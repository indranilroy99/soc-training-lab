'use strict';

const bcrypt   = require('bcryptjs');
const { db }   = require('../db');
const { requireAuth } = require('../middleware/auth');
const { ok, badRequest, unauthorized, notFound } = require('../middleware/response');
const { parseBody } = require('../middleware/security');
const { validateNewPassword, requireString, sanitize } = require('../middleware/validate');
const { getUserTotalScore, getUserRank } = require('../services/users');
const { getStreak }                      = require('../services/streaks');
const { authActionLimiter }              = require('../middleware/rateLimit');

const MAX_IMAGE_BYTES = 500_000; // 500KB base64 limit for profile pictures

// GET /api/me
function getMe(req, res) {
  const user = requireAuth(req, res); if (!user) return;
  const score = getUserTotalScore(user.id);
  const rank  = getUserRank(user.id);

  const stats = db.prepare(
    `SELECT COUNT(*) AS total_answered,
            SUM(CASE WHEN is_correct=1 THEN 1 ELSE 0 END) AS correct_answered
     FROM user_answers WHERE user_id=?`
  ).get(user.id);

  const labsDone       = db.prepare(`SELECT COUNT(*) AS c FROM user_progress WHERE user_id=? AND status='completed'`).get(user.id).c;
  const labsInProgress = db.prepare(`SELECT COUNT(*) AS c FROM user_progress WHERE user_id=? AND status='in_progress'`).get(user.id).c;

  const totalAnswered   = stats?.total_answered   || 0;
  const correctAnswered = stats?.correct_answered || 0;
  const accuracy = totalAnswered > 0 ? Math.round((correctAnswered / totalAnswered) * 100) : 0;

  const streak = getStreak(user.id);

  // Wrap in try/catch: profile columns may not exist on older installs
  let profile = null;
  try {
    profile = db.prepare(
      `SELECT display_name, dob, institution, bio, profile_image, email, force_pw_change,
              last_lab_slug, last_active_at FROM users WHERE id=?`
    ).get(user.id);
  } catch {
    // Fallback: extended columns not yet added via migration
    profile = db.prepare(`SELECT username FROM users WHERE id=?`).get(user.id);
  }

  return ok(res, {
    id: user.id, username: user.username, role: user.role,
    display_name: profile?.display_name || null,
    email: profile?.email || null,
    dob: profile?.dob || null,
    institution: profile?.institution || null,
    bio: profile?.bio || null,
    profile_image: profile?.profile_image || null,
    force_pw_change: !!profile?.force_pw_change,
    score, rank, labs_done: labsDone, labs_in_progress: labsInProgress,
    total_answered: totalAnswered, correct_answered: correctAnswered, accuracy,
    streak,
    last_lab_slug:   profile?.last_lab_slug   || null,
    last_active_at:  profile?.last_active_at  || null,
  });
}

// GET /api/me/closures
function getMyClosures(req, res) {
  const user = requireAuth(req, res); if (!user) return;
  const closures = db.prepare(
    `SELECT ac.alert_id, sa.title AS alert_title, sa.severity,
            ac.classification, ac.is_correct, ac.points_awarded,
            ac.investigation_score, ac.step_scores, ac.scoring_feedback,
            ac.triage_reason, ac.fp_reason, ac.closed_at
     FROM alert_closures ac
     LEFT JOIN soc_alerts sa ON sa.id = ac.alert_id
     WHERE ac.user_id=?
     ORDER BY ac.closed_at DESC LIMIT 50`
  ).all(user.id);

  return ok(res, {
    records: closures.map(c => ({
      alert_id: c.alert_id, alert_title: c.alert_title, severity: c.severity,
      classification: c.classification, is_correct: !!c.is_correct,
      points: c.points_awarded, investigation_score: c.investigation_score || 0,
      step_scores:      c.step_scores      ? JSON.parse(c.step_scores)      : {},
      scoring_feedback: c.scoring_feedback ? JSON.parse(c.scoring_feedback) : [],
      triage_reason: c.triage_reason, fp_reason: c.fp_reason, closed_at: c.closed_at,
    })),
  });
}

// PUT /api/me/profile  — update optional profile fields
async function updateProfile(req, res) {
  const user = requireAuth(req, res); if (!user) return;
  const body = await parseBody(req);

  const allowed = ['display_name', 'dob', 'institution', 'bio', 'email'];
  const setClauses = []; const vals = [];

  for (const field of allowed) {
    if (body[field] !== undefined) {
      const v = body[field] ? sanitize(String(body[field])).slice(0, 256) : null;
      setClauses.push(`${field}=?`);
      vals.push(v);
    }
  }

  // Profile image: allowlist safe types only — SVG excluded (can embed <script> tags)
  if (body.profile_image !== undefined) {
    if (body.profile_image && body.profile_image.length > MAX_IMAGE_BYTES) {
      return badRequest(res, `Profile image too large. Maximum ${Math.round(MAX_IMAGE_BYTES / 1024)}KB.`);
    }
    const ALLOWED_IMG = ['data:image/jpeg;base64,','data:image/jpg;base64,','data:image/png;base64,','data:image/webp;base64,','data:image/gif;base64,'];
    if (body.profile_image && !ALLOWED_IMG.some(t => body.profile_image.startsWith(t))) {
      return badRequest(res, 'Profile image must be JPEG, PNG, WebP, or GIF. SVG is not allowed.');
    }
    setClauses.push('profile_image=?');
    vals.push(body.profile_image || null);
  }

  if (setClauses.length > 0) {
    vals.push(user.id);
    db.prepare(`UPDATE users SET ${setClauses.join(', ')} WHERE id=?`).run(...vals);
  }

  return ok(res, { updated: setClauses.length });
}

// POST /api/user/password
async function changePassword(req, res) {
  const user = requireAuth(req, res); if (!user) return;
  // Rate limit: prevent brute-forcing current_password on the network
  let rlDone = false;
  authActionLimiter(req, res, () => { rlDone = true; });
  if (!rlDone) return;
  const { current_password, new_password } = await parseBody(req);

  // force_pw_change users: skip current password check on FIRST change
  const profile = db.prepare(`SELECT password_hash, force_pw_change FROM users WHERE id=?`).get(user.id);
  const isForced = !!profile?.force_pw_change;

  if (!isForced) {
    if (!current_password) return badRequest(res, 'current_password is required');
    if (!bcrypt.compareSync(current_password, profile.password_hash)) {
      return unauthorized(res, 'Current password is incorrect');
    }
  }

  const err = validateNewPassword(new_password);
  if (err) return badRequest(res, err);

  const hash = bcrypt.hashSync(new_password, 10);
  db.prepare(`UPDATE users SET password_hash=?, force_pw_change=0 WHERE id=?`).run(hash, user.id);
  // Invalidate all OTHER sessions, keep current one alive
  const auth  = (req.headers['authorization'] || '').trim();
  const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
  if (token) db.prepare(`DELETE FROM sessions WHERE user_id=? AND token!=?`).run(user.id, token);

  return ok(res, { message: 'Password updated successfully.' });
}

// POST /api/me/draft — save an answer draft for a question
async function saveDraft(req, res) {
  const user = requireAuth(req, res); if (!user) return;
  const { lab_slug, question_id, answer } = await parseBody(req);
  if (!lab_slug || !question_id) return badRequest(res, 'lab_slug and question_id required');

  const lab = db.prepare(`SELECT id FROM labs WHERE slug=?`).get(lab_slug);
  if (!lab) return notFound(res, 'Lab not found');

  db.prepare(`
    INSERT INTO draft_answers (user_id, lab_id, question_id, draft_answer)
    VALUES (?,?,?,?)
    ON CONFLICT(user_id, question_id) DO UPDATE SET draft_answer=excluded.draft_answer
  `).run(user.id, lab.id, question_id, String(answer || ''));

  return ok(res, { saved: true });
}

// POST /api/me/position — track which question the user is on (for resume)
async function savePosition(req, res) {
  const user = requireAuth(req, res); if (!user) return;
  const { lab_slug, question_id } = await parseBody(req);
  if (!lab_slug) return ok(res, { ok: true }); // silent no-op if missing

  // Update last_lab_slug in users table (add column if needed)
  try {
    db.prepare(`UPDATE users SET last_lab_slug=?, last_active_at=datetime('now') WHERE id=?`)
      .run(lab_slug, user.id);
  } catch {
    // Column may not exist yet - silently ignore
  }
  return ok(res, { saved: true });
}

module.exports = { getMe, getMyClosures, updateProfile, changePassword, saveDraft, savePosition };
