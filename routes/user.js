'use strict';

const bcrypt   = require('bcryptjs');
const { db }   = require('../db');
const { requireAuth } = require('../middleware/auth');
const { ok, badRequest, unauthorized } = require('../middleware/response');
const { parseBody } = require('../middleware/security');
const { validateNewPassword } = require('../middleware/validate');
const { getUserTotalScore, getUserRank } = require('../services/users');
const { getStreak } = require('../services/streaks');

// GET /api/me
function getMe(req, res) {
  const user = requireAuth(req, res); if (!user) return;
  const score = getUserTotalScore(user.id);
  const rank  = getUserRank(user.id);

  const stats = db.prepare(
    `SELECT
       COUNT(*) as total_answered,
       SUM(CASE WHEN is_correct=1 THEN 1 ELSE 0 END) as correct_answered
     FROM user_answers WHERE user_id=?`
  ).get(user.id);

  const labsDone = db.prepare(
    `SELECT COUNT(*) as c FROM user_progress WHERE user_id=? AND status='completed'`
  ).get(user.id).c;

  const labsInProgress = db.prepare(
    `SELECT COUNT(*) as c FROM user_progress WHERE user_id=? AND status='in_progress'`
  ).get(user.id).c;

  const totalAnswered   = stats?.total_answered   || 0;
  const correctAnswered = stats?.correct_answered || 0;
  const accuracy = totalAnswered > 0 ? Math.round((correctAnswered / totalAnswered) * 100) : 0;

  const streak = getStreak(user.id);
  return ok(res, {
    id: user.id, username: user.username, role: user.role,
    score, rank, labs_done: labsDone, labs_in_progress: labsInProgress,
    total_answered: totalAnswered, correct_answered: correctAnswered, accuracy,
    streak,
  });
}

// GET /api/me/closures
function getMyClosures(req, res) {
  const user = requireAuth(req, res); if (!user) return;
  const closures = db.prepare(
    `SELECT ac.alert_id, sa.title as alert_title, sa.severity,
            ac.classification, ac.is_correct, ac.points_awarded,
            ac.investigation_score, ac.step_scores, ac.scoring_feedback,
            ac.triage_reason, ac.fp_reason, ac.closed_at
     FROM alert_closures ac
     LEFT JOIN soc_alerts sa ON sa.id = ac.alert_id
     WHERE ac.user_id=?
     ORDER BY ac.closed_at DESC LIMIT 50`
  ).all(user.id);

  const records = closures.map(c => ({
    alert_id:            c.alert_id,
    alert_title:         c.alert_title,
    severity:            c.severity,
    classification:      c.classification,
    is_correct:          !!c.is_correct,
    points:              c.points_awarded,
    investigation_score: c.investigation_score || 0,
    step_scores:         c.step_scores     ? JSON.parse(c.step_scores)     : {},
    scoring_feedback:    c.scoring_feedback ? JSON.parse(c.scoring_feedback) : [],
    triage_reason:       c.triage_reason,
    fp_reason:           c.fp_reason,
    closed_at:           c.closed_at,
  }));
  return ok(res, { records });
}

// POST /api/user/password
async function changePassword(req, res) {
  const user = requireAuth(req, res); if (!user) return;
  const { current_password, new_password } = await parseBody(req);

  if (!current_password) return badRequest(res, 'current_password is required');
  const err = validateNewPassword(new_password);
  if (err) return badRequest(res, err);

  const row = db.prepare(`SELECT password_hash FROM users WHERE id=?`).get(user.id);
  if (!bcrypt.compareSync(current_password, row.password_hash)) {
    return unauthorized(res, 'Current password is incorrect');
  }

  const hash = bcrypt.hashSync(new_password, 10);
  db.prepare(`UPDATE users SET password_hash=? WHERE id=?`).run(hash, user.id);
  // Invalidate all other sessions for this user
  db.prepare(`DELETE FROM sessions WHERE user_id=?`).run(user.id);
  return ok(res, { message: 'Password changed. Please log in again.' });
}

module.exports = { getMe, getMyClosures, changePassword };
