'use strict';

const bcrypt         = require('bcryptjs');
const { db }         = require('../db');
const { requireAdmin } = require('../middleware/auth');
const { parseBody }    = require('../middleware/security');
const { ok, created, notFound, badRequest } = require('../middleware/response');
const { requireString, validateNewPassword, sanitize } = require('../middleware/validate');
const { getAnalystProfile } = require('../services/analyst_profile');
const { invalidateLeaderboardCache } = require('./leaderboard');

// ── GET /api/admin/stats ─────────────────────────────────────────────────
function getStats(req, res) {
  const admin = requireAdmin(req, res); if (!admin) return;
  const total_users    = db.prepare(`SELECT COUNT(*) as c FROM users WHERE role='analyst'`).get().c;
  const active_users   = db.prepare(`SELECT COUNT(*) as c FROM users WHERE role='analyst' AND is_active=1`).get().c;
  const labs_completed = db.prepare(`SELECT COUNT(*) as c FROM user_progress WHERE status='completed'`).get().c;
  const total_labs     = db.prepare(`SELECT COUNT(*) as c FROM labs`).get().c;
  const total_alerts   = db.prepare(`SELECT COUNT(*) as c FROM soc_alerts`).get().c;
  const avg_row = db.prepare(
    `SELECT COALESCE(AVG(s),0) as avg FROM (SELECT SUM(pts_awarded) as s FROM user_answers WHERE is_correct=1 GROUP BY user_id)`
  ).get();
  const total_answers = db.prepare(`SELECT COUNT(*) as c FROM user_answers`).get().c;
  return ok(res, { total_users, active_users, labs_completed, total_labs, total_alerts, avg_score: Math.round(avg_row.avg), total_answers });
}

// ── GET /api/admin/users ─────────────────────────────────────────────────
function listUsers(req, res) {
  const admin = requireAdmin(req, res); if (!admin) return;

  // Try full query with session tracking columns; fall back if columns don't exist yet
  let users;
  try {
    users = db.prepare(`
      SELECT u.id, u.username, u.role, u.is_active, u.created_at,
        u.display_name, u.email, u.force_pw_change,
        COALESCE(lab.score,0) + COALESCE(cls.score,0) AS score,
        COALESCE(prog.labs_done,0) AS labs_done,
        sess.last_seen, sess.expires_at,
        CASE
          WHEN sess.last_seen IS NOT NULL AND sess.last_seen > datetime('now','-5 minutes') THEN 1
          ELSE 0
        END AS is_online
      FROM users u
      LEFT JOIN (SELECT user_id, SUM(CASE WHEN is_correct=1 THEN pts_awarded ELSE 0 END) s FROM user_answers GROUP BY user_id) lab ON lab.user_id=u.id
      LEFT JOIN (SELECT user_id, SUM(points_awarded) s FROM alert_closures WHERE is_correct=1 GROUP BY user_id) cls ON cls.user_id=u.id
      LEFT JOIN (SELECT user_id, COUNT(DISTINCT lab_id) AS labs_done FROM user_progress WHERE status='completed' GROUP BY user_id) prog ON prog.user_id=u.id
      LEFT JOIN (SELECT user_id, MAX(COALESCE(last_seen_at, expires_at)) AS last_seen, MAX(expires_at) AS expires_at FROM sessions GROUP BY user_id) sess ON sess.user_id=u.id
      ORDER BY is_online DESC, u.username ASC
    `).all();
  } catch (e1) {
    // Fallback level 2: scores-included query failed — try without score JOINs
    try {
      users = db.prepare(`
        SELECT u.id, u.username, u.role, u.is_active, u.created_at,
          NULL AS display_name, NULL AS email, NULL AS force_pw_change,
          COALESCE(lab.score,0) AS score, COALESCE(prog.labs_done,0) AS labs_done,
          NULL AS last_seen, NULL AS expires_at, 0 AS is_online
        FROM users u
        LEFT JOIN (SELECT user_id, SUM(CASE WHEN is_correct=1 THEN pts_awarded ELSE 0 END) AS score FROM user_answers GROUP BY user_id) lab ON lab.user_id=u.id
        LEFT JOIN (SELECT user_id, COUNT(DISTINCT lab_id) AS labs_done FROM user_progress WHERE status='completed' GROUP BY user_id) prog ON prog.user_id=u.id
        ORDER BY u.username ASC
      `).all();
    } catch (e2) {
      // Nuclear fallback: just return users with no score data
      try {
        users = db.prepare(`SELECT id, username, role, is_active, created_at FROM users ORDER BY username ASC`).all()
          .map(u => ({ ...u, display_name: null, email: null, force_pw_change: 1, score: 0, labs_done: 0, last_seen: null, expires_at: null, is_online: 0 }));
      } catch (e3) {
        users = [];
      }
    }
  }
  return ok(res, users);
}

// ── POST /api/admin/users ────────────────────────────────────────────────
async function createUser(req, res) {
  const admin = requireAdmin(req, res); if (!admin) return;
  const { username, password, role } = await parseBody(req);
  const uErr = requireString(username, 'username', { max: 64 });
  if (uErr) return badRequest(res, uErr);
  const pErr = validateNewPassword(password);
  if (pErr) return badRequest(res, pErr);
  const validRole  = ['analyst','admin'].includes(role) ? role : 'analyst';
  const cleanName  = sanitize(username);
  const existing   = db.prepare(`SELECT id FROM users WHERE username=?`).get(cleanName);
  if (existing) return badRequest(res, 'Username already exists');
  const hash = bcrypt.hashSync(password, 10);
  const forcePw = validRole === 'admin' ? 0 : 1;
  const info = db.prepare(`INSERT INTO users (username, password_hash, role, force_pw_change) VALUES (?,?,?,?)`).run(cleanName, hash, validRole, forcePw);
  return created(res, { id: info.lastInsertRowid, username: cleanName, role: validRole });
}

// ── PUT /api/admin/users/:id ─────────────────────────────────────────────
async function updateUser(req, res, userId) {
  const admin = requireAdmin(req, res); if (!admin) return;
  const uid   = parseInt(userId, 10);
  const target = db.prepare(`SELECT id, role FROM users WHERE id=?`).get(uid);
  if (!target) return notFound(res, 'User not found');
  // Security: prevent admins from modifying other admin accounts (privilege abuse)
  if (target.role === 'admin' && target.id !== admin.id) {
    return require('../middleware/response').forbidden(res, 'Cannot modify another administrator account');
  }
  const body = await parseBody(req);
  if (body.active !== undefined) {
    const newActive = body.active ? 1 : 0;
    db.prepare(`UPDATE users SET is_active=? WHERE id=?`).run(newActive, uid);
    // Deactivating a user: kill all their sessions immediately so they can't keep using the platform
    if (!newActive) db.prepare(`DELETE FROM sessions WHERE user_id=?`).run(uid);
  }
  if (body.password) {
    const err = validateNewPassword(body.password);
    if (err) return badRequest(res, err);
    db.prepare(`UPDATE users SET password_hash=? WHERE id=?`).run(bcrypt.hashSync(body.password, 10), uid);
    db.prepare(`DELETE FROM sessions WHERE user_id=?`).run(uid);
  }
  return ok(res);
}

// ── DELETE /api/admin/users/:id ──────────────────────────────────────────
function deleteUser(req, res, userId) {
  const admin = requireAdmin(req, res); if (!admin) return;
  const uid   = parseInt(userId, 10);
  if (uid === admin.id) return badRequest(res, 'Cannot delete your own account');
  const target = db.prepare(`SELECT id, username, role FROM users WHERE id=?`).get(uid);
  // Security: prevent admins from deleting other admin accounts
  if (target && target.role === 'admin') {
    return require('../middleware/response').forbidden(res, 'Cannot delete an administrator account');
  }
  if (!target) return notFound(res, 'User not found');

  // Explicitly delete from all related tables before deleting the user.
  // This handles any FK constraint gaps and is safer than relying on CASCADE alone.
  const relatedTables = [
    'sessions', 'user_progress', 'user_answers', 'draft_answers',
    'alert_closures', 'user_alert_state', 'incidents', 'escalations',
    'user_achievements', 'lab_notes', 'streaks',
  ];
  db.transaction(() => {
    for (const tbl of relatedTables) {
      try {
        db.prepare(`DELETE FROM ${tbl} WHERE user_id=?`).run(uid);
      } catch { /* table may not exist in all installs — skip */ }
    }
    db.prepare(`DELETE FROM users WHERE id=?`).run(uid);
  })();

  invalidateLeaderboardCache();  // user removed — refresh cache
  return ok(res, { deleted: target.username });
}

// ── GET /api/admin/progress ──────────────────────────────────────────────
function getProgress(req, res) {
  const admin = requireAdmin(req, res); if (!admin) return;
  const users = db.prepare(`SELECT id, username FROM users WHERE role='analyst' ORDER BY username`).all();
  const labs  = db.prepare(`SELECT id, slug, title, points FROM labs ORDER BY order_index`).all();
  const allProg = db.prepare(`SELECT user_id, lab_id, status, score, completed_at FROM user_progress`).all();
  // Batch-load scores to avoid N+1 queries (2 queries vs 2×N)
  const labScores = db.prepare(
    `SELECT user_id, COALESCE(SUM(pts_awarded),0) AS s FROM user_answers WHERE is_correct=1 GROUP BY user_id`
  ).all().reduce((m, r) => { m[r.user_id] = r.s; return m; }, {});
  const alertScores = db.prepare(
    `SELECT user_id, COALESCE(SUM(points_awarded),0) AS s FROM alert_closures WHERE is_correct=1 GROUP BY user_id`
  ).all().reduce((m, r) => { m[r.user_id] = r.s; return m; }, {});

  const matrix = users.map(u => {
    const row = { user_id: u.id, username: u.username, labs: {} };
    labs.forEach(l => {
      const p = allProg.find(x => x.user_id === u.id && x.lab_id === l.id);
      row.labs[l.slug] = p ? { status: p.status, score: p.score, completed_at: p.completed_at } : { status: 'not_started', score: 0 };
    });
    row.total_score = (labScores[u.id] || 0) + (alertScores[u.id] || 0);
    return row;
  });
  return ok(res, { users: matrix, labs });
}

// ── GET /api/admin/labs ──────────────────────────────────────────────────
function listAdminLabs(req, res) {
  const admin = requireAdmin(req, res); if (!admin) return;
  const labs = db.prepare(
    `SELECT l.*,
       (SELECT COUNT(*) FROM questions q WHERE q.lab_id = l.id) as question_count,
       (SELECT COUNT(*) FROM user_progress p WHERE p.lab_id = l.id AND p.status='completed') as completions
     FROM labs l ORDER BY l.order_index`
  ).all().map(l => ({
    ...l,
    alert_refs: (() => { try { return JSON.parse(l.alert_refs || '[]'); } catch { return []; } })(),
    evidence:   (() => { if (!l.evidence) return []; try { return JSON.parse(l.evidence); } catch { return l.evidence; } })(),
  }));
  return ok(res, labs);
}

// ── POST /api/admin/labs ─────────────────────────────────────────────────
async function createLab(req, res) {
  const admin = requireAdmin(req, res); if (!admin) return;
  const body = await parseBody(req);
  const { title, description, category, difficulty, points, is_visible, alert_refs, evidence, questions: qs } = body;
  if (!title) return badRequest(res, 'title is required');
  const slug = sanitize(title).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
  const existing = db.prepare(`SELECT id FROM labs WHERE slug=?`).get(slug);
  if (existing) return badRequest(res, 'A lab with this title already exists');
  const maxOrder = db.prepare(`SELECT COALESCE(MAX(order_index),0) as m FROM labs`).get().m;
  const info = db.prepare(
    `INSERT INTO labs (slug, title, description, category, difficulty, points, is_visible, alert_refs, evidence, order_index)
     VALUES (?,?,?,?,?,?,?,?,?,?)`
  ).run(slug, title, description || '', category || 'SOC Operations', difficulty || 'intermediate',
    parseInt(points) || 100, is_visible !== false ? 1 : 0,
    JSON.stringify(alert_refs || []), JSON.stringify(evidence || []), maxOrder + 1);
  const labId = info.lastInsertRowid;
  // Bulk-insert questions if provided
  if (Array.isArray(qs) && qs.length > 0) {
    const qInsert = db.prepare(
      `INSERT INTO questions (lab_id, question, answer_type, correct_answer, options, points, hint, order_index)
       VALUES (?,?,?,?,?,?,?,?)`
    );
    db.transaction(() => {
      qs.forEach((q, i) => qInsert.run(labId, q.question, q.answer_type || 'text', q.correct_answer || '',
        q.options ? JSON.stringify(q.options) : null, parseInt(q.points) || 10, q.hint || null, i + 1));
    })();
  }
  return created(res, { id: labId, slug });
}

// ── PUT /api/admin/labs/:id ──────────────────────────────────────────────
async function updateLab(req, res, labId) {
  const admin = requireAdmin(req, res); if (!admin) return;
  const id = parseInt(labId, 10);
  if (!db.prepare(`SELECT id FROM labs WHERE id=?`).get(id)) return notFound(res, 'Lab not found');
  const body = await parseBody(req);
  const fields = ['title','description','category','difficulty','points','is_visible'];
  const setClauses = []; const vals = [];
  fields.forEach(f => {
    if (body[f] !== undefined) { setClauses.push(`${f}=?`); vals.push(body[f]); }
  });
  if (body.alert_refs !== undefined) { setClauses.push('alert_refs=?'); vals.push(JSON.stringify(body.alert_refs)); }
  if (body.evidence   !== undefined) { setClauses.push('evidence=?');   vals.push(JSON.stringify(body.evidence));   }
  if (setClauses.length > 0) { vals.push(id); db.prepare(`UPDATE labs SET ${setClauses.join(',')} WHERE id=?`).run(...vals); }
  return ok(res);
}

// ── DELETE /api/admin/labs/:id ───────────────────────────────────────────
function deleteLab(req, res, labId) {
  const admin = requireAdmin(req, res); if (!admin) return;
  db.prepare(`DELETE FROM labs WHERE id=?`).run(parseInt(labId, 10));
  return ok(res);
}

// ── GET /api/admin/labs/:id/questions ────────────────────────────────────
function getLabQuestions(req, res, labId) {
  const admin = requireAdmin(req, res); if (!admin) return;
  const qs = db.prepare(
    `SELECT id, order_index, question, answer_type, correct_answer, options, points, hint, hint_levels, alert_ref
     FROM questions WHERE lab_id=? ORDER BY order_index`
  ).all(parseInt(labId, 10)).map(q => ({ ...q, options: q.options ? (() => { try { return JSON.parse(q.options); } catch { return null; } })() : null }));
  return ok(res, qs);
}

// ── POST /api/admin/labs/:id/questions ───────────────────────────────────
async function addQuestion(req, res, labId) {
  const admin = requireAdmin(req, res); if (!admin) return;
  const id = parseInt(labId, 10);
  if (!db.prepare(`SELECT id FROM labs WHERE id=?`).get(id)) return notFound(res, 'Lab not found');
  const { question, answer_type, correct_answer, options, points, hint, alert_ref } = await parseBody(req);
  if (!question) return badRequest(res, 'question is required');
  if (!correct_answer) return badRequest(res, 'correct_answer is required');
  const maxOrder = db.prepare(`SELECT COALESCE(MAX(order_index),0) as m FROM questions WHERE lab_id=?`).get(id).m;
  const info = db.prepare(
    `INSERT INTO questions (lab_id, question, answer_type, correct_answer, options, points, hint, alert_ref, order_index)
     VALUES (?,?,?,?,?,?,?,?,?)`
  ).run(id, question, answer_type || 'text', correct_answer,
    options ? JSON.stringify(options) : null, parseInt(points) || 10, hint || null, alert_ref || null, maxOrder + 1);
  return created(res, { id: info.lastInsertRowid });
}

// ── PUT /api/admin/questions/:id ─────────────────────────────────────────
async function updateQuestion(req, res, qId) {
  const admin = requireAdmin(req, res); if (!admin) return;
  const id = parseInt(qId, 10);
  if (!db.prepare(`SELECT id FROM questions WHERE id=?`).get(id)) return notFound(res, 'Question not found');
  const body = await parseBody(req);
  const fields = ['question','answer_type','correct_answer','points','hint','alert_ref'];
  const setClauses = []; const vals = [];
  fields.forEach(f => { if (body[f] !== undefined) { setClauses.push(`${f}=?`); vals.push(body[f]); } });
  if (body.options !== undefined) { setClauses.push('options=?'); vals.push(JSON.stringify(body.options)); }
  if (setClauses.length > 0) { vals.push(id); db.prepare(`UPDATE questions SET ${setClauses.join(',')} WHERE id=?`).run(...vals); }
  return ok(res);
}

// ── DELETE /api/admin/questions/:id ─────────────────────────────────────
function deleteQuestion(req, res, qId) {
  const admin = requireAdmin(req, res); if (!admin) return;
  db.prepare(`DELETE FROM questions WHERE id=?`).run(parseInt(qId, 10));
  return ok(res);
}

// ── GET /api/admin/analysts/:id/activity ─────────────────────────────────
function getAnalystActivity(req, res, userId) {
  const admin = requireAdmin(req, res); if (!admin) return;
  const uid   = parseInt(userId, 10);
  const closures = db.prepare(
    `SELECT ac.*, sa.title as alert_title, sa.severity, sa.category
     FROM alert_closures ac LEFT JOIN soc_alerts sa ON sa.id = ac.alert_id
     WHERE ac.user_id=? ORDER BY ac.closed_at DESC LIMIT 50`
  ).all(uid);
  const total = closures.length;
  const correct = closures.filter(c => c.is_correct).length;
  const fps = closures.filter(c => c.classification === 'false_positive');
  return ok(res, {
    alerts_triaged: total, correct_closes: correct,
    fp_accuracy: fps.length > 0 ? Math.round((fps.filter(c=>c.is_correct).length / fps.length) * 100) + '%' : 'N/A',
    triage_score: total > 0 ? Math.round((correct / total) * 100) : 0,
    total_points: closures.reduce((s,c) => s + (c.points_awarded||0), 0),
    records: closures.map(c => ({
      alert_id: c.alert_id, alert_title: c.alert_title, severity: c.severity,
      classification: c.classification, is_correct: !!c.is_correct,
      points: c.points_awarded, investigation_score: c.investigation_score || 0,
      step_scores: c.step_scores ? JSON.parse(c.step_scores) : {},
      scoring_feedback: c.scoring_feedback ? JSON.parse(c.scoring_feedback) : [],
      fp_reason: c.fp_reason, triage_reason: c.triage_reason,
      closed_at: c.closed_at,
    })),
  });
}

// ── GET /api/admin/analysts/:id/profile ──────────────────────────────────
function getProfile(req, res, userId) {
  const admin = requireAdmin(req, res); if (!admin) return;
  const uid   = parseInt(userId, 10);
  try {
    const data = getAnalystProfile(uid);
    if (!data) return notFound(res, 'Analyst not found');
    return ok(res, data);
  } catch (err) {
    console.error('[getProfile] Error for user', uid, ':', err.message);
    return require('../middleware/response').serverError(res, 'Unable to load profile. Please try again.');
  }
}

// ── POST /api/admin/batch/reset — wipe analyst progress + delete accounts ─
async function batchReset(req, res) {
  const admin = requireAdmin(req, res); if (!admin) return;
  const { note, confirm, delete_users } = await parseBody(req);
  if (confirm !== 'RESET') return badRequest(res, 'Send { confirm: "RESET" } to confirm.');

  const analysts = db.prepare(`SELECT id FROM users WHERE role='analyst'`).all();
  const analystCount = analysts.length;
  const relatedTables = ['user_progress','user_answers','draft_answers','alert_closures',
                         'user_alert_state','incidents','escalations','user_achievements','streaks',
                         'lab_notes','bonus_lab_completions','sessions'];

  db.transaction(() => {
    // Clear all progress and session data for every analyst
    for (const tbl of relatedTables) {
      try {
        db.prepare(`DELETE FROM ${tbl} WHERE user_id IN (SELECT id FROM users WHERE role='analyst')`).run();
      } catch { /* table may not exist in all installs */ }
    }

    if (delete_users) {
      // Hard delete: remove all analyst accounts entirely
      db.prepare(`DELETE FROM users WHERE role='analyst'`).run();
    } else {
      // Soft reset: keep accounts, reset scores and force password change
      // Wrap in try/catch — extra_labs_bonus column may not exist on older installs
      try {
        db.prepare(`UPDATE users SET points=0, extra_labs_bonus=0, force_pw_change=1, last_lab_slug=NULL, last_active_at=NULL WHERE role='analyst'`).run();
      } catch {
        db.prepare(`UPDATE users SET points=0, force_pw_change=1, last_lab_slug=NULL, last_active_at=NULL WHERE role='analyst'`).run();
      }
    }
    // Also clear the leaderboard snapshot table if it exists
    try { db.prepare(`DELETE FROM leaderboard WHERE user_id IN (SELECT id FROM users WHERE role='analyst')`).run(); } catch {}

    // Audit log
    db.prepare(`INSERT INTO batch_resets (reset_by, note, users_affected) VALUES (?,?,?)`)
      .run(admin.id, sanitize(note || ''), analystCount);
  })();

  invalidateLeaderboardCache();  // clear cached scores after full reset
  return ok(res, {
    reset: true,
    analysts_affected: analystCount,
    users_deleted: !!delete_users,
    note: note || '',
  });
}

// ── GET /api/admin/users/export — export all analysts as CSV ─────────────
function exportUsers(req, res) {
  const admin = requireAdmin(req, res); if (!admin) return;
  let users;
  try {
    // Only export analyst accounts — admin accounts excluded for security
    users = db.prepare(
      `SELECT username, role, is_active, display_name, email, institution, created_at FROM users WHERE role='analyst' ORDER BY username`
    ).all();
  } catch {
    users = db.prepare(`SELECT username, role, is_active, created_at FROM users WHERE role='analyst' ORDER BY username`).all();
  }

  const header = 'username,password,role,display_name,email,institution';
  const rows = users.map(u =>
    [u.username, '', u.role, u.display_name || '', u.email || '', u.institution || '']
      .map(v => `"${String(v).replace(/"/g, '""')}"`)
      .join(',')
  );
  const csv = [header, ...rows].join('\n');

  // Write raw CSV directly (not JSON-encoded)
  res.writeHead(200, {
    'Content-Type':        'text/csv; charset=utf-8',
    'Content-Disposition': 'attachment; filename="diaas-users.csv"',
    'Cache-Control':       'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(csv);
}

// ── POST /api/admin/users/import — import analysts from CSV ──────────────
async function importUsers(req, res) {
  const admin = requireAdmin(req, res); if (!admin) return;
  const body  = await parseBody(req);
  const { rows } = body; // [{ username, password, role?, display_name?, email?, institution? }]

  if (!Array.isArray(rows) || !rows.length) return badRequest(res, 'rows array required');
  if (rows.length > 200) return badRequest(res, 'Maximum 200 users per import');

  const created = []; const errors = [];

  // Pre-validate all rows first (fast — no hashing yet)
  const toHash = [];
  for (let i = 0; i < rows.length; i++) {
    const r = rows[i];
    if (!r.username || !r.password) { errors.push({ row: i+1, error: 'username and password required' }); continue; }
    const uname = sanitize(r.username).toLowerCase().replace(/[^a-z0-9_]/g, '_');
    if (uname.length < 3) { errors.push({ row: i+1, error: 'username too short' }); continue; }
    if (r.password.length < 8) { errors.push({ row: i+1, error: 'password must be 8+ characters' }); continue; }
    const role = r.role === 'admin' ? 'admin' : 'analyst';
    toHash.push({ row: i+1, uname, role, r });
  }

  // Hash passwords async (non-blocking) — allows other requests to be served during this
  const validated = await Promise.all(toHash.map(async ({ row, uname, role, r }) => {
    const hash = await new Promise((res, rej) =>
      require('bcryptjs').hash(r.password, 10, (err, h) => err ? rej(err) : res(h))
    );
    return { row, uname, hash, role, r };
  }));

  // Now insert all valid rows inside a single fast transaction (no hashing inside)
  db.transaction(() => {
    for (const { row, uname, hash, role, r } of validated) {
      if (db.prepare(`SELECT id FROM users WHERE username=?`).get(uname)) {
        errors.push({ row, error: `username '${uname}' already exists` }); continue;
      }
      const info = db.prepare(
        `INSERT INTO users (username, password_hash, role, display_name, email, institution, force_pw_change) VALUES (?,?,?,?,?,?,?)`
      ).run(uname, hash, role, r.display_name || null, r.email || null, r.institution || null, role === 'admin' ? 0 : 1);
      created.push({ id: info.lastInsertRowid, username: uname, role });
    }
  })();

  return ok(res, { created: created.length, errors, users: created });
}

// ── GET /api/admin/batch/history ─────────────────────────────────────────
function batchHistory(req, res) {
  const admin = requireAdmin(req, res); if (!admin) return;
  const rows = db.prepare(
    `SELECT br.*, u.username AS reset_by_name FROM batch_resets br
     LEFT JOIN users u ON u.id=br.reset_by ORDER BY br.reset_at DESC LIMIT 20`
  ).all();
  return ok(res, rows);
}


// GET /api/admin/report/:userId — full report card data bundle
async function getReportCard(req, res, userId) {
  const admin = requireAdmin(req, res); if (!admin) return;
  const uid = parseInt(userId, 10);

  const user = db.prepare(`SELECT id, username, display_name, email, institution, created_at FROM users WHERE id=?`).get(uid);
  if (!user) return notFound(res, 'User not found');

  // Performance pillars
  const { getStudentPerformance } = require('../services/scoring_weighted');
  const perf = getStudentPerformance(uid);

  // All labs with per-question progress
  const { getAnalystProfile } = require('../services/analyst_profile');
  const profile = getAnalystProfile(uid);

  // Graduation data
  const { generateGraduationReport } = require('../services/graduation');
  let grad = null;
  try { grad = generateGraduationReport(uid); } catch {}

  // Streak
  const streak = db.prepare(`SELECT current_streak, longest_streak FROM streaks WHERE user_id=?`).get(uid);

  return ok(res, {
    user,
    perf,
    labs: profile.lab_activity || [],
    category_breakdown: profile.category_breakdown || [],
    alert_history: profile.alert_history || [],
    grad,
    streak: streak || { current_streak: 0, longest_streak: 0 },
    generated_at: new Date().toISOString(),
  });
}

module.exports = {
  getStats, listUsers, createUser, updateUser, deleteUser, getProfile,
  batchReset, exportUsers, importUsers, batchHistory, getReportCard,
  getProgress, listAdminLabs, createLab, updateLab, deleteLab,
  getLabQuestions, addQuestion, updateQuestion, deleteQuestion,
  getAnalystActivity,
};
