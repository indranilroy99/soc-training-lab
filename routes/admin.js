'use strict';

const bcrypt         = require('bcryptjs');
const { db }         = require('../db');
const { requireAdmin } = require('../middleware/auth');
const { parseBody }    = require('../middleware/security');
const { ok, created, notFound, badRequest } = require('../middleware/response');
const { requireString, validateNewPassword, sanitize } = require('../middleware/validate');

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
  const users = db.prepare(
    `SELECT u.id, u.username, u.role, u.is_active, u.created_at,
       COALESCE(lab.score,0) + COALESCE(cls.score,0) as score,
       COALESCE(prog.labs_done,0) as labs_done,
       sess.last_session
     FROM users u
     LEFT JOIN (SELECT user_id, SUM(CASE WHEN is_correct=1 THEN pts_awarded ELSE 0 END) as score FROM user_answers GROUP BY user_id) lab ON lab.user_id = u.id
     LEFT JOIN (SELECT user_id, SUM(points_awarded) as score FROM alert_closures WHERE is_correct=1 GROUP BY user_id) cls ON cls.user_id = u.id
     LEFT JOIN (SELECT user_id, COUNT(DISTINCT lab_id) as labs_done FROM user_progress WHERE status='completed' GROUP BY user_id) prog ON prog.user_id = u.id
     LEFT JOIN (SELECT user_id, MAX(expires_at) as last_session FROM sessions GROUP BY user_id) sess ON sess.user_id = u.id
     ORDER BY u.username`
  ).all();
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
  const info = db.prepare(`INSERT INTO users (username, password_hash, role) VALUES (?,?,?)`).run(cleanName, hash, validRole);
  return created(res, { id: info.lastInsertRowid, username: cleanName, role: validRole });
}

// ── PUT /api/admin/users/:id ─────────────────────────────────────────────
async function updateUser(req, res, userId) {
  const admin = requireAdmin(req, res); if (!admin) return;
  const uid   = parseInt(userId, 10);
  if (!db.prepare(`SELECT id FROM users WHERE id=?`).get(uid)) return notFound(res, 'User not found');
  const body = await parseBody(req);
  if (body.active !== undefined) db.prepare(`UPDATE users SET is_active=? WHERE id=?`).run(body.active ? 1 : 0, uid);
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
  db.prepare(`DELETE FROM users WHERE id=?`).run(uid);
  return ok(res);
}

// ── GET /api/admin/progress ──────────────────────────────────────────────
function getProgress(req, res) {
  const admin = requireAdmin(req, res); if (!admin) return;
  const users = db.prepare(`SELECT id, username FROM users WHERE role='analyst' ORDER BY username`).all();
  const labs  = db.prepare(`SELECT id, slug, title, points FROM labs ORDER BY order_index`).all();
  const allProg = db.prepare(`SELECT user_id, lab_id, status, score, completed_at FROM user_progress`).all();
  const matrix = users.map(u => {
    const row = { user_id: u.id, username: u.username, labs: {} };
    labs.forEach(l => {
      const p = allProg.find(x => x.user_id === u.id && x.lab_id === l.id);
      row.labs[l.slug] = p ? { status: p.status, score: p.score, completed_at: p.completed_at } : { status: 'not_started', score: 0 };
    });
    row.total_score = Object.values(row.labs).reduce((s, l) => s + (l.score || 0), 0);
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
    evidence:   (() => { try { return JSON.parse(l.evidence   || '[]'); } catch { return []; } })(),
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
  ).all(parseInt(labId, 10)).map(q => ({ ...q, options: q.options ? JSON.parse(q.options) : null }));
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

module.exports = {
  getStats, listUsers, createUser, updateUser, deleteUser,
  getProgress, listAdminLabs, createLab, updateLab, deleteLab,
  getLabQuestions, addQuestion, updateQuestion, deleteQuestion,
  getAnalystActivity,
};
