// DIAAS-SEC Platform — Backend Server
// Pure Node.js — no Express, no frameworks
// Dependencies: better-sqlite3, bcryptjs

'use strict';

const http     = require('http');
const fs       = require('fs');
const path     = require('path');
const crypto   = require('crypto');
const bcrypt   = require('bcryptjs');
const Database = require('better-sqlite3');

// ── Config ────────────────────────────────────────────────
const PORT    = process.env.PORT || 3000;
const DB_PATH = path.join(__dirname, 'database', 'diaas.db');
const PUBLIC  = path.join(__dirname, 'public');
const SESSION_TTL_HOURS = 24;

// ── Database ──────────────────────────────────────────────
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// ── Migrations (idempotent) ───────────────────────────────
try {
  db.prepare(`ALTER TABLE labs ADD COLUMN is_visible INTEGER DEFAULT 1`).run();
  console.log('[migrate] Added labs.is_visible column');
} catch(e) {
  // Column already exists — ignore
}

// ── MIME types ────────────────────────────────────────────
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.js':   'application/javascript; charset=utf-8',
  '.json': 'application/json',
  '.png':  'image/png',
  '.jpg':  'image/jpeg',
  '.svg':  'image/svg+xml',
  '.ico':  'image/x-icon',
  '.woff2':'font/woff2',
  '.woff': 'font/woff',
};

// ── Helpers ───────────────────────────────────────────────
function jsonRes(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  });
  res.end(body);
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => { body += chunk; if (body.length > 1e6) req.destroy(); });
    req.on('end', () => {
      try { resolve(JSON.parse(body || '{}')); }
      catch { resolve({}); }
    });
    req.on('error', reject);
  });
}

function requireAuth(req, res) {
  const auth  = req.headers['authorization'] || '';
  const token = auth.replace('Bearer ', '').trim();
  if (!token) { jsonRes(res, 401, { error: 'No token provided' }); return null; }
  const now = new Date().toISOString();
  const row = db.prepare(
    `SELECT u.id, u.username, u.role, u.is_active as active
     FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token = ? AND s.expires_at > ? AND u.is_active = 1`
  ).get(token, now);
  if (!row) { jsonRes(res, 401, { error: 'Invalid or expired session' }); return null; }
  return row;
}

function requireAdmin(req, res) {
  const user = requireAuth(req, res);
  if (!user) return null;
  if (user.role !== 'admin') { jsonRes(res, 403, { error: 'Admin access required' }); return null; }
  return user;
}

function serveFile(res, filePath) {
  const ext  = path.extname(filePath).toLowerCase();
  const mime = MIME[ext] || 'application/octet-stream';
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not found');
      return;
    }
    res.writeHead(200, { 'Content-Type': mime, 'Cache-Control': 'no-cache' });
    res.end(data);
  });
}

function getUserTotalScore(userId) {
  const row = db.prepare(
    `SELECT COALESCE(SUM(pts_awarded),0) as total FROM user_answers WHERE user_id=? AND is_correct=1`
  ).get(userId);
  return row ? row.total : 0;
}

function getUserRank(userId) {
  const scores = db.prepare(
    `SELECT user_id, SUM(pts_awarded) as total FROM user_answers WHERE is_correct=1 GROUP BY user_id ORDER BY total DESC`
  ).all();
  const idx = scores.findIndex(r => r.user_id === userId);
  // return 0 if analyst has no score yet — frontend renders "–"
  if (idx === -1) return 0;
  return idx + 1;
}

function getLabsWithProgress(userId) {
  const labs = db.prepare(`SELECT * FROM labs WHERE is_visible=1 OR is_visible IS NULL ORDER BY order_index`).all();
  return labs.map(lab => {
    const prog = db.prepare(
      `SELECT status, score, started_at, completed_at FROM user_progress WHERE user_id=? AND lab_id=?`
    ).get(userId, lab.id);
    const totalQ = db.prepare(`SELECT COUNT(*) as c FROM questions WHERE lab_id=?`).get(lab.id).c;
    const doneQ  = db.prepare(
      `SELECT COUNT(DISTINCT question_id) as c FROM user_answers WHERE user_id=? AND lab_id=? AND is_correct=1`
    ).get(userId, lab.id).c;
    const alertRefs = lab.alert_refs ? JSON.parse(lab.alert_refs) : [];
    return {
      ...lab,
      alert_refs:      alertRefs,
      status:          prog ? prog.status : 'not_started',
      score:           prog ? prog.score  : 0,
      started_at:      prog ? prog.started_at : null,
      completed_at:    prog ? prog.completed_at : null,
      questions_total: totalQ,
      questions_done:  doneQ,
    };
  });
}

// ── Routes ────────────────────────────────────────────────
async function router(req, res) {
  const url    = req.url.split('?')[0];
  const qs     = req.url.includes('?') ? req.url.split('?')[1] : '';
  const params = new URLSearchParams(qs);
  const method = req.method.toUpperCase();

  // CORS preflight
  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin':  '*',
      'Access-Control-Allow-Headers': 'Authorization, Content-Type',
      'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
    });
    res.end();
    return;
  }

  // ── POST /api/auth/login ──────────────────────────────
  if (method === 'POST' && url === '/api/auth/login') {
    const { username, password } = await parseBody(req);
    if (!username || !password) {
      return jsonRes(res, 400, { error: 'Username and password required' });
    }
    const user = db.prepare(`SELECT * FROM users WHERE username=? AND is_active=1`).get(username);
    if (!user || !bcrypt.compareSync(password, user.password_hash)) {
      return jsonRes(res, 401, { error: 'Invalid username or password' });
    }
    const token   = crypto.randomBytes(48).toString('hex');
    const expires = new Date(Date.now() + SESSION_TTL_HOURS * 3600 * 1000).toISOString();
    db.prepare(`INSERT INTO sessions (user_id, token, expires_at) VALUES (?,?,?)`).run(user.id, token, expires);
    return jsonRes(res, 200, {
      token,
      user: { id: user.id, username: user.username, role: user.role }
    });
  }

  // ── POST /api/auth/logout ─────────────────────────────
  if (method === 'POST' && url === '/api/auth/logout') {
    const auth  = req.headers['authorization'] || '';
    const token = auth.replace('Bearer ', '').trim();
    if (token) db.prepare(`DELETE FROM sessions WHERE token=?`).run(token);
    return jsonRes(res, 200, { ok: true });
  }

  // ── GET /api/me ───────────────────────────────────────
  if (method === 'GET' && url === '/api/me') {
    const user = requireAuth(req, res); if (!user) return;
    const score = getUserTotalScore(user.id);
    const rank  = getUserRank(user.id);
    const labsDone = db.prepare(
      `SELECT COUNT(*) as c FROM user_progress WHERE user_id=? AND status='completed'`
    ).get(user.id).c;
    const labsInProgress = db.prepare(
      `SELECT COUNT(*) as c FROM user_progress WHERE user_id=? AND status='in_progress'`
    ).get(user.id).c;
    const totalAnswered = db.prepare(
      `SELECT COUNT(*) as c FROM user_answers WHERE user_id=?`
    ).get(user.id).c;
    const correctAnswered = db.prepare(
      `SELECT COUNT(*) as c FROM user_answers WHERE user_id=? AND is_correct=1`
    ).get(user.id).c;
    const accuracy = totalAnswered > 0 ? Math.round((correctAnswered / totalAnswered) * 100) : 0;
    return jsonRes(res, 200, {
      id: user.id, username: user.username, role: user.role,
      score, rank, labs_done: labsDone, labs_in_progress: labsInProgress,
      total_answered: totalAnswered, correct_answered: correctAnswered, accuracy
    });
  }

  // ── GET /api/labs ─────────────────────────────────────
  if (method === 'GET' && url === '/api/labs') {
    const user = requireAuth(req, res); if (!user) return;
    return jsonRes(res, 200, getLabsWithProgress(user.id));
  }

  // ── GET /api/labs/:slug ───────────────────────────────
  const labMatch = url.match(/^\/api\/labs\/([^/]+)$/);
  if (method === 'GET' && labMatch) {
    const user = requireAuth(req, res); if (!user) return;
    const slug = labMatch[1];
    const lab  = db.prepare(`SELECT * FROM labs WHERE slug=?`).get(slug);
    if (!lab) return jsonRes(res, 404, { error: 'Lab not found' });
    const questions = db.prepare(
      `SELECT id, order_index, question, answer_type, options, points, hint FROM questions WHERE lab_id=? ORDER BY order_index`
    ).all(lab.id).map(q => ({
      ...q,
      options: q.options ? JSON.parse(q.options) : null
    }));
    const answeredQ = db.prepare(
      `SELECT question_id, is_correct, pts_awarded, attempt_number FROM user_answers WHERE user_id=? AND lab_id=? ORDER BY submitted_at DESC`
    ).all(user.id, lab.id);
    const answerMap = {};
    answeredQ.forEach(a => { if (!answerMap[a.question_id]) answerMap[a.question_id] = a; });
    const questionsWithStatus = questions.map(q => ({
      ...q,
      completed:  !!(answerMap[q.id] && answerMap[q.id].is_correct),
      attempts:   answerMap[q.id] ? answerMap[q.id].attempt_number : 0,
      pts_earned: answerMap[q.id] ? answerMap[q.id].pts_awarded : 0,
    }));
    const prog = db.prepare(
      `SELECT status, score, started_at, completed_at FROM user_progress WHERE user_id=? AND lab_id=?`
    ).get(user.id, lab.id);
    const alertRefs = lab.alert_refs ? JSON.parse(lab.alert_refs) : [];
    return jsonRes(res, 200, {
      ...lab,
      alert_refs: alertRefs,
      questions: questionsWithStatus,
      progress: prog || { status: 'not_started', score: 0 }
    });
  }

  // ── POST /api/labs/:slug/submit ───────────────────────
  const submitMatch = url.match(/^\/api\/labs\/([^/]+)\/submit$/);
  if (method === 'POST' && submitMatch) {
    const user = requireAuth(req, res); if (!user) return;
    const slug = submitMatch[1];
    const lab  = db.prepare(`SELECT * FROM labs WHERE slug=?`).get(slug);
    if (!lab) return jsonRes(res, 404, { error: 'Lab not found' });
    const { question_id, answer } = await parseBody(req);
    if (!question_id || answer === undefined) {
      return jsonRes(res, 400, { error: 'question_id and answer required' });
    }
    const question = db.prepare(`SELECT * FROM questions WHERE id=? AND lab_id=?`).get(question_id, lab.id);
    if (!question) return jsonRes(res, 404, { error: 'Question not found' });

    // Already correctly answered?
    const alreadyCorrect = db.prepare(
      `SELECT id FROM user_answers WHERE user_id=? AND question_id=? AND is_correct=1`
    ).get(user.id, question_id);
    if (alreadyCorrect) {
      return jsonRes(res, 200, {
        correct: true, already_answered: true,
        pts: 0, explanation: question.explanation,
        total_score: getUserTotalScore(user.id)
      });
    }

    const priorRow = db.prepare(
      `SELECT attempt_number FROM user_answers WHERE user_id=? AND question_id=? ORDER BY submitted_at DESC LIMIT 1`
    ).get(user.id, question_id);
    const priorAttempts = priorRow ? priorRow.attempt_number : 0;
    const MAX_ATTEMPTS = 3;

    const submitted = String(answer).trim().toLowerCase();
    const correct_a = question.correct_answer.trim().toLowerCase();
    let correct = false;
    if (question.answer_type === 'choice') {
      correct = submitted === correct_a;
    } else {
      const keywords = correct_a.split(/\s+/).filter(w => w.length > 4);
      const matchCount = keywords.filter(k => submitted.includes(k)).length;
      correct = matchCount >= Math.ceil(keywords.length * 0.35);
    }

    const ptsAwarded = correct ? (priorAttempts === 0 ? question.points : Math.floor(question.points * 0.5)) : 0;

    db.prepare(
      `INSERT OR REPLACE INTO user_answers (user_id, lab_id, question_id, submitted_answer, is_correct, pts_awarded, attempt_number)
       VALUES (?,?,?,?,?,?,?)`
    ).run(user.id, lab.id, question_id, answer, correct ? 1 : 0, ptsAwarded, priorAttempts + 1);

    const totalQ = db.prepare(`SELECT COUNT(*) as c FROM questions WHERE lab_id=?`).get(lab.id).c;
    const doneQ  = db.prepare(
      `SELECT COUNT(DISTINCT question_id) as c FROM user_answers WHERE user_id=? AND lab_id=? AND is_correct=1`
    ).get(user.id, lab.id).c;
    const labScore = db.prepare(
      `SELECT COALESCE(SUM(pts_awarded),0) as s FROM user_answers WHERE user_id=? AND lab_id=? AND is_correct=1`
    ).get(user.id, lab.id).s;
    const newStatus = doneQ >= totalQ ? 'completed' : 'in_progress';
    const existing  = db.prepare(`SELECT id FROM user_progress WHERE user_id=? AND lab_id=?`).get(user.id, lab.id);
    if (existing) {
      db.prepare(
        `UPDATE user_progress SET status=?, score=?, completed_at=? WHERE user_id=? AND lab_id=?`
      ).run(newStatus, labScore, newStatus === 'completed' ? new Date().toISOString() : null, user.id, lab.id);
    } else {
      db.prepare(
        `INSERT INTO user_progress (user_id, lab_id, status, score, started_at, completed_at)
         VALUES (?,?,?,?,?,?)`
      ).run(user.id, lab.id, newStatus, labScore, new Date().toISOString(),
        newStatus === 'completed' ? new Date().toISOString() : null);
    }

    const attemptsLeft = correct ? 0 : Math.max(0, MAX_ATTEMPTS - (priorAttempts + 1));
    const reveal = !correct && (priorAttempts + 1) >= MAX_ATTEMPTS;

    return jsonRes(res, 200, {
      correct,
      pts: ptsAwarded,
      explanation: (correct || reveal) ? question.explanation : null,
      correct_answer: reveal ? question.correct_answer : null,
      attempts_left: attemptsLeft,
      lab_status: newStatus,
      total_score: getUserTotalScore(user.id)
    });
  }

  // ── POST /api/user/password ───────────────────────────
  if (method === 'POST' && url === '/api/user/password') {
    const user = requireAuth(req, res); if (!user) return;
    const { current_password, new_password } = await parseBody(req);
    if (!current_password || !new_password) {
      return jsonRes(res, 400, { error: 'current_password and new_password required' });
    }
    if (new_password.length < 8) {
      return jsonRes(res, 400, { error: 'Password must be at least 8 characters' });
    }
    const row = db.prepare(`SELECT password_hash FROM users WHERE id=?`).get(user.id);
    if (!bcrypt.compareSync(current_password, row.password_hash)) {
      return jsonRes(res, 401, { error: 'Current password is incorrect' });
    }
    const hash = bcrypt.hashSync(new_password, 10);
    db.prepare(`UPDATE users SET password_hash=? WHERE id=?`).run(hash, user.id);
    db.prepare(`DELETE FROM sessions WHERE user_id=?`).run(user.id);
    return jsonRes(res, 200, { ok: true });
  }

  // ── GET /api/leaderboard ──────────────────────────────
  if (method === 'GET' && url === '/api/leaderboard') {
    const user = requireAuth(req, res); if (!user) return;
    const rows = db.prepare(
      `SELECT u.id, u.username,
         COALESCE(SUM(CASE WHEN a.is_correct=1 THEN a.pts_awarded ELSE 0 END),0) as score,
         COUNT(DISTINCT CASE WHEN a.is_correct=1 THEN a.question_id END) as correct_answers,
         COUNT(DISTINCT CASE WHEN p.status='completed' THEN p.lab_id END) as labs_done,
         COUNT(DISTINCT a.question_id) as total_answers
       FROM users u
       LEFT JOIN user_answers a ON a.user_id = u.id
       LEFT JOIN user_progress p ON p.user_id = u.id
       WHERE u.role='analyst' AND u.is_active=1
       GROUP BY u.id ORDER BY score DESC LIMIT 50`
    ).all();
    const board = rows.map((r, i) => ({
      rank: r.score > 0 ? i + 1 : 0,
      id: r.id,
      username: r.username,
      score: r.score,
      labs_done: r.labs_done,
      correct_answers: r.correct_answers,
      accuracy: r.total_answers > 0 ? Math.round((r.correct_answers / r.total_answers) * 100) : 0,
      is_me: r.id === user.id,
    }));
    return jsonRes(res, 200, board);
  }

  // ── GET /api/alerts ───────────────────────────────────
  if (method === 'GET' && url === '/api/alerts') {
    const user = requireAuth(req, res); if (!user) return;
    const severity  = params.get('severity');
    const category  = params.get('category');
    const status    = params.get('status');
    const search    = params.get('q');
    const limit     = Math.min(parseInt(params.get('limit') || '100'), 200);
    const offset    = parseInt(params.get('offset') || '0');

    let where = [];
    let args  = [];
    if (severity) { where.push('severity=?'); args.push(severity); }
    if (category) { where.push('category=?'); args.push(category); }
    if (status)   { where.push('status=?');   args.push(status); }
    if (search)   {
      where.push(`(title LIKE ? OR description LIKE ? OR host LIKE ? OR src_ip LIKE ? OR mitre_technique LIKE ?)`);
      const q = `%${search}%`;
      args.push(q, q, q, q, q);
    }

    const whereStr = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const alerts = db.prepare(
      `SELECT id, severity, category, title, source, host, src_ip, dst_ip, username,
              process, event_id, mitre_tactic, mitre_technique, status, timestamp
       FROM soc_alerts ${whereStr}
       ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,
                timestamp DESC
       LIMIT ? OFFSET ?`
    ).all(...args, limit, offset);

    const total = db.prepare(`SELECT COUNT(*) as c FROM soc_alerts ${whereStr}`).get(...args).c;

    // summary counts
    const counts = db.prepare(
      `SELECT severity, COUNT(*) as n FROM soc_alerts GROUP BY severity`
    ).all().reduce((acc, r) => { acc[r.severity] = r.n; return acc; }, {});

    return jsonRes(res, 200, { alerts, total, counts });
  }

  // ── GET /api/alerts/:id ───────────────────────────────
  const alertMatch = url.match(/^\/api\/alerts\/([A-Z0-9-]+)$/);
  if (method === 'GET' && alertMatch) {
    const user = requireAuth(req, res); if (!user) return;
    const alert = db.prepare(`SELECT * FROM soc_alerts WHERE id=?`).get(alertMatch[1]);
    if (!alert) return jsonRes(res, 404, { error: 'Alert not found' });
    // parse JSON fields
    ['iocs','timeline','network_flow'].forEach(f => {
      try { alert[f] = JSON.parse(alert[f] || 'null'); } catch { alert[f] = null; }
    });
    return jsonRes(res, 200, alert);
  }

  // ── GET /api/admin/stats ──────────────────────────────
  if (method === 'GET' && url === '/api/admin/stats') {
    const admin = requireAdmin(req, res); if (!admin) return;
    const total_users    = db.prepare(`SELECT COUNT(*) as c FROM users WHERE role='analyst'`).get().c;
    const active_users   = db.prepare(`SELECT COUNT(*) as c FROM users WHERE role='analyst' AND is_active=1`).get().c;
    const labs_completed = db.prepare(`SELECT COUNT(*) as c FROM user_progress WHERE status='completed'`).get().c;
    const total_labs     = db.prepare(`SELECT COUNT(*) as c FROM labs`).get().c;
    const total_alerts   = db.prepare(`SELECT COUNT(*) as c FROM soc_alerts`).get().c;
    const avg_score_row  = db.prepare(
      `SELECT COALESCE(AVG(s),0) as avg FROM (SELECT SUM(pts_awarded) as s FROM user_answers WHERE is_correct=1 GROUP BY user_id)`
    ).get();
    const total_answers  = db.prepare(`SELECT COUNT(*) as c FROM user_answers`).get().c;
    return jsonRes(res, 200, {
      total_users, active_users, labs_completed, total_labs, total_alerts,
      avg_score: Math.round(avg_score_row.avg),
      total_answers,
    });
  }

  // ── GET /api/admin/users ──────────────────────────────
  if (method === 'GET' && url === '/api/admin/users') {
    const admin = requireAdmin(req, res); if (!admin) return;
    const users = db.prepare(
      `SELECT u.id, u.username, u.role, u.is_active, u.created_at,
         COALESCE(SUM(CASE WHEN a.is_correct=1 THEN a.pts_awarded ELSE 0 END),0) as score,
         COUNT(DISTINCT CASE WHEN p.status='completed' THEN p.lab_id END) as labs_done,
         MAX(s.expires_at) as last_session
       FROM users u
       LEFT JOIN user_answers a ON a.user_id = u.id
       LEFT JOIN user_progress p ON p.user_id = u.id
       LEFT JOIN sessions s ON s.user_id = u.id
       GROUP BY u.id ORDER BY u.username`
    ).all();
    return jsonRes(res, 200, users);
  }

  // ── POST /api/admin/users ─────────────────────────────
  if (method === 'POST' && url === '/api/admin/users') {
    const admin = requireAdmin(req, res); if (!admin) return;
    const { username, password, role } = await parseBody(req);
    if (!username || !password) return jsonRes(res, 400, { error: 'username and password required' });
    const validRole = ['analyst', 'admin'].includes(role) ? role : 'analyst';
    const existing = db.prepare(`SELECT id FROM users WHERE username=?`).get(username);
    if (existing) return jsonRes(res, 409, { error: 'Username already exists' });
    const hash = bcrypt.hashSync(password, 10);
    const info = db.prepare(
      `INSERT INTO users (username, password_hash, role) VALUES (?,?,?)`
    ).run(username, hash, validRole);
    return jsonRes(res, 201, { id: info.lastInsertRowid, username, role: validRole });
  }

  // ── PUT /api/admin/users/:id ──────────────────────────
  const userPutMatch = url.match(/^\/api\/admin\/users\/(\d+)$/);
  if (method === 'PUT' && userPutMatch) {
    const admin = requireAdmin(req, res); if (!admin) return;
    const userId = parseInt(userPutMatch[1]);
    const body = await parseBody(req);
    const user = db.prepare(`SELECT id FROM users WHERE id=?`).get(userId);
    if (!user) return jsonRes(res, 404, { error: 'User not found' });
    if (body.active !== undefined) {
      db.prepare(`UPDATE users SET is_active=? WHERE id=?`).run(body.active ? 1 : 0, userId);
    }
    if (body.password) {
      const hash = bcrypt.hashSync(body.password, 10);
      db.prepare(`UPDATE users SET password_hash=? WHERE id=?`).run(hash, userId);
      db.prepare(`DELETE FROM sessions WHERE user_id=?`).run(userId);
    }
    return jsonRes(res, 200, { ok: true });
  }

  // ── DELETE /api/admin/users/:id ───────────────────────
  const userDelMatch = url.match(/^\/api\/admin\/users\/(\d+)$/);
  if (method === 'DELETE' && userDelMatch) {
    const admin = requireAdmin(req, res); if (!admin) return;
    const userId = parseInt(userDelMatch[1]);
    if (userId === admin.id) return jsonRes(res, 400, { error: 'Cannot delete your own account' });
    db.prepare(`DELETE FROM users WHERE id=?`).run(userId);
    return jsonRes(res, 200, { ok: true });
  }

  // ── GET /api/admin/progress ───────────────────────────
  if (method === 'GET' && url === '/api/admin/progress') {
    const admin = requireAdmin(req, res); if (!admin) return;
    const users = db.prepare(`SELECT id, username FROM users WHERE role='analyst' ORDER BY username`).all();
    const labs  = db.prepare(`SELECT id, slug, title, points FROM labs ORDER BY order_index`).all();
    const allProgress = db.prepare(`SELECT user_id, lab_id, status, score, completed_at FROM user_progress`).all();
    const matrix = users.map(u => {
      const row = { user_id: u.id, username: u.username, labs: {} };
      labs.forEach(l => {
        const p = allProgress.find(x => x.user_id === u.id && x.lab_id === l.id);
        row.labs[l.slug] = p
          ? { status: p.status, score: p.score, completed_at: p.completed_at }
          : { status: 'not_started', score: 0 };
      });
      row.total_score = Object.values(row.labs).reduce((s, l) => s + l.score, 0);
      return row;
    });
    return jsonRes(res, 200, { users: matrix, labs });
  }

  // ── GET /api/admin/labs ───────────────────────────────
  if (method === 'GET' && url === '/api/admin/labs') {
    const admin = requireAdmin(req, res); if (!admin) return;
    const labs = db.prepare(
      `SELECT l.*,
         (SELECT COUNT(*) FROM questions q WHERE q.lab_id = l.id) as question_count,
         (SELECT COUNT(*) FROM user_progress p WHERE p.lab_id = l.id AND p.status='completed') as completions
       FROM labs l ORDER BY l.order_index`
    ).all().map(l => ({ ...l, alert_refs: l.alert_refs ? JSON.parse(l.alert_refs) : [] }));
    return jsonRes(res, 200, labs);
  }

  // ── POST /api/admin/labs ──────────────────────────────
  if (method === 'POST' && url === '/api/admin/labs') {
    const admin = requireAdmin(req, res); if (!admin) return;
    const body = await parseBody(req);
    const { title, description, difficulty, category, points, alert_refs, is_visible } = body;
    if (!title) return jsonRes(res, 400, { error: 'title is required' });
    const slug = title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') + '-' + Date.now().toString(36);
    const maxOrder = db.prepare(`SELECT COALESCE(MAX(order_index),0) as m FROM labs`).get().m;
    const info = db.prepare(
      `INSERT INTO labs (slug, title, description, difficulty, category, points, alert_refs, order_index, is_visible)
       VALUES (?,?,?,?,?,?,?,?,?)`
    ).run(
      slug,
      title.trim(),
      (description || '').trim(),
      difficulty || 'medium',
      (category || '').trim(),
      parseInt(points) || 100,
      JSON.stringify(Array.isArray(alert_refs) ? alert_refs : []),
      maxOrder + 1,
      is_visible === false || is_visible === 0 ? 0 : 1
    );
    return jsonRes(res, 201, { id: info.lastInsertRowid, slug });
  }

  // ── PUT /api/admin/labs/:id ───────────────────────────
  const labAdminPutMatch = url.match(/^\/api\/admin\/labs\/(\d+)$/);
  if (method === 'PUT' && labAdminPutMatch) {
    const admin = requireAdmin(req, res); if (!admin) return;
    const labId = parseInt(labAdminPutMatch[1]);
    const lab = db.prepare(`SELECT id FROM labs WHERE id=?`).get(labId);
    if (!lab) return jsonRes(res, 404, { error: 'Lab not found' });
    const body = await parseBody(req);
    const fields = [];
    const vals   = [];
    if (body.title       !== undefined) { fields.push('title=?');       vals.push(body.title.trim()); }
    if (body.description !== undefined) { fields.push('description=?'); vals.push(body.description.trim()); }
    if (body.difficulty  !== undefined) { fields.push('difficulty=?');  vals.push(body.difficulty); }
    if (body.category    !== undefined) { fields.push('category=?');    vals.push(body.category.trim()); }
    if (body.points      !== undefined) { fields.push('points=?');      vals.push(parseInt(body.points) || 100); }
    if (body.alert_refs  !== undefined) { fields.push('alert_refs=?');  vals.push(JSON.stringify(Array.isArray(body.alert_refs) ? body.alert_refs : [])); }
    if (body.is_visible  !== undefined) { fields.push('is_visible=?');  vals.push(body.is_visible ? 1 : 0); }
    if (body.order_index !== undefined) { fields.push('order_index=?'); vals.push(parseInt(body.order_index)); }
    if (fields.length === 0) return jsonRes(res, 400, { error: 'Nothing to update' });
    vals.push(labId);
    db.prepare(`UPDATE labs SET ${fields.join(', ')} WHERE id=?`).run(...vals);
    return jsonRes(res, 200, { ok: true });
  }

  // ── DELETE /api/admin/labs/:id ────────────────────────
  const labAdminDelMatch = url.match(/^\/api\/admin\/labs\/(\d+)$/);
  if (method === 'DELETE' && labAdminDelMatch) {
    const admin = requireAdmin(req, res); if (!admin) return;
    const labId = parseInt(labAdminDelMatch[1]);
    const lab = db.prepare(`SELECT id FROM labs WHERE id=?`).get(labId);
    if (!lab) return jsonRes(res, 404, { error: 'Lab not found' });
    db.prepare(`DELETE FROM labs WHERE id=?`).run(labId);
    return jsonRes(res, 200, { ok: true });
  }

  // ── GET /api/admin/labs/:id/questions ─────────────────
  const labQGetMatch = url.match(/^\/api\/admin\/labs\/(\d+)\/questions$/);
  if (method === 'GET' && labQGetMatch) {
    const admin = requireAdmin(req, res); if (!admin) return;
    const labId = parseInt(labQGetMatch[1]);
    const questions = db.prepare(`SELECT * FROM questions WHERE lab_id=? ORDER BY order_index`).all(labId).map(q => ({
      ...q,
      options: q.options ? JSON.parse(q.options) : []
    }));
    return jsonRes(res, 200, questions);
  }

  // ── POST /api/admin/labs/:id/questions ────────────────
  const labQPostMatch = url.match(/^\/api\/admin\/labs\/(\d+)\/questions$/);
  if (method === 'POST' && labQPostMatch) {
    const admin = requireAdmin(req, res); if (!admin) return;
    const labId = parseInt(labQPostMatch[1]);
    const lab = db.prepare(`SELECT id FROM labs WHERE id=?`).get(labId);
    if (!lab) return jsonRes(res, 404, { error: 'Lab not found' });
    const body = await parseBody(req);
    const { question, answer_type, options, correct_answer, hint, explanation, points, difficulty } = body;
    if (!question || !correct_answer) return jsonRes(res, 400, { error: 'question and correct_answer are required' });
    const maxOrder = db.prepare(`SELECT COALESCE(MAX(order_index),0) as m FROM questions WHERE lab_id=?`).get(labId).m;
    const info = db.prepare(
      `INSERT INTO questions (lab_id, question, answer_type, options, correct_answer, hint, explanation, points, difficulty, order_index)
       VALUES (?,?,?,?,?,?,?,?,?,?)`
    ).run(
      labId,
      question.trim(),
      answer_type || 'choice',
      options ? JSON.stringify(Array.isArray(options) ? options : []) : null,
      correct_answer.trim(),
      (hint || '').trim(),
      (explanation || '').trim(),
      parseInt(points) || 20,
      difficulty || 'medium',
      maxOrder + 1
    );
    return jsonRes(res, 201, { id: info.lastInsertRowid });
  }

  // ── PUT /api/admin/questions/:id ──────────────────────
  const qPutMatch = url.match(/^\/api\/admin\/questions\/(\d+)$/);
  if (method === 'PUT' && qPutMatch) {
    const admin = requireAdmin(req, res); if (!admin) return;
    const qId = parseInt(qPutMatch[1]);
    const q = db.prepare(`SELECT id FROM questions WHERE id=?`).get(qId);
    if (!q) return jsonRes(res, 404, { error: 'Question not found' });
    const body = await parseBody(req);
    const fields = [];
    const vals   = [];
    if (body.question       !== undefined) { fields.push('question=?');       vals.push(body.question.trim()); }
    if (body.answer_type    !== undefined) { fields.push('answer_type=?');    vals.push(body.answer_type); }
    if (body.options        !== undefined) { fields.push('options=?');        vals.push(body.options ? JSON.stringify(Array.isArray(body.options) ? body.options : []) : null); }
    if (body.correct_answer !== undefined) { fields.push('correct_answer=?'); vals.push(body.correct_answer.trim()); }
    if (body.hint           !== undefined) { fields.push('hint=?');           vals.push(body.hint.trim()); }
    if (body.explanation    !== undefined) { fields.push('explanation=?');    vals.push(body.explanation.trim()); }
    if (body.points         !== undefined) { fields.push('points=?');         vals.push(parseInt(body.points) || 20); }
    if (body.difficulty     !== undefined) { fields.push('difficulty=?');     vals.push(body.difficulty); }
    if (body.order_index    !== undefined) { fields.push('order_index=?');    vals.push(parseInt(body.order_index)); }
    if (fields.length === 0) return jsonRes(res, 400, { error: 'Nothing to update' });
    vals.push(qId);
    db.prepare(`UPDATE questions SET ${fields.join(', ')} WHERE id=?`).run(...vals);
    return jsonRes(res, 200, { ok: true });
  }

  // ── DELETE /api/admin/questions/:id ───────────────────
  const qDelMatch = url.match(/^\/api\/admin\/questions\/(\d+)$/);
  if (method === 'DELETE' && qDelMatch) {
    const admin = requireAdmin(req, res); if (!admin) return;
    const qId = parseInt(qDelMatch[1]);
    db.prepare(`DELETE FROM questions WHERE id=?`).run(qId);
    return jsonRes(res, 200, { ok: true });
  }

  // ── Static files & HTML routes ────────────────────────
  if (method === 'GET') {
    if (url === '/' || url === '/login' || url === '/login.html') {
      return serveFile(res, path.join(PUBLIC, 'login.html'));
    }
    if (url === '/analyst' || url === '/analyst/') {
      return serveFile(res, path.join(PUBLIC, 'analyst', 'index.html'));
    }
    if (url === '/admin' || url === '/admin/') {
      return serveFile(res, path.join(PUBLIC, 'admin', 'index.html'));
    }
    const filePath = path.join(PUBLIC, url);
    if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      return serveFile(res, filePath);
    }
  }

  // ── POST /api/alerts/:id/status ─────────────────────
  // Body: { status, triage_reason?, containment_steps?, eradication_steps?,
  //         recovery_steps?, rca_notes?, fp_reason? }
  const statusMatch = url.match(/^\/api\/alerts\/([A-Z0-9-]+)\/status$/);
  if (method === 'POST' && statusMatch) {
    const user = requireAuth(req, res); if (!user) return;
    const alertId = statusMatch[1];
    const body = await parseBody(req);
    const { status, triage_reason, containment_steps, eradication_steps,
            recovery_steps, rca_notes, fp_reason } = body;

    const allowed = ['open', 'investigating', 'false_positive', 'closed'];
    if (!allowed.includes(status)) return jsonRes(res, 400, { error: 'Invalid status' });

    const alert = db.prepare('SELECT id, category, severity FROM soc_alerts WHERE id=?').get(alertId);
    if (!alert) return jsonRes(res, 404, { error: 'Alert not found' });

    // Ensure alert_closures table exists (idempotent migration)
    db.prepare(`CREATE TABLE IF NOT EXISTS alert_closures (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      alert_id TEXT NOT NULL, user_id INTEGER NOT NULL,
      classification TEXT NOT NULL,
      triage_reason TEXT, containment_steps TEXT, eradication_steps TEXT,
      recovery_steps TEXT, rca_notes TEXT, fp_reason TEXT,
      is_correct INTEGER DEFAULT 0, points_awarded INTEGER DEFAULT 0,
      closed_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(alert_id) REFERENCES soc_alerts(id) ON DELETE CASCADE
    )`).run();

    let points_awarded = 0;
    let is_correct = 0;

    if (status === 'closed' || status === 'false_positive') {
      // Validate: require justification for both paths
      if (status === 'false_positive' && !fp_reason) {
        return jsonRes(res, 400, { error: 'Justification required to close as false positive' });
      }
      if (status === 'closed' && (!triage_reason || !containment_steps || !eradication_steps || !recovery_steps || !rca_notes)) {
        return jsonRes(res, 400, { error: 'All IR steps are required to close as resolved' });
      }

      // Ground truth: alerts with category containing 'Test' or title containing
      // 'false positive' or '[BENIGN]' are FP; everything else is TP.
      // Simple heuristic — in a real system this would be a db field.
      const title = String(db.prepare('SELECT title FROM soc_alerts WHERE id=?').get(alertId)?.title || '');
      const isTruePositive = !title.toLowerCase().includes('[benign]') &&
                             !title.toLowerCase().includes('false positive') &&
                             !alert.category?.toLowerCase().includes('test');

      if (status === 'closed' && isTruePositive) {
        is_correct = 1; points_awarded = 5;
      } else if (status === 'false_positive' && !isTruePositive) {
        is_correct = 1; points_awarded = 3;
      }
      // wrong classification = 0 points (no negatives)

      // Record closure
      db.prepare(`INSERT INTO alert_closures
        (alert_id, user_id, classification, triage_reason, containment_steps,
         eradication_steps, recovery_steps, rca_notes, fp_reason, is_correct, points_awarded)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)`
      ).run(alertId, user.id, status,
        triage_reason || null, containment_steps || null,
        eradication_steps || null, recovery_steps || null,
        rca_notes || null, fp_reason || null,
        is_correct, points_awarded);

      // Award points to user if correct
      if (points_awarded > 0) {
        db.prepare('UPDATE users SET points = COALESCE(points,0) + ? WHERE id=?')
          .run(points_awarded, user.id);
      }
    }

    db.prepare('UPDATE soc_alerts SET status=? WHERE id=?').run(status, alertId);
    return jsonRes(res, 200, { ok: true, alertId, status, is_correct, points_awarded });
  }

  // ── GET /api/alerts/:id/incident ─────────────────────
  const incidentGetMatch = url.match(/^\/api\/alerts\/([A-Z0-9-]+)\/incident$/);
  if (method === 'GET' && incidentGetMatch) {
    const user = requireAuth(req, res); if (!user) return;
    const alertId = incidentGetMatch[1];
    // ensure incidents table exists (migration)
    db.prepare(`CREATE TABLE IF NOT EXISTS incidents (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      alert_id TEXT NOT NULL,
      user_id INTEGER NOT NULL,
      title TEXT,
      stage TEXT NOT NULL DEFAULT 'identification',
      containment_at TEXT, eradication_at TEXT, recovery_at TEXT, rca_at TEXT, closed_at TEXT,
      notes TEXT DEFAULT '{}',
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(alert_id) REFERENCES soc_alerts(id) ON DELETE CASCADE
    )`).run();
    const inc = db.prepare('SELECT * FROM incidents WHERE alert_id=?').get(alertId);
    return jsonRes(res, 200, inc || null);
  }

  // ── POST /api/alerts/:id/incident ─────────────────────
  // Body: { stage: 'identification'|'containment'|'eradication'|'recovery'|'rca'|'closed', notes?: '...', title?: '...' }
  const incidentPostMatch = url.match(/^\/api\/alerts\/([A-Z0-9-]+)\/incident$/);
  if (method === 'POST' && incidentPostMatch) {
    const user = requireAuth(req, res); if (!user) return;
    const alertId = incidentPostMatch[1];
    const { stage, notes, title } = await parseBody(req);
    const validStages = ['identification','containment','eradication','recovery','rca','closed'];
    if (!validStages.includes(stage)) return jsonRes(res, 400, { error: 'Invalid stage' });
    // ensure table exists
    db.prepare(`CREATE TABLE IF NOT EXISTS incidents (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      alert_id TEXT NOT NULL,
      user_id INTEGER NOT NULL,
      title TEXT,
      stage TEXT NOT NULL DEFAULT 'identification',
      containment_at TEXT, eradication_at TEXT, recovery_at TEXT, rca_at TEXT, closed_at TEXT,
      notes TEXT DEFAULT '{}',
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(alert_id) REFERENCES soc_alerts(id) ON DELETE CASCADE
    )`).run();
    const existing = db.prepare('SELECT * FROM incidents WHERE alert_id=?').get(alertId);
    const now = new Date().toISOString();
    const stageCol = { containment: 'containment_at', eradication: 'eradication_at', recovery: 'recovery_at', rca: 'rca_at', closed: 'closed_at' }[stage];
    if (!existing) {
      // create incident record at identification stage
      const mergedNotes = JSON.stringify({ identification: notes || '' });
      db.prepare(
        `INSERT INTO incidents (alert_id, user_id, title, stage, notes, created_at, updated_at) VALUES (?,?,?,?,?,?,?)`
      ).run(alertId, user.id, title || null, stage, mergedNotes, now, now);
    } else {
      // advance stage + record timestamp + merge notes
      let parsedNotes = {};
      try { parsedNotes = JSON.parse(existing.notes || '{}'); } catch(e) {}
      if (notes) parsedNotes[stage] = notes;
      const updates = [`stage=?`, `notes=?`, `updated_at=?`];
      const vals = [stage, JSON.stringify(parsedNotes), now];
      if (stageCol && !existing[stageCol]) { updates.push(`${stageCol}=?`); vals.push(now); }
      vals.push(alertId);
      db.prepare(`UPDATE incidents SET ${updates.join(', ')} WHERE alert_id=?`).run(...vals);
    }
    // also update alert status
    const alertStatus = stage === 'closed' ? 'closed' : 'investigating';
    db.prepare('UPDATE soc_alerts SET status=? WHERE id=?').run(alertStatus, alertId);
    const result = db.prepare('SELECT * FROM incidents WHERE alert_id=?').get(alertId);
    return jsonRes(res, 200, { ok: true, incident: result });
  }

  // ── POST /api/alerts/:id/escalate ────────────────────
  const escalateMatch = url.match(/^\/api\/alerts\/([A-Z0-9-]+)\/escalate$/);
  if (method === 'POST' && escalateMatch) {
    const user = requireAuth(req, res); if (!user) return;
    const alertId = escalateMatch[1];
    const alert = db.prepare(`SELECT id FROM soc_alerts WHERE id=?`).get(alertId);
    if (!alert) return jsonRes(res, 404, { error: 'Alert not found' });
    const { level, justification } = await parseBody(req);
    const validLevel = ['L2', 'L3'].includes(level) ? level : 'L2';
    const info = db.prepare(
      `INSERT INTO escalations (alert_id, user_id, level, justification) VALUES (?,?,?,?)`
    ).run(alertId, user.id, validLevel, justification || null);
    db.prepare(`UPDATE soc_alerts SET status='investigating' WHERE id=?`).run(alertId);
    return jsonRes(res, 200, { ok: true, escalation_id: info.lastInsertRowid });
  }

  // ── GET /api/alerts/:id/escalations ──────────────────
  const escalationsMatch = url.match(/^\/api\/alerts\/([A-Z0-9-]+)\/escalations$/);
  if (method === 'GET' && escalationsMatch) {
    const user = requireAuth(req, res); if (!user) return;
    const alertId = escalationsMatch[1];
    const rows = db.prepare(
      `SELECT e.id, e.alert_id, e.level, e.justification, e.status, e.created_at,
              u.username
       FROM escalations e
       JOIN users u ON u.id = e.user_id
       WHERE e.alert_id = ?
       ORDER BY e.created_at ASC`
    ).all(alertId);
    return jsonRes(res, 200, rows);
  }

  // ── GET /api/admin/analysts/:id/activity ──────────────────
  const analystActivityMatch = url.match(/^\/api\/admin\/analysts\/(\d+)\/activity$/);
  if (method === 'GET' && analystActivityMatch) {
    const admin = requireAuth(req, res); if (!admin) return;
    if (admin.role !== 'admin') return jsonRes(res, 403, { error: 'Forbidden' });
    const userId = parseInt(analystActivityMatch[1]);

    // Ensure table exists
    db.prepare(`CREATE TABLE IF NOT EXISTS alert_closures (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      alert_id TEXT NOT NULL, user_id INTEGER NOT NULL,
      classification TEXT NOT NULL,
      triage_reason TEXT, containment_steps TEXT, eradication_steps TEXT,
      recovery_steps TEXT, rca_notes TEXT, fp_reason TEXT,
      is_correct INTEGER DEFAULT 0, points_awarded INTEGER DEFAULT 0,
      closed_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(alert_id) REFERENCES soc_alerts(id) ON DELETE CASCADE
    )`).run();

    const closures = db.prepare(`
      SELECT ac.*, sa.title as alert_title, sa.severity, sa.category
      FROM alert_closures ac
      LEFT JOIN soc_alerts sa ON sa.id = ac.alert_id
      WHERE ac.user_id = ?
      ORDER BY ac.closed_at DESC
      LIMIT 50
    `).all(userId);

    const total = closures.length;
    const correct = closures.filter(c => c.is_correct).length;
    const fps = closures.filter(c => c.classification === 'false_positive');
    const tps = closures.filter(c => c.classification === 'closed');
    const fp_correct = fps.filter(c => c.is_correct).length;
    const fp_accuracy = fps.length > 0 ? Math.round((fp_correct / fps.length) * 100) + '%' : 'N/A';
    const triage_score = total > 0 ? Math.round((correct / total) * 100) : 0;
    const total_points = closures.reduce((s, c) => s + (c.points_awarded || 0), 0);

    const records = closures.map(c => ({
      alert_id: c.alert_id,
      alert_title: c.alert_title,
      severity: c.severity,
      classification: c.classification,
      is_correct: !!c.is_correct,
      points: c.points_awarded,
      fp_reason: c.fp_reason,
      triage_reason: c.triage_reason,
      containment_steps: c.containment_steps,
      eradication_steps: c.eradication_steps,
      recovery_steps: c.recovery_steps,
      rca_notes: c.rca_notes,
      closed_at: c.closed_at
    }));

    return jsonRes(res, 200, {
      alerts_triaged: total,
      correct_closes: correct,
      fp_accuracy,
      triage_score,
      total_points,
      records
    });
  }

  // 404 fallback
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not found' }));
}

// ── Server ────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  try {
    await router(req, res);
  } catch (err) {
    console.error('[ERROR]', err.message);
    if (!res.headersSent) {
      jsonRes(res, 500, { error: 'Internal server error' });
    }
  }
});

// Clean expired sessions every hour
setInterval(() => {
  const deleted = db.prepare(`DELETE FROM sessions WHERE expires_at < datetime('now')`).run();
  if (deleted.changes > 0) console.log(`[cleanup] Removed ${deleted.changes} expired sessions`);
}, 3600 * 1000);

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n  DIAAS-SEC Platform`);
  console.log(`  Running at http://0.0.0.0:${PORT}`);
  console.log(`  Login:   http://localhost:${PORT}`);
  console.log(`  Analyst: http://localhost:${PORT}/analyst`);
  console.log(`  Admin:   http://localhost:${PORT}/admin\n`);
});
