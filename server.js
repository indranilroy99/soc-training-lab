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
    `SELECT u.id, u.username, u.role, u.active
     FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token = ? AND s.expires_at > ? AND u.active = 1`
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
    `SELECT COALESCE(SUM(pts_awarded),0) as total FROM answers WHERE user_id=? AND correct=1`
  ).get(userId);
  return row ? row.total : 0;
}

function getUserRank(userId) {
  const scores = db.prepare(
    `SELECT user_id, SUM(pts_awarded) as total FROM answers WHERE correct=1 GROUP BY user_id ORDER BY total DESC`
  ).all();
  const idx = scores.findIndex(r => r.user_id === userId);
  return idx === -1 ? scores.length + 1 : idx + 1;
}

function getLabsWithProgress(userId) {
  const labs = db.prepare(`SELECT * FROM labs WHERE active=1 ORDER BY order_num`).all();
  return labs.map(lab => {
    const prog = db.prepare(
      `SELECT status, score, attempts, started_at, completed_at FROM progress WHERE user_id=? AND lab_id=?`
    ).get(userId, lab.id);
    const totalQ = db.prepare(`SELECT COUNT(*) as c FROM questions WHERE lab_id=?`).get(lab.id).c;
    const doneQ  = db.prepare(
      `SELECT COUNT(DISTINCT question_id) as c FROM answers WHERE user_id=? AND lab_id=? AND correct=1`
    ).get(userId, lab.id).c;
    return {
      ...lab,
      status:       prog ? prog.status : 'not_started',
      score:        prog ? prog.score  : 0,
      attempts:     prog ? prog.attempts : 0,
      started_at:   prog ? prog.started_at : null,
      completed_at: prog ? prog.completed_at : null,
      questions_total: totalQ,
      questions_done:  doneQ,
    };
  });
}

// ── Routes ────────────────────────────────────────────────
async function router(req, res) {
  const url    = req.url.split('?')[0];
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
    const user = db.prepare(`SELECT * FROM users WHERE username=? AND active=1`).get(username);
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
      `SELECT COUNT(*) as c FROM progress WHERE user_id=? AND status='completed'`
    ).get(user.id).c;
    const labsInProgress = db.prepare(
      `SELECT COUNT(*) as c FROM progress WHERE user_id=? AND status='in_progress'`
    ).get(user.id).c;
    const totalAnswered = db.prepare(
      `SELECT COUNT(*) as c FROM answers WHERE user_id=?`
    ).get(user.id).c;
    const correctAnswered = db.prepare(
      `SELECT COUNT(*) as c FROM answers WHERE user_id=? AND correct=1`
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
    const lab  = db.prepare(`SELECT * FROM labs WHERE slug=? AND active=1`).get(slug);
    if (!lab) return jsonRes(res, 404, { error: 'Lab not found' });
    const questions = db.prepare(
      `SELECT id, order_num, question_text, answer_type, options, points, hint FROM questions WHERE lab_id=? ORDER BY order_num`
    ).all(lab.id).map(q => ({
      ...q,
      options: q.options ? JSON.parse(q.options) : null
    }));
    // attach per-question completion status for this user
    const answeredQ = db.prepare(
      `SELECT question_id, correct, pts_awarded, attempts FROM answers WHERE user_id=? AND lab_id=? ORDER BY submitted_at DESC`
    ).all(user.id, lab.id);
    // only keep most recent per question
    const answerMap = {};
    answeredQ.forEach(a => { if (!answerMap[a.question_id]) answerMap[a.question_id] = a; });
    const questionsWithStatus = questions.map(q => ({
      ...q,
      completed:   !!(answerMap[q.id] && answerMap[q.id].correct),
      attempts:    answerMap[q.id] ? answerMap[q.id].attempts : 0,
      pts_earned:  answerMap[q.id] ? answerMap[q.id].pts_awarded : 0,
    }));
    const prog = db.prepare(
      `SELECT status, score, started_at, completed_at FROM progress WHERE user_id=? AND lab_id=?`
    ).get(user.id, lab.id);
    return jsonRes(res, 200, {
      ...lab,
      questions: questionsWithStatus,
      progress: prog || { status: 'not_started', score: 0 }
    });
  }

  // ── POST /api/labs/:slug/submit ───────────────────────
  const submitMatch = url.match(/^\/api\/labs\/([^/]+)\/submit$/);
  if (method === 'POST' && submitMatch) {
    const user = requireAuth(req, res); if (!user) return;
    const slug = submitMatch[1];
    const lab  = db.prepare(`SELECT * FROM labs WHERE slug=? AND active=1`).get(slug);
    if (!lab) return jsonRes(res, 404, { error: 'Lab not found' });
    const { question_id, answer } = await parseBody(req);
    if (!question_id || answer === undefined) {
      return jsonRes(res, 400, { error: 'question_id and answer required' });
    }
    const question = db.prepare(`SELECT * FROM questions WHERE id=? AND lab_id=?`).get(question_id, lab.id);
    if (!question) return jsonRes(res, 404, { error: 'Question not found' });

    // Check if already correctly answered
    const alreadyCorrect = db.prepare(
      `SELECT id FROM answers WHERE user_id=? AND question_id=? AND correct=1`
    ).get(user.id, question_id);
    if (alreadyCorrect) {
      return jsonRes(res, 200, {
        correct: true, already_answered: true,
        pts: 0, explanation: question.explanation,
        total_score: getUserTotalScore(user.id)
      });
    }

    // Count prior attempts for this question
    const priorAttempts = db.prepare(
      `SELECT COUNT(*) as c FROM answers WHERE user_id=? AND question_id=?`
    ).get(user.id, question_id).c;
    const MAX_ATTEMPTS = 3;

    // Normalise answer comparison — case-insensitive, trim, partial match for text type
    const submitted  = String(answer).trim().toLowerCase();
    const correct_a  = question.correct_answer.trim().toLowerCase();
    let correct = false;
    if (question.answer_type === 'choice') {
      correct = submitted === correct_a;
    } else {
      // text — check if submitted contains key words from the correct answer
      const keywords = correct_a.split(/\s+/).filter(w => w.length > 4);
      const matchCount = keywords.filter(k => submitted.includes(k)).length;
      correct = matchCount >= Math.ceil(keywords.length * 0.35);
    }

    const ptsAwarded = correct ? (priorAttempts === 0 ? question.points : Math.floor(question.points * 0.5)) : 0;

    // Record answer
    db.prepare(
      `INSERT INTO answers (user_id, lab_id, question_id, submitted_answer, correct, pts_awarded, attempts)
       VALUES (?,?,?,?,?,?,?)`
    ).run(user.id, lab.id, question_id, answer, correct ? 1 : 0, ptsAwarded, priorAttempts + 1);

    // Update / create progress row
    const totalQ = db.prepare(`SELECT COUNT(*) as c FROM questions WHERE lab_id=?`).get(lab.id).c;
    const doneQ  = db.prepare(
      `SELECT COUNT(DISTINCT question_id) as c FROM answers WHERE user_id=? AND lab_id=? AND correct=1`
    ).get(user.id, lab.id).c;
    const labScore = db.prepare(
      `SELECT COALESCE(SUM(pts_awarded),0) as s FROM answers WHERE user_id=? AND lab_id=? AND correct=1`
    ).get(user.id, lab.id).s;
    const newStatus = doneQ >= totalQ ? 'completed' : 'in_progress';
    const existing  = db.prepare(`SELECT id FROM progress WHERE user_id=? AND lab_id=?`).get(user.id, lab.id);
    if (existing) {
      db.prepare(
        `UPDATE progress SET status=?, score=?, attempts=attempts+1, completed_at=?
         WHERE user_id=? AND lab_id=?`
      ).run(newStatus, labScore, newStatus === 'completed' ? new Date().toISOString() : null, user.id, lab.id);
    } else {
      db.prepare(
        `INSERT INTO progress (user_id, lab_id, status, score, attempts, started_at, completed_at)
         VALUES (?,?,?,?,1,?,?)`
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

  // ── POST /api/user/password (self-service, any authenticated user) ──
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
         COALESCE(SUM(CASE WHEN a.correct=1 THEN a.pts_awarded ELSE 0 END),0) as score,
         COUNT(DISTINCT CASE WHEN a.correct=1 THEN a.question_id END) as correct_answers,
         COUNT(DISTINCT CASE WHEN p.status='completed' THEN p.lab_id END) as labs_done,
         COUNT(DISTINCT a.question_id) as total_answers
       FROM users u
       LEFT JOIN answers a ON a.user_id = u.id
       LEFT JOIN progress p ON p.user_id = u.id
       WHERE u.role='analyst' AND u.active=1
       GROUP BY u.id ORDER BY score DESC LIMIT 50`
    ).all();
    const board = rows.map((r, i) => ({
      rank: i + 1,
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

  // ── GET /api/admin/stats ──────────────────────────────
  if (method === 'GET' && url === '/api/admin/stats') {
    const admin = requireAdmin(req, res); if (!admin) return;
    const total_users   = db.prepare(`SELECT COUNT(*) as c FROM users WHERE role='analyst'`).get().c;
    const active_users  = db.prepare(`SELECT COUNT(*) as c FROM users WHERE role='analyst' AND active=1`).get().c;
    const labs_completed = db.prepare(`SELECT COUNT(*) as c FROM progress WHERE status='completed'`).get().c;
    const total_labs    = db.prepare(`SELECT COUNT(*) as c FROM labs WHERE active=1`).get().c;
    const avg_score_row = db.prepare(
      `SELECT COALESCE(AVG(s),0) as avg FROM (SELECT SUM(pts_awarded) as s FROM answers WHERE correct=1 GROUP BY user_id)`
    ).get();
    const total_answers = db.prepare(`SELECT COUNT(*) as c FROM answers`).get().c;
    return jsonRes(res, 200, {
      total_users, active_users, labs_completed, total_labs,
      avg_score: Math.round(avg_score_row.avg),
      total_answers,
    });
  }

  // ── GET /api/admin/users ──────────────────────────────
  if (method === 'GET' && url === '/api/admin/users') {
    const admin = requireAdmin(req, res); if (!admin) return;
    const users = db.prepare(
      `SELECT u.id, u.username, u.role, u.active, u.created_at,
         COALESCE(SUM(CASE WHEN a.correct=1 THEN a.pts_awarded ELSE 0 END),0) as score,
         COUNT(DISTINCT CASE WHEN p.status='completed' THEN p.lab_id END) as labs_done,
         MAX(s.expires_at) as last_session
       FROM users u
       LEFT JOIN answers a ON a.user_id = u.id
       LEFT JOIN progress p ON p.user_id = u.id
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
      db.prepare(`UPDATE users SET active=? WHERE id=?`).run(body.active ? 1 : 0, userId);
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
    const labs  = db.prepare(`SELECT id, slug, title, points FROM labs WHERE active=1 ORDER BY order_num`).all();
    const allProgress = db.prepare(`SELECT user_id, lab_id, status, score, completed_at FROM progress`).all();
    const matrix = users.map(u => {
      const row = { user_id: u.id, username: u.username, labs: {} };
      labs.forEach(l => {
        const p = allProgress.find(x => x.user_id === u.id && x.lab_id === l.id);
        row.labs[l.slug] = p ? { status: p.status, score: p.score, completed_at: p.completed_at } : { status: 'not_started', score: 0 };
      });
      row.total_score = Object.values(row.labs).reduce((s, l) => s + l.score, 0);
      return row;
    });
    return jsonRes(res, 200, { users: matrix, labs });
  }

  // ── Static files & HTML routes ────────────────────────
  if (method === 'GET') {
    // Route: / → login
    if (url === '/' || url === '/login' || url === '/login.html') {
      return serveFile(res, path.join(PUBLIC, 'login.html'));
    }
    // Route: /analyst → analyst app
    if (url === '/analyst' || url === '/analyst/') {
      return serveFile(res, path.join(PUBLIC, 'analyst', 'index.html'));
    }
    // Route: /admin → admin app
    if (url === '/admin' || url === '/admin/') {
      return serveFile(res, path.join(PUBLIC, 'admin', 'index.html'));
    }
    // Static assets
    const filePath = path.join(PUBLIC, url);
    if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      return serveFile(res, filePath);
    }
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
