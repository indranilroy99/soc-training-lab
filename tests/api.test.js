'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const bcrypt = require('bcryptjs');

const repoRoot = path.join(__dirname, '..');
const dbPath = path.join(repoRoot, 'database', 'diaas.db');
const dbBackupPath = path.join(repoRoot, 'database', 'diaas.db.pre-test-backup');

let server;
let baseUrl;
let cleanupTimer;
let db;
let loginAttempts;

async function api(pathname, { method = 'GET', token, body, headers = {} } = {}) {
  const res = await fetch(baseUrl + pathname, {
    method,
    headers: {
      ...(body ? { 'Content-Type': 'application/json' } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...headers,
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = null;
  const text = await res.text();
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  return { status: res.status, data, headers: res.headers };
}

async function login(username, password) {
  const res = await api('/api/auth/login', { method: 'POST', body: { username, password } });
  assert.equal(res.status, 200, `login failed for ${username}: ${JSON.stringify(res.data)}`);
  assert.ok(res.data.token, 'missing token');
  return res.data.token;
}

test.before(async () => {
  if (fs.existsSync(dbBackupPath)) fs.unlinkSync(dbBackupPath);
  if (fs.existsSync(dbPath)) fs.copyFileSync(dbPath, dbBackupPath);
  if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath);

  execFileSync(process.execPath, ['database/seed.js'], { cwd: repoRoot, stdio: 'inherit' });

  ({ startServer: global.startServer, stopServer: global.stopServer, db, loginAttempts, sessionCleanupTimer: cleanupTimer } = require('../server'));
  loginAttempts.clear();
  server = await global.startServer(0, '127.0.0.1');
  const { port } = server.address();
  baseUrl = `http://127.0.0.1:${port}`;
});

test.after(async () => {
  if (cleanupTimer) clearInterval(cleanupTimer);
  if (global.stopServer) await global.stopServer();
  if (db && db.open) db.close();
  if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath);
  if (fs.existsSync(dbBackupPath)) {
    fs.copyFileSync(dbBackupPath, dbPath);
    fs.unlinkSync(dbBackupPath);
  }
});

test('login returns token and api/me returns analyst profile', async () => {
  const token = await login('analyst_01', 'Analyst@2024');
  const me = await api('/api/me', { token });
  assert.equal(me.status, 200);
  assert.equal(me.data.username, 'analyst_01');
  assert.equal(me.data.role, 'analyst');
  assert.equal(typeof me.data.score, 'number');
});

test('password change invalidates old session and allows login with new password', async () => {
  const token = await login('analyst_02', 'Analyst@2024');
  const change = await api('/api/user/password', {
    method: 'POST',
    token,
    body: { current_password: 'Analyst@2024', new_password: 'Analyst@2024#New' }
  });
  assert.equal(change.status, 200);

  const oldSession = await api('/api/me', { token });
  assert.equal(oldSession.status, 401);

  const oldLogin = await api('/api/auth/login', { method: 'POST', body: { username: 'analyst_02', password: 'Analyst@2024' } });
  assert.equal(oldLogin.status, 401);

  const newToken = await login('analyst_02', 'Analyst@2024#New');
  const me = await api('/api/me', { token: newToken });
  assert.equal(me.status, 200);

  db.prepare('UPDATE users SET password_hash = ? WHERE username = ?').run(bcrypt.hashSync('Analyst@2024', 10), 'analyst_02');
  db.prepare('DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE username = ?)').run('analyst_02');
});

test('leaderboard score includes alert closure points', async () => {
  const token = await login('analyst_03', 'Analyst@2024');
  const user = db.prepare('SELECT id FROM users WHERE username = ?').get('analyst_03');
  assert.ok(user);

  db.prepare('DELETE FROM alert_closures WHERE user_id = ? AND alert_id = ?').run(user.id, 'ALT-001');
  db.prepare('INSERT INTO alert_closures (alert_id, user_id, classification, fp_reason, triage_reason, containment_steps, eradication_steps, recovery_steps, rca_notes, is_correct, points_awarded, investigation_score, closed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)')
    .run('ALT-001', user.id, 'false_positive', 'Test justification', null, null, null, null, null, 1, 15, 100, new Date().toISOString());

  const board = await api('/api/leaderboard', { token });
  assert.equal(board.status, 200);
  const row = board.data.find(r => r.username === 'analyst_03');
  assert.ok(row, 'leaderboard row missing');
  assert.ok(row.score >= 15, `expected closure points in score, got ${row.score}`);

  db.prepare('DELETE FROM alert_closures WHERE user_id = ? AND alert_id = ?').run(user.id, 'ALT-001');
});

test('alert state is isolated per analyst', async () => {
  const tokenA = await login('analyst_04', 'Analyst@2024');
  const tokenB = await login('analyst_05', 'Analyst@2024');

  db.prepare('DELETE FROM user_alert_state WHERE alert_id = ? AND user_id IN ((SELECT id FROM users WHERE username = ?), (SELECT id FROM users WHERE username = ?))')
    .run('ALT-002', 'analyst_04', 'analyst_05');

  const resA = await api('/api/alerts/ALT-002/status', {
    method: 'POST',
    token: tokenA,
    body: { status: 'false_positive', fp_reason: 'Benign lab test traffic' }
  });
  assert.equal(resA.status, 200, JSON.stringify(resA.data));

  const alertA = await api('/api/alerts/ALT-002', { token: tokenA });
  const alertB = await api('/api/alerts/ALT-002', { token: tokenB });
  assert.equal(alertA.status, 200);
  assert.equal(alertB.status, 200);
  assert.equal(alertA.data.status, 'false_positive');
  assert.equal(alertB.data.status, 'open');

  db.prepare('DELETE FROM user_alert_state WHERE alert_id = ? AND user_id IN ((SELECT id FROM users WHERE username = ?), (SELECT id FROM users WHERE username = ?))')
    .run('ALT-002', 'analyst_04', 'analyst_05');
});

test('admin can create a lab with evidence and progressive hint questions in one request', async () => {
  const adminToken = await login('admin', 'Admin@2024');
  const uniqueTitle = `Regression Lab ${Date.now()}`;
  const create = await api('/api/admin/labs', {
    method: 'POST',
    token: adminToken,
    body: {
      title: uniqueTitle,
      description: 'Integrated admin lab builder regression test',
      difficulty: 'medium',
      category: 'Additional Labs',
      points: 120,
      alert_refs: ['ALT-003'],
      evidence: [
        { type: 'log', title: 'Proxy Log', content: 'GET /update/check from 203.0.113.101' },
        { type: 'note', title: 'Analyst Note', content: 'Investigate python-requests beaconing.' }
      ],
      questions: [
        {
          question: 'Which external IP is beaconing?',
          answer_type: 'text',
          correct_answer: '45.33.32.156',
          hint: 'Start with the linked alert evidence.',
          hint_levels: ['Review the outbound HTTP destination IP in the log.', 'The answer starts with 45.'],
          explanation: 'Beacon destination identified from HTTP log.',
          points: 30,
          difficulty: 'medium',
          alert_ref: 'ALT-003'
        }
      ],
      is_visible: true
    }
  });

  assert.equal(create.status, 201, JSON.stringify(create.data));
  assert.ok(create.data.id);
  assert.ok(create.data.slug);

  const adminLabs = await api('/api/admin/labs', { token: adminToken });
  assert.equal(adminLabs.status, 200);
  const createdLab = adminLabs.data.find(l => l.id === create.data.id);
  assert.ok(createdLab, 'created lab missing from admin list');
  assert.equal(createdLab.category, 'Additional Labs');
  assert.deepEqual(createdLab.alert_refs, ['ALT-003']);
  assert.equal(createdLab.evidence.length, 2);

  const createdQuestions = await api(`/api/admin/labs/${create.data.id}/questions`, { token: adminToken });
  assert.equal(createdQuestions.status, 200);
  assert.equal(createdQuestions.data.length, 1);
  assert.deepEqual(createdQuestions.data[0].hint_levels, ['Review the outbound HTTP destination IP in the log.', 'The answer starts with 45.']);
  assert.equal(createdQuestions.data[0].alert_ref, 'ALT-003');

  const cleanupCreatedLab = db.transaction((labId) => {
    db.prepare('DELETE FROM user_answers WHERE lab_id = ?').run(labId);
    db.prepare('DELETE FROM user_progress WHERE lab_id = ?').run(labId);
    db.prepare('DELETE FROM questions WHERE lab_id = ?').run(labId);
    db.prepare('DELETE FROM labs WHERE id = ?').run(labId);
  });
  cleanupCreatedLab(create.data.id);
});

test('guided hints reduce points progressively without revealing the full answer', async () => {
  const token = await login('analyst_06', 'Analyst@2024');
  const labRow = db.prepare(`SELECT l.slug, q.id AS question_id, q.points, q.correct_answer
    FROM labs l
    JOIN questions q ON q.lab_id = l.id
    WHERE q.hint_levels IS NOT NULL AND q.hint_levels != '[]' AND q.correct_answer IS NOT NULL
    ORDER BY l.id ASC, q.order_index ASC
    LIMIT 1`).get();
  assert.ok(labRow, 'expected seeded question with hint levels');

  db.prepare('DELETE FROM user_answers WHERE user_id = (SELECT id FROM users WHERE username = ?) AND question_id = ?').run('analyst_06', labRow.question_id);
  db.prepare('DELETE FROM user_progress WHERE user_id = (SELECT id FROM users WHERE username = ?) AND lab_id = (SELECT id FROM labs WHERE slug = ?)').run('analyst_06', labRow.slug);

  const detail = await api(`/api/labs/${labRow.slug}`, { token });
  assert.equal(detail.status, 200);
  const question = detail.data.questions.find(q => q.id === labRow.question_id);
  assert.ok(question, 'question missing from lab detail');
  assert.ok(Array.isArray(question.hint_plan));
  assert.ok(question.hint_plan.length >= 2, 'need progressive hints');

  const hint1 = await api(`/api/labs/${labRow.slug}/hint`, {
    method: 'POST',
    token,
    body: { question_id: labRow.question_id }
  });
  assert.equal(hint1.status, 200, JSON.stringify(hint1.data));
  assert.equal(hint1.data.hint_level, 1);
  assert.ok(hint1.data.remaining_points < labRow.points);
  assert.notEqual(hint1.data.hint, labRow.correct_answer);

  const hint2 = await api(`/api/labs/${labRow.slug}/hint`, {
    method: 'POST',
    token,
    body: { question_id: labRow.question_id }
  });
  assert.equal(hint2.status, 200, JSON.stringify(hint2.data));
  assert.equal(hint2.data.hint_level, 2);
  assert.ok(hint2.data.remaining_points <= hint1.data.remaining_points);
  assert.notEqual(hint2.data.hint, labRow.correct_answer);

  const correct = await api(`/api/labs/${labRow.slug}/submit`, {
    method: 'POST',
    token,
    body: { question_id: labRow.question_id, answer: labRow.correct_answer }
  });
  assert.equal(correct.status, 200, JSON.stringify(correct.data));
  assert.equal(correct.data.correct, true);
  assert.equal(correct.data.hints_used, 2);
  assert.equal(correct.data.pts, hint2.data.remaining_points);

  const repeatHint = await api(`/api/labs/${labRow.slug}/hint`, {
    method: 'POST',
    token,
    body: { question_id: labRow.question_id }
  });
  assert.equal(repeatHint.status, 200);
  assert.equal(repeatHint.data.already_completed, true);

  db.prepare('DELETE FROM user_answers WHERE user_id = (SELECT id FROM users WHERE username = ?) AND question_id = ?').run('analyst_06', labRow.question_id);
  db.prepare('DELETE FROM user_progress WHERE user_id = (SELECT id FROM users WHERE username = ?) AND lab_id = (SELECT id FROM labs WHERE slug = ?)').run('analyst_06', labRow.slug);
});

test('concurrent analyst login and read flows succeed under classroom-sized burst', async () => {
  const users = Array.from({ length: 10 }, (_, i) => `analyst_${String(i + 1).padStart(2, '0')}`);
  const sessions = await Promise.all(users.map(async username => {
    const token = await login(username, 'Analyst@2024');
    const [me, alerts, labs] = await Promise.all([
      api('/api/me', { token }),
      api('/api/alerts?limit=20', { token }),
      api('/api/labs', { token }),
    ]);
    return { username, me, alerts, labs };
  }));

  for (const session of sessions) {
    assert.equal(session.me.status, 200, `${session.username} /api/me failed`);
    assert.equal(session.alerts.status, 200, `${session.username} /api/alerts failed`);
    assert.equal(session.labs.status, 200, `${session.username} /api/labs failed`);
    assert.ok(Array.isArray(session.alerts.data.alerts), `${session.username} alerts payload invalid`);
    assert.ok(Array.isArray(session.labs.data), `${session.username} labs payload invalid`);
  }
});
