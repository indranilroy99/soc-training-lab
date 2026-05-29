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

test('disallowed preflight origin is rejected', async () => {
  const res = await api('/api/me', {
    method: 'OPTIONS',
    headers: {
      Origin: 'https://evil.example',
      'Access-Control-Request-Method': 'GET'
    }
  });
  assert.equal(res.status, 403);
});
