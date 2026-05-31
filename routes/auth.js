'use strict';

const crypto   = require('crypto');
const bcrypt   = require('bcryptjs');
const cfg      = require('../config');
const { db }   = require('../db');
const { ok, badRequest, unauthorized, jsonRes } = require('../middleware/response');
const { parseBody }  = require('../middleware/security');
const { isLoginThrottled, recordLoginFailure, clearLoginFailures, getClientIp } = require('../middleware/rateLimit');
const { validateCredentials } = require('../middleware/validate');
const { logger }     = require('../middleware/logger');
const { award }      = require('../services/achievements');

// POST /api/auth/login
async function login(req, res) {
  const body = await parseBody(req);
  const { username, password } = body;

  const validationError = validateCredentials({ username, password });
  if (validationError) return badRequest(res, validationError);

  const ip = getClientIp(req);
  if (isLoginThrottled(username, ip)) {
    return jsonRes(res, 429, { ok: false, error: 'Too many failed attempts. Try again in 15 minutes.' });
  }

  const user = db.prepare(
    `SELECT id, username, role, password_hash, is_active, force_pw_change FROM users WHERE username=? AND is_active=1`
  ).get(username.trim());

  // Use constant-time comparison to prevent timing attacks even on missing user
  const dummyHash = '$2a$10$nothingdummyhashtopreventtiming';
  const hashToCheck = user?.password_hash || dummyHash;
  const passwordMatch = bcrypt.compareSync(password, hashToCheck);

  if (!user || !passwordMatch) {
    recordLoginFailure(username, ip);
    logger.warn('login_failed', { username: username.trim(), ip, reqId: req.id });
    return unauthorized(res, 'Invalid username or password');
  }

  clearLoginFailures(username, ip);

  const token   = crypto.randomBytes(cfg.SESSION_BYTES).toString('hex');
  const expires = new Date(Date.now() + cfg.SESSION_TTL_HOURS * 3_600_000).toISOString();
  // Single-session enforcement: invalidate all previous sessions for this user
  db.prepare(`DELETE FROM sessions WHERE user_id=?`).run(user.id);
  // Attempt INSERT with optional tracking columns, fall back to base schema if needed
  try {
    db.prepare(`INSERT INTO sessions (user_id, token, expires_at, created_at, last_seen_at) VALUES (?,?,?,?,?)`)
      .run(user.id, token, expires, new Date().toISOString(), new Date().toISOString());
  } catch {
    db.prepare(`INSERT INTO sessions (user_id, token, expires_at) VALUES (?,?,?)`)
      .run(user.id, token, expires);
  }

  logger.info('login_success', { userId: user.id, username: user.username, ip, reqId: req.id });
  // Award first-login achievement (ignored if already earned)
  try { award(user.id, 'first_login'); } catch {}
  return ok(res, { token, user: { id: user.id, username: user.username, role: user.role, force_pw_change: !!user.force_pw_change } });
}

// POST /api/auth/logout
async function logout(req, res) {
  const auth  = (req.headers['authorization'] || '').trim();
  const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
  if (token) db.prepare(`DELETE FROM sessions WHERE token=?`).run(token);
  return ok(res, { message: 'Logged out successfully' });
}

module.exports = { login, logout };
