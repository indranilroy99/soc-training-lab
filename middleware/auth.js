'use strict';

// ── Authentication middleware ──────────────────────────────────────────────
// requireAuth and requireAdmin used by every protected route.

const cfg    = require('../config');
const { db } = require('../db');
const { jsonRes } = require('./response');

const SESSION_TTL_MS       = cfg.SESSION_TTL_HOURS * 3_600_000;
const TOUCH_INTERVAL_MS    = cfg.SESSION_TOUCH_INTERVAL_MS;

// ── requireAuth ───────────────────────────────────────────────────────────
// Returns the authenticated user object, or sends 401 and returns null.
function requireAuth(req, res) {
  const auth  = (req.headers['authorization'] || '').trim();
  const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';

  if (!token) {
    jsonRes(res, 401, { ok: false, error: 'Authentication required' });
    return null;
  }

  const now = new Date().toISOString();
  const row = db.prepare(
    `SELECT u.id, u.username, u.role, u.is_active,
            s.expires_at, s.token
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.token = ? AND s.expires_at > ? AND u.is_active = 1`
  ).get(token, now);

  if (!row) {
    jsonRes(res, 401, { ok: false, error: 'Session expired or invalid. Please log in again.' });
    return null;
  }

  // Slide the session expiry window if it's getting close
  const expiresTs = Date.parse(row.expires_at || '');
  if (!isNaN(expiresTs) && (expiresTs - Date.now()) < TOUCH_INTERVAL_MS) {
    const nextExpiry = new Date(Date.now() + SESSION_TTL_MS).toISOString();
    db.prepare(`UPDATE sessions SET expires_at=? WHERE token=?`).run(nextExpiry, token);
  }

  // Attach user ID to request for logging
  req._userId = row.id;
  return row;
}

// ── requireAdmin ──────────────────────────────────────────────────────────
function requireAdmin(req, res) {
  const user = requireAuth(req, res);
  if (!user) return null;
  if (user.role !== 'admin') {
    jsonRes(res, 403, { ok: false, error: 'Admin access required' });
    return null;
  }
  return user;
}

module.exports = { requireAuth, requireAdmin };
