'use strict';

// ── Rate limiting middleware ───────────────────────────────────────────────
// Per-IP sliding window counters stored in memory.
// Applies globally to all API routes, plus a tighter limit on auth and submit.
//
// NOTE: In a multi-process cluster each worker has its own counter map.
// This means the effective limit is LIMIT × WORKERS across the cluster.
// For a 60-student classroom this is intentional — legitimate students
// should never hit the limit. The purpose is to prevent a single bad actor
// from flooding the server, not to enforce a strict global cap.

const cfg = require('../config');
const { jsonRes } = require('./response');

function getClientIp(req) {
  // Do NOT trust X-Forwarded-For — it's trivially spoofable without a verified proxy.
  // In a classroom LAN environment, use the direct socket IP for rate limiting.
  // If you deploy behind nginx/haproxy, configure it to set X-Real-IP and verify
  // the TRUSTED_PROXY env var before using forwarded headers.
  const TRUSTED_PROXY = process.env.TRUSTED_PROXY;
  if (TRUSTED_PROXY && req.socket?.remoteAddress === TRUSTED_PROXY) {
    const forwarded = req.headers['x-real-ip'] || req.headers['x-forwarded-for'];
    if (forwarded) return forwarded.split(',')[0].trim();
  }
  return req.socket?.remoteAddress || 'unknown';
}

// ── Generic rate limiter factory ──────────────────────────────────────────
function createLimiter({ windowMs, max, message }) {
  const hits = new Map();

  // Clean up old entries every window to prevent memory leak
  setInterval(() => {
    const cutoff = Date.now() - windowMs;
    for (const [key, entry] of hits) {
      if (entry.firstHit < cutoff) hits.delete(key);
    }
  }, windowMs).unref();

  return function rateLimit(req, res, next) {
    const key  = getClientIp(req);
    const now  = Date.now();
    const entry = hits.get(key);

    if (!entry || (now - entry.firstHit) > windowMs) {
      hits.set(key, { count: 1, firstHit: now });
      return next();
    }

    entry.count += 1;
    if (entry.count > max) {
      const retryAfter = Math.ceil((windowMs - (now - entry.firstHit)) / 1000);
      res.setHeader('Retry-After', retryAfter);
      jsonRes(res, 429, { ok: false, error: message || 'Too many requests. Please wait a moment.' });
      return;
    }
    next();
  };
}

// ── Login-specific throttle ───────────────────────────────────────────────
// Keyed on username+IP to prevent targeted account brute force.
const loginAttempts = new Map();

function isLoginThrottled(username, ip) {
  const key   = `${String(username || '').toLowerCase()}|${ip}`;
  const entry = loginAttempts.get(key);
  if (!entry) return false;
  if ((Date.now() - entry.firstTs) > cfg.LOGIN_WINDOW_MS) {
    loginAttempts.delete(key);
    return false;
  }
  return entry.count >= cfg.LOGIN_MAX_ATTEMPTS;
}

function recordLoginFailure(username, ip) {
  const key   = `${String(username || '').toLowerCase()}|${ip}`;
  const now   = Date.now();
  const entry = loginAttempts.get(key);
  if (!entry || (now - entry.firstTs) > cfg.LOGIN_WINDOW_MS) {
    loginAttempts.set(key, { count: 1, firstTs: now });
  } else {
    entry.count += 1;
  }
}

function clearLoginFailures(username, ip) {
  loginAttempts.delete(`${String(username || '').toLowerCase()}|${ip}`);
}

// ── Pre-built limiters ────────────────────────────────────────────────────
const apiLimiter = createLimiter({
  windowMs: cfg.API_RATE_WINDOW_MS,
  max:      cfg.API_RATE_MAX,
  message:  'Too many requests. Please slow down.',
});

const submitLimiter = createLimiter({
  windowMs: cfg.API_RATE_WINDOW_MS,
  max:      cfg.SUBMIT_RATE_MAX,
  message:  'Too many answer submissions. Please wait a moment before continuing.',
});

// Tight rate limiter for sensitive auth operations (password change, etc.)
const authActionLimiter = createLimiter({
  windowMs: 15 * 60 * 1000,  // 15-minute window
  max:      10,               // max 10 attempts per 15 min per IP
  message:  'Too many authentication attempts. Please wait 15 minutes.',
});

module.exports = {
  apiLimiter,
  submitLimiter,
  authActionLimiter,
  isLoginThrottled,
  recordLoginFailure,
  clearLoginFailures,
  getClientIp,
};
