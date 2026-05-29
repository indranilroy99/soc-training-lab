'use strict';

// ── All application configuration in one file ─────────────────────────────
// Change environment behaviour here, not scattered through the codebase.

const path = require('path');

const isProd = process.env.NODE_ENV === 'production';

module.exports = {
  // ── Server ───────────────────────────────────────────────────────────────
  PORT:    parseInt(process.env.PORT || '3000', 10),
  HOST:    process.env.HOST || '0.0.0.0',
  IS_PROD: isProd,

  // ── Paths ────────────────────────────────────────────────────────────────
  DB_PATH: process.env.DB_PATH || path.join(__dirname, 'database', 'diaas.db'),
  PUBLIC:  path.join(__dirname, 'public'),

  // ── Auth & Sessions ───────────────────────────────────────────────────────
  SESSION_TTL_HOURS:         24,
  SESSION_TOUCH_INTERVAL_MS: 30 * 60 * 1000,
  SESSION_BYTES:             48,            // token entropy bytes

  // ── Login rate limiting ───────────────────────────────────────────────────
  LOGIN_WINDOW_MS:   15 * 60 * 1000,        // 15-minute window
  LOGIN_MAX_ATTEMPTS: 10,                    // max attempts before lockout

  // ── API rate limiting (requests per window per IP) ────────────────────────
  API_RATE_WINDOW_MS: 60 * 1000,            // 1-minute window
  API_RATE_MAX:       300,                  // 300 req/min per IP (fine for classroom)
  SUBMIT_RATE_MAX:    30,                   // 30 submits/min per IP

  // ── Leaderboard cache ─────────────────────────────────────────────────────
  LB_CACHE_TTL_MS: 10 * 1000,              // 10 seconds

  // ── Cluster ───────────────────────────────────────────────────────────────
  CLUSTER_MIN_WORKERS: 2,
  CLUSTER_MAX_WORKERS: 6,

  // ── Input validation limits ───────────────────────────────────────────────
  MAX_USERNAME_LEN:  64,
  MIN_PASSWORD_LEN:  8,
  MAX_PASSWORD_LEN:  128,
  MAX_BODY_BYTES:    1_000_000,             // 1MB max request body

  // ── Security headers ─────────────────────────────────────────────────────
  // These are applied to EVERY response via middleware/security.js
  SECURITY_HEADERS: {
    'X-Content-Type-Options':  'nosniff',
    'X-Frame-Options':         'DENY',
    'X-XSS-Protection':        '1; mode=block',
    'Referrer-Policy':         'strict-origin-when-cross-origin',
    'Permissions-Policy':      'camera=(), microphone=(), geolocation=(), payment=()',
    // CSP: allow same-origin scripts/styles, Google Fonts, inline styles (needed for current HTML)
    'Content-Security-Policy':
      "default-src 'self'; " +
      "script-src 'self' 'unsafe-inline'; " +
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
      "font-src https://fonts.gstatic.com; " +
      "img-src 'self' data:; " +
      "connect-src 'self'; " +
      "object-src 'none'; " +
      "base-uri 'self'; " +
      "form-action 'self'",
  },

  // API responses must never be cached by the browser
  API_CACHE_HEADER: 'no-store, no-cache, must-revalidate',
};
