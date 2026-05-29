'use strict';

// ── Security middleware ────────────────────────────────────────────────────
// Applied to EVERY request before routing.
// Current state was zero security headers — this adds comprehensive coverage.

const cfg = require('../config');

// ── Security headers ──────────────────────────────────────────────────────
// Applied to all responses regardless of route.
function securityHeaders(req, res, next) {
  for (const [k, v] of Object.entries(cfg.SECURITY_HEADERS)) {
    res.setHeader(k, v);
  }
  // API routes: never cache responses
  if (req.url.startsWith('/api/')) {
    res.setHeader('Cache-Control', cfg.API_CACHE_HEADER);
    res.setHeader('Pragma', 'no-cache');
  }
  next();
}

// ── CORS ──────────────────────────────────────────────────────────────────
// Local network deployment: only allow same-origin and localhost.
// If you deploy behind a domain, add it to ALLOWED_ORIGINS in config.
const ALLOWED_ORIGINS = new Set([
  '',                      // same-origin (no Origin header)
  'null',                  // file:// or opaque origins
]);
const LOCALHOST_RE = /^https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0)(:\d+)?$/i;
// Also allow any private network IP (RFC1918) for LAN classroom use
const PRIVATE_IP_RE = /^https?:\/\/(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)(:\d+)?$/i;

function cors(req, res, next) {
  const origin = req.headers.origin || '';
  const allowed =
    ALLOWED_ORIGINS.has(origin) ||
    LOCALHOST_RE.test(origin) ||
    PRIVATE_IP_RE.test(origin);

  if (req.method === 'OPTIONS') {
    if (!allowed) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'Origin not allowed' }));
      return;
    }
    res.writeHead(204, {
      'Access-Control-Allow-Origin':  origin || '*',
      'Access-Control-Allow-Headers': 'Authorization, Content-Type, X-Request-ID',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Max-Age':       '86400',
      'Vary': 'Origin',
    });
    res.end();
    return;
  }

  if (allowed && origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  next();
}

// ── Request body size limit ───────────────────────────────────────────────
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    let bytes = 0;
    req.on('data', chunk => {
      bytes += chunk.length;
      if (bytes > cfg.MAX_BODY_BYTES) {
        req.destroy(Object.assign(new Error('Request body too large'), { code: 'BODY_TOO_LARGE', status: 413 }));
        return;
      }
      body += chunk;
    });
    req.on('end', () => {
      if (!body) return resolve({});
      try { resolve(JSON.parse(body)); }
      catch { resolve({}); }
    });
    req.on('error', reject);
  });
}

// ── Request ID ────────────────────────────────────────────────────────────
// Attach a unique ID to each request for log correlation.
const { randomBytes } = require('crypto');
function requestId(req, res, next) {
  req.id = req.headers['x-request-id'] || randomBytes(8).toString('hex');
  res.setHeader('X-Request-ID', req.id);
  next();
}

module.exports = { securityHeaders, cors, parseBody, requestId };
