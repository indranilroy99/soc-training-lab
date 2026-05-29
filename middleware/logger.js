'use strict';

// ── Structured logger ─────────────────────────────────────────────────────
// Replaces scattered console.log/error calls with consistent structured logs.
// Format: JSON lines — easy to grep, pipe to log aggregators, or read raw.

const cfg = require('../config');

function timestamp() {
  return new Date().toISOString();
}

function log(level, event, data = {}) {
  const entry = {
    ts:    timestamp(),
    level,
    event,
    pid:   process.pid,
    ...data,
  };
  // In production you'd pipe this to a file or log aggregator.
  // For classroom use, stdout is fine — pipe to >> logs/server.log
  console.log(JSON.stringify(entry));
}

const logger = {
  info:  (event, data) => log('INFO',  event, data),
  warn:  (event, data) => log('WARN',  event, data),
  error: (event, data) => log('ERROR', event, data),
  debug: (event, data) => { if (!cfg.IS_PROD) log('DEBUG', event, data); },
};

// ── Request logging middleware ────────────────────────────────────────────
// Logs every request on completion with method, path, status, duration, user.
function requestLogger(req, res, next) {
  const start = Date.now();
  // Patch res.writeHead to capture the status code
  const origWriteHead = res.writeHead.bind(res);
  res.writeHead = function (statusCode, ...args) {
    res._statusCode = statusCode;
    return origWriteHead(statusCode, ...args);
  };
  res.on('finish', () => {
    const ms = Date.now() - start;
    const status = res._statusCode || res.statusCode;
    // Skip noisy health check logs in production
    if (cfg.IS_PROD && req.url === '/health') return;
    logger.info('request', {
      id:     req.id,
      method: req.method,
      path:   req.url.split('?')[0],
      status,
      ms,
      user:   req._userId || null,
      ip:     (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '').split(',')[0].trim(),
    });
  });
  next();
}

// ── Error logger ──────────────────────────────────────────────────────────
function logError(err, req = null) {
  logger.error('unhandled_error', {
    id:      req?.id,
    path:    req?.url,
    message: err.message,
    code:    err.code,
    status:  err.status,
    // Only include stack in development — never in production logs served to users
    stack:   cfg.IS_PROD ? undefined : err.stack,
  });
}

module.exports = { logger, requestLogger, logError };
