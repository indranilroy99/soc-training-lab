'use strict';

// ── Application server ────────────────────────────────────────────────────
// Wires together: middleware chain → router → global error handler.
// Thin layer — all logic lives in routes/ and middleware/.

const http = require('http');
const cfg  = require('./config');
const { router }        = require('./routes/index');
const { securityHeaders, cors, requestId } = require('./middleware/security');
const { requestLogger, logError }          = require('./middleware/logger');
const { jsonRes }                          = require('./middleware/response');
const { startSessionCleanup }              = require('./db');
const { seedAchievements }                 = require('./services/achievements');
const { seedLearningPaths }                = require('./services/paths');

// ── Middleware chain ──────────────────────────────────────────────────────
// Each middleware calls next() to pass to the next layer.
// If a middleware sends a response it does NOT call next().
function applyMiddleware(req, res, middlewares, final) {
  let i = 0;
  function next() {
    if (i >= middlewares.length) return final(req, res);
    middlewares[i++](req, res, next);
  }
  next();
}

// ── Request handler ───────────────────────────────────────────────────────
async function handleRequest(req, res) {
  await new Promise(resolve => {
    applyMiddleware(req, res, [
      requestId,        // attach X-Request-ID
      securityHeaders,  // 8 security headers on every response
      cors,             // CORS — LAN + localhost only
      requestLogger,    // log method + path + status + duration + user
    ], resolve);
  });

  try {
    await router(req, res);
  } catch (err) {
    logError(err, req);
    if (!res.headersSent) {
      // OWASP A05 — never expose internal error details, table names, or stack traces
      // Log the real error server-side; send only a generic message to the client
      jsonRes(res, err.status || 500, { ok: false, error: 'Something went wrong. Please try again.' });
    }
  }
}

// ── HTTP server ───────────────────────────────────────────────────────────
const server = http.createServer(handleRequest);

// ── Graceful shutdown ─────────────────────────────────────────────────────
// On SIGTERM (systemd stop / launchd unload): finish in-flight requests,
// then close the DB connection cleanly. Prevents DB corruption.
let cleanupTimer;

function shutdown(signal) {
  console.log(`[app] ${signal} received — shutting down gracefully`);
  clearInterval(cleanupTimer);
  server.close(() => {
    console.log('[app] HTTP server closed');
    try {
      const { db } = require('./db');
      db.close();
      console.log('[app] Database connection closed');
    } catch {}
    process.exit(0);
  });
  // Force exit after 10 seconds if graceful shutdown stalls
  setTimeout(() => {
    console.error('[app] Forced shutdown after timeout');
    process.exit(1);
  }, 10_000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));

// ── Unhandled error safety nets ───────────────────────────────────────────
process.on('uncaughtException', err => {
  logError(err);
  console.error('[app] Uncaught exception — process will continue but investigate this');
});

process.on('unhandledRejection', (reason) => {
  console.error('[app] Unhandled promise rejection:', reason);
});

// ── Start ─────────────────────────────────────────────────────────────────
function startServer(port = cfg.PORT, host = cfg.HOST) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.once('listening', () => {
      server.off('error', reject);
      cleanupTimer = startSessionCleanup();
      // Seed reference data only in primary/standalone mode — workers skip this
      // to avoid concurrent INSERTs on startup (INSERT OR IGNORE handles conflicts
      // but unnecessary DB contention at startup is avoided)
      const cl = require('cluster');
      if (!cl.isWorker) {
        seedAchievements();
        seedLearningPaths();
      }
      resolve(server);
    });
    server.listen(port, host);
  });
}

function stopServer() {
  return new Promise((resolve, reject) => {
    if (!server.listening) return resolve();
    server.close(err => err ? reject(err) : resolve());
  });
}

module.exports = { server, startServer, stopServer };
