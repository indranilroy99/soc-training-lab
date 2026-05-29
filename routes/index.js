'use strict';

// ── Central router ────────────────────────────────────────────────────────
// All URL matching happens here. Each match delegates to a route module.
// Pattern: exact match first, then regex matches in order.

const path   = require('path');
const fs     = require('fs');
const cfg    = require('../config');
const { healthCheck } = require('../db');
const { jsonRes }     = require('../middleware/response');
const { apiLimiter, submitLimiter } = require('../middleware/rateLimit');

// ── Route handlers ────────────────────────────────────────────────────────
const authRoutes   = require('./auth');
const userRoutes   = require('./user');
const labRoutes    = require('./labs');
const alertRoutes  = require('./alerts');
const lbRoutes     = require('./leaderboard');
const adminRoutes  = require('./admin');
const achRoutes    = require('./achievements');
const pathRoutes   = require('./paths');
const noteRoutes   = require('./notes');

// ── MIME types for static files ───────────────────────────────────────────
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.js':   'application/javascript; charset=utf-8',
  '.json': 'application/json',
  '.png':  'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
  '.svg':  'image/svg+xml', '.ico': 'image/x-icon',
  '.woff2':'font/woff2',    '.woff': 'font/woff',
  '.webp': 'image/webp',
};

function serveFile(res, filePath) {
  const resolved  = path.resolve(filePath);
  const publicDir = path.resolve(cfg.PUBLIC);
  // Path traversal guard
  if (!resolved.startsWith(publicDir + path.sep) && resolved !== publicDir) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end('Forbidden');
    return;
  }
  const ext  = path.extname(resolved).toLowerCase();
  const mime = MIME[ext] || 'application/octet-stream';
  fs.readFile(resolved, (err, data) => {
    if (err) { res.writeHead(404, { 'Content-Type': 'text/plain' }); res.end('Not found'); return; }
    const cacheControl = ext === '.html' ? 'no-store' : 'public, max-age=3600';
    res.writeHead(200, { 'Content-Type': mime, 'Cache-Control': cacheControl });
    res.end(data);
  });
}

// ── Main router function ───────────────────────────────────────────────────
async function router(req, res) {
  const rawUrl = req.url || '/';
  const url    = rawUrl.split('?')[0];
  const method = req.method.toUpperCase();

  // ── Health check (no auth, no rate limit) ─────────────────────────────
  if (method === 'GET' && url === '/health') {
    const h = healthCheck();
    return jsonRes(res, h.ok ? 200 : 503, { ok: h.ok, pid: process.pid, ts: new Date().toISOString(), ...(h.error ? { error: h.error } : {}) });
  }

  // ── Apply API rate limiter to all /api/* routes ───────────────────────
  if (url.startsWith('/api/')) {
    let rateLimitDone = false;
    apiLimiter(req, res, () => { rateLimitDone = true; });
    if (!rateLimitDone) return; // rate limiter already responded
  }

  // ── Auth routes ───────────────────────────────────────────────────────
  if (method === 'POST' && url === '/api/auth/login')  return authRoutes.login(req, res);
  if (method === 'POST' && url === '/api/auth/logout') return authRoutes.logout(req, res);

  // ── User routes ───────────────────────────────────────────────────────
  if (method === 'GET'  && url === '/api/me')           return userRoutes.getMe(req, res);
  if (method === 'GET'  && url === '/api/me/closures')  return userRoutes.getMyClosures(req, res);
  if (method === 'POST' && url === '/api/user/password') return userRoutes.changePassword(req, res);

  // ── Leaderboard ───────────────────────────────────────────────────────
  if (method === 'GET'  && url === '/api/leaderboard')  return lbRoutes.getLeaderboard(req, res);

  // ── Achievements & Paths ──────────────────────────────────────────────
  if (method === 'GET'  && url === '/api/achievements') return achRoutes.listAchievements(req, res);
  if (method === 'GET'  && url === '/api/paths')        return pathRoutes.listPaths(req, res);

  // ── Labs ──────────────────────────────────────────────────────────────
  if (method === 'GET'  && url === '/api/labs')         return labRoutes.listLabs(req, res);

  const labMatch = url.match(/^\/api\/labs\/([^/]+)$/);
  if (method === 'GET'  && labMatch)                    return labRoutes.getLab(req, res, labMatch[1]);

  const submitMatch = url.match(/^\/api\/labs\/([^/]+)\/submit$/);
  if (method === 'POST' && submitMatch) {
    // Tighter rate limit on answer submission
    let done = false;
    submitLimiter(req, res, () => { done = true; });
    if (!done) return;
    return labRoutes.submitAnswer(req, res, submitMatch[1]);
  }

  const hintMatch = url.match(/^\/api\/labs\/([^/]+)\/hint$/);
  if (method === 'POST' && hintMatch)                   return labRoutes.requestHint(req, res, hintMatch[1]);

  const resetMatch = url.match(/^\/api\/labs\/([^/]+)\/reset$/);
  if (method === 'POST' && resetMatch)                  return labRoutes.resetLab(req, res, resetMatch[1]);

  const notesMatch = url.match(/^\/api\/labs\/([^/]+)\/notes$/);
  if (method === 'GET' && notesMatch)                   return noteRoutes.getNotes(req, res, notesMatch[1]);
  if (method === 'PUT' && notesMatch)                   return noteRoutes.saveNotes(req, res, notesMatch[1]);

  // ── Alerts ────────────────────────────────────────────────────────────
  if (method === 'GET' && url.startsWith('/api/alerts') && url === '/api/alerts') {
    return alertRoutes.listAlerts(req, res);
  }

  const alertIdMatch = url.match(/^\/api\/alerts\/([A-Z0-9-]+)$/);
  if (method === 'GET'  && alertIdMatch)                return alertRoutes.getAlert(req, res, alertIdMatch[1]);

  const alertStatusMatch = url.match(/^\/api\/alerts\/([A-Z0-9-]+)\/status$/);
  if (method === 'POST' && alertStatusMatch)            return alertRoutes.updateAlertStatus(req, res, alertStatusMatch[1]);

  const incidentMatch = url.match(/^\/api\/alerts\/([A-Z0-9-]+)\/incident$/);
  if (method === 'GET'  && incidentMatch)               return alertRoutes.getIncident(req, res, incidentMatch[1]);
  if (method === 'POST' && incidentMatch)               return alertRoutes.upsertIncident(req, res, incidentMatch[1]);

  const escalateMatch = url.match(/^\/api\/alerts\/([A-Z0-9-]+)\/escalate$/);
  if (method === 'POST' && escalateMatch)               return alertRoutes.escalateAlert(req, res, escalateMatch[1]);

  const escalationsMatch = url.match(/^\/api\/alerts\/([A-Z0-9-]+)\/escalations$/);
  if (method === 'GET'  && escalationsMatch)            return alertRoutes.getEscalations(req, res, escalationsMatch[1]);

  // ── Admin routes ──────────────────────────────────────────────────────
  if (method === 'GET'  && url === '/api/admin/stats')    return adminRoutes.getStats(req, res);
  if (method === 'GET'  && url === '/api/admin/users')    return adminRoutes.listUsers(req, res);
  if (method === 'POST' && url === '/api/admin/users')    return adminRoutes.createUser(req, res);
  if (method === 'GET'  && url === '/api/admin/progress') return adminRoutes.getProgress(req, res);
  if (method === 'GET'  && url === '/api/admin/labs')     return adminRoutes.listAdminLabs(req, res);

  const userAdminMatch = url.match(/^\/api\/admin\/users\/(\d+)$/);
  if (method === 'PUT'    && userAdminMatch) return adminRoutes.updateUser(req, res, userAdminMatch[1]);
  if (method === 'DELETE' && userAdminMatch) return adminRoutes.deleteUser(req, res, userAdminMatch[1]);

  const analystActivityMatch = url.match(/^\/api\/admin\/analysts\/(\d+)\/activity$/);
  if (method === 'GET' && analystActivityMatch) return adminRoutes.getAnalystActivity(req, res, analystActivityMatch[1]);

  // ── Static file serving ───────────────────────────────────────────────
  if (method === 'GET') {
    if (url === '/' || url === '/login' || url === '/login.html')
      return serveFile(res, path.join(cfg.PUBLIC, 'login.html'));
    if (url === '/analyst' || url === '/analyst/')
      return serveFile(res, path.join(cfg.PUBLIC, 'analyst', 'index.html'));
    if (url === '/admin' || url === '/admin/')
      return serveFile(res, path.join(cfg.PUBLIC, 'admin', 'index.html'));

    // Serve other static assets (CSS, JS, fonts, images)
    let normalised;
    try { normalised = path.posix.normalize(decodeURIComponent(url)).replace(/^\/+/, ''); }
    catch { return jsonRes(res, 400, { ok: false, error: 'Invalid path' }); }

    const filePath = path.join(cfg.PUBLIC, normalised);
    if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      return serveFile(res, filePath);
    }
  }

  // ── 404 ───────────────────────────────────────────────────────────────
  jsonRes(res, 404, { ok: false, error: 'Not found' });
}

module.exports = { router };
