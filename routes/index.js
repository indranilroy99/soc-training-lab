'use strict';

const path   = require('path');
const fs     = require('fs');
const cfg    = require('../config');
const { healthCheck } = require('../db');
const { jsonRes }     = require('../middleware/response');
const { apiLimiter, submitLimiter } = require('../middleware/rateLimit');

const authRoutes   = require('./auth');
const userRoutes   = require('./user');
const labRoutes    = require('./labs');
const alertRoutes  = require('./alerts');
const lbRoutes     = require('./leaderboard');
const adminRoutes  = require('./admin');
const achRoutes    = require('./achievements');
const perfRoutes   = require('./performance');
const pathRoutes   = require('./paths');
const noteRoutes   = require('./notes');

// ── MIME types ────────────────────────────────────────────────────────────
const MIME = {
  '.html':'text/html; charset=utf-8', '.css':'text/css; charset=utf-8',
  '.js':'application/javascript; charset=utf-8', '.json':'application/json',
  '.png':'image/png', '.jpg':'image/jpeg', '.jpeg':'image/jpeg',
  '.svg':'image/svg+xml', '.ico':'image/x-icon',
  '.woff2':'font/woff2', '.woff':'font/woff', '.webp':'image/webp',
};

function serveFile(res, filePath) {
  const resolved  = path.resolve(filePath);
  const publicDir = path.resolve(cfg.PUBLIC);
  if (!resolved.startsWith(publicDir + path.sep) && resolved !== publicDir) {
    res.writeHead(403); res.end('Forbidden'); return;
  }
  const ext  = path.extname(resolved).toLowerCase();
  const mime = MIME[ext] || 'application/octet-stream';
  fs.readFile(resolved, (err, data) => {
    if (err) { res.writeHead(404); res.end('Not found'); return; }
    res.writeHead(200, { 'Content-Type': mime, 'Cache-Control': ext==='.html' ? 'no-store' : 'public, max-age=3600' });
    res.end(data);
  });
}

async function router(req, res) {
  const rawUrl = req.url || '/';
  const url    = rawUrl.split('?')[0];
  const method = req.method.toUpperCase();

  // Health check
  if (method === 'GET' && url === '/health') {
    const h = healthCheck();
    return jsonRes(res, h.ok ? 200 : 503, { ok: h.ok, pid: process.pid, ts: new Date().toISOString() });
  }

  // Apply rate limiter to all API routes
  if (url.startsWith('/api/')) {
    let done = false;
    apiLimiter(req, res, () => { done = true; });
    if (!done) return;
  }

  // ── Auth ──────────────────────────────────────────────────────────────
  if (method === 'POST' && url === '/api/auth/login')  return authRoutes.login(req, res);
  if (method === 'POST' && url === '/api/auth/logout') return authRoutes.logout(req, res);

  // ── User ──────────────────────────────────────────────────────────────
  if (method === 'GET'  && url === '/api/me')            return userRoutes.getMe(req, res);
  if (method === 'GET'  && url === '/api/me/closures')   return userRoutes.getMyClosures(req, res);
  if (method === 'POST' && url === '/api/user/password') return userRoutes.changePassword(req, res);
  if (method === 'GET'  && url === '/api/me/performance') return perfRoutes.myPerformance(req, res);
  if (method === 'GET'  && url === '/api/admin/performance/all') return perfRoutes.allPerformance(req, res);
  // Drafts stub — admin page calls this; return empty if no route
  if (method === 'GET'  && url.startsWith('/api/me/drafts/')) return jsonRes(res, 200, { ok: true, drafts: {} });

  // ── Leaderboard ───────────────────────────────────────────────────────
  if (method === 'GET'  && url === '/api/leaderboard')  return lbRoutes.getLeaderboard(req, res);

  // ── Achievements & Paths & Notes ──────────────────────────────────────
  if (method === 'GET'  && url === '/api/achievements') return achRoutes.listAchievements(req, res);
  if (method === 'GET'  && url === '/api/paths')        return pathRoutes.listPaths(req, res);

  const notesMatch = url.match(/^\/api\/labs\/([^/]+)\/notes$/);
  if (method === 'GET' && notesMatch)  return noteRoutes.getNotes(req, res, notesMatch[1]);
  if (method === 'PUT' && notesMatch)  return noteRoutes.saveNotes(req, res, notesMatch[1]);

  // ── Labs ──────────────────────────────────────────────────────────────
  if (method === 'GET'  && url === '/api/labs') return labRoutes.listLabs(req, res);

  const labSlugMatch = url.match(/^\/api\/labs\/([^/]+)$/);
  if (method === 'GET'  && labSlugMatch) return labRoutes.getLab(req, res, labSlugMatch[1]);

  const submitMatch = url.match(/^\/api\/labs\/([^/]+)\/submit$/);
  if (method === 'POST' && submitMatch) {
    let done = false;
    submitLimiter(req, res, () => { done = true; });
    if (!done) return;
    return labRoutes.submitAnswer(req, res, submitMatch[1]);
  }

  const hintMatch  = url.match(/^\/api\/labs\/([^/]+)\/hint$/);
  if (method === 'POST' && hintMatch)  return labRoutes.requestHint(req, res, hintMatch[1]);

  const resetMatch = url.match(/^\/api\/labs\/([^/]+)\/reset$/);
  if (method === 'POST' && resetMatch) return labRoutes.resetLab(req, res, resetMatch[1]);

  // ── Alerts ────────────────────────────────────────────────────────────
  if (method === 'GET' && url.startsWith('/api/alerts') && url === '/api/alerts') return alertRoutes.listAlerts(req, res);

  const alertIdMatch     = url.match(/^\/api\/alerts\/([A-Z0-9-]+)$/);
  if (method === 'GET'  && alertIdMatch)  return alertRoutes.getAlert(req, res, alertIdMatch[1]);

  const alertStatusMatch = url.match(/^\/api\/alerts\/([A-Z0-9-]+)\/status$/);
  if (method === 'POST' && alertStatusMatch) return alertRoutes.updateAlertStatus(req, res, alertStatusMatch[1]);

  const incidentMatch    = url.match(/^\/api\/alerts\/([A-Z0-9-]+)\/incident$/);
  if (method === 'GET'  && incidentMatch) return alertRoutes.getIncident(req, res, incidentMatch[1]);
  if (method === 'POST' && incidentMatch) return alertRoutes.upsertIncident(req, res, incidentMatch[1]);

  const escalateMatch    = url.match(/^\/api\/alerts\/([A-Z0-9-]+)\/escalate$/);
  if (method === 'POST' && escalateMatch) return alertRoutes.escalateAlert(req, res, escalateMatch[1]);

  const escalationsMatch = url.match(/^\/api\/alerts\/([A-Z0-9-]+)\/escalations$/);
  if (method === 'GET'  && escalationsMatch) return alertRoutes.getEscalations(req, res, escalationsMatch[1]);

  // ── Admin ─────────────────────────────────────────────────────────────
  if (method === 'GET'  && url === '/api/admin/stats')    return adminRoutes.getStats(req, res);
  if (method === 'GET'  && url === '/api/admin/users')    return adminRoutes.listUsers(req, res);
  if (method === 'POST' && url === '/api/admin/users')    return adminRoutes.createUser(req, res);
  if (method === 'GET'  && url === '/api/admin/progress') return adminRoutes.getProgress(req, res);
  if (method === 'GET'  && url === '/api/admin/labs')     return adminRoutes.listAdminLabs(req, res);
  if (method === 'POST' && url === '/api/admin/labs')     return adminRoutes.createLab(req, res);

  const userAdminMatch = url.match(/^\/api\/admin\/users\/(\d+)$/);
  if (method === 'PUT'    && userAdminMatch) return adminRoutes.updateUser(req, res, userAdminMatch[1]);
  if (method === 'DELETE' && userAdminMatch) return adminRoutes.deleteUser(req, res, userAdminMatch[1]);

  const adminLabIdMatch = url.match(/^\/api\/admin\/labs\/(\d+)$/);
  if (method === 'PUT'    && adminLabIdMatch) return adminRoutes.updateLab(req, res, adminLabIdMatch[1]);
  if (method === 'DELETE' && adminLabIdMatch) return adminRoutes.deleteLab(req, res, adminLabIdMatch[1]);

  const adminLabQsMatch = url.match(/^\/api\/admin\/labs\/(\d+)\/questions$/);
  if (method === 'GET'  && adminLabQsMatch) return adminRoutes.getLabQuestions(req, res, adminLabQsMatch[1]);
  if (method === 'POST' && adminLabQsMatch) return adminRoutes.addQuestion(req, res, adminLabQsMatch[1]);

  const adminQMatch = url.match(/^\/api\/admin\/questions\/(\d+)$/);
  if (method === 'PUT'    && adminQMatch) return adminRoutes.updateQuestion(req, res, adminQMatch[1]);
  if (method === 'DELETE' && adminQMatch) return adminRoutes.deleteQuestion(req, res, adminQMatch[1]);

  const analystActMatch = url.match(/^\/api\/admin\/analysts\/(\d+)\/activity$/);
  if (method === 'GET' && analystActMatch) return adminRoutes.getAnalystActivity(req, res, analystActMatch[1]);

  const analystProfileMatch = url.match(/^\/api\/admin\/analysts\/(\d+)\/profile$/);
  if (method === 'GET' && analystProfileMatch) return adminRoutes.getProfile(req, res, analystProfileMatch[1]);

  // ── Static files ──────────────────────────────────────────────────────
  if (method === 'GET') {
    if (url === '/' || url === '/login' || url === '/login.html')
      return serveFile(res, path.join(cfg.PUBLIC, 'login.html'));
    if (url === '/analyst' || url === '/analyst/')
      return serveFile(res, path.join(cfg.PUBLIC, 'analyst', 'index.html'));
    if (url === '/admin' || url === '/admin/')
      return serveFile(res, path.join(cfg.PUBLIC, 'admin', 'index.html'));

    let normalised;
    try { normalised = path.posix.normalize(decodeURIComponent(url)).replace(/^\/+/, ''); }
    catch { return jsonRes(res, 400, { ok: false, error: 'Invalid path' }); }

    const filePath = path.join(cfg.PUBLIC, normalised);
    if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      return serveFile(res, filePath);
    }
  }

  jsonRes(res, 404, { ok: false, error: 'Not found' });
}

module.exports = { router };
