'use strict';

// ── Consistent API response helpers ───────────────────────────────────────
// Every API endpoint uses these. Never call res.writeHead manually in routes.

const cfg = require('../config');

function jsonRes(res, status, data, extraHeaders = {}) {
  // Ensure data is always an object — never send a bare string or array
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type':  'application/json',
    'Cache-Control': cfg.API_CACHE_HEADER,
    ...extraHeaders,
  });
  res.end(body);
}

function ok(res, data = {}, status = 200) {
  return jsonRes(res, status, { ok: true, ...data });
}

function created(res, data = {}) {
  return ok(res, data, 201);
}

function notFound(res, message = 'Not found') {
  return jsonRes(res, 404, { ok: false, error: message });
}

function badRequest(res, message = 'Bad request') {
  return jsonRes(res, 400, { ok: false, error: message });
}

function unauthorized(res, message = 'Authentication required') {
  return jsonRes(res, 401, { ok: false, error: message });
}

function forbidden(res, message = 'Access denied') {
  return jsonRes(res, 403, { ok: false, error: message });
}

function serverError(res, message = 'Internal server error') {
  return jsonRes(res, 500, { ok: false, error: message });
}

module.exports = { jsonRes, ok, created, notFound, badRequest, unauthorized, forbidden, serverError };
