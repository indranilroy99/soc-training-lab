'use strict';

const { requireAuth } = require('../middleware/auth');
const { ok }          = require('../middleware/response');
const { getPathsWithProgress } = require('../services/paths');

// GET /api/paths
function listPaths(req, res) {
  const user = requireAuth(req, res); if (!user) return;
  return ok(res, getPathsWithProgress(user.id));
}

module.exports = { listPaths };
