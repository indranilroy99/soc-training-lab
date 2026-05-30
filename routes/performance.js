'use strict';

const { db }                  = require('../db');
const { requireAuth }         = require('../middleware/auth');
const { requireAdmin }        = require('../middleware/auth');
const { ok }                  = require('../middleware/response');
const { getStudentPerformance } = require('../services/scoring_weighted');

// GET /api/me/performance  — individual analyst performance breakdown
function myPerformance(req, res) {
  const user = requireAuth(req, res); if (!user) return;
  return ok(res, getStudentPerformance(user.id));
}

// GET /api/admin/performance/all  — all students with performance scores (admin)
function allPerformance(req, res) {
  const admin = requireAdmin(req, res); if (!admin) return;

  const students = db.prepare(
    `SELECT id, username FROM users WHERE role='analyst' AND is_active=1 ORDER BY username`
  ).all();

  const rows = students.map(s => {
    const p = getStudentPerformance(s.id);
    return {
      id:       s.id,
      username: s.username,
      dps:      p.dps,
      grade:    p.grade,
      breakdown: p.breakdown,
      raw:       p.raw,
    };
  });

  // Sort by DPS descending, then alphabetically
  rows.sort((a, b) => b.dps - a.dps || a.username.localeCompare(b.username));
  return ok(res, rows);
}

module.exports = { myPerformance, allPerformance };
