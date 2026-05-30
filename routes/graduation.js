'use strict';

const { requireAuth }            = require('../middleware/auth');
const { requireAdmin }           = require('../middleware/auth');
const { ok, notFound, badRequest } = require('../middleware/response');
const { db }                     = require('../db');
const { getPrerequisiteStatus, generateGraduationReport, GRADUATION_LAB_SLUG } = require('../services/graduation');

// GET /api/graduation/status  — analyst checks if they're eligible
function getGraduationStatus(req, res) {
  const user   = requireAuth(req, res); if (!user) return;
  const status = getPrerequisiteStatus(user.id);

  // Find the graduation lab
  const lab = db.prepare(`SELECT id, slug, title, description FROM labs WHERE slug=?`).get(GRADUATION_LAB_SLUG);

  return ok(res, { ...status, lab: lab || null });
}

// GET /api/graduation/report  — analyst gets their graduation scorecard
function getMyReport(req, res) {
  const user = requireAuth(req, res); if (!user) return;
  const status = getPrerequisiteStatus(user.id);
  if (!status.unlocked) {
    return badRequest(res, `Graduation lab not yet unlocked. Complete ${status.missing?.length || 'required'} more labs first.`);
  }
  return ok(res, generateGraduationReport(user.id));
}

// GET /api/admin/graduation/report/:userId  — admin pulls any student's report
function getStudentReport(req, res, userId) {
  const admin = requireAdmin(req, res); if (!admin) return;
  const uid   = parseInt(userId, 10);
  const user  = db.prepare(`SELECT id FROM users WHERE id=?`).get(uid);
  if (!user) return notFound(res, 'User not found');
  return ok(res, generateGraduationReport(uid));
}

module.exports = { getGraduationStatus, getMyReport, getStudentReport };
