'use strict';

// ── User services ─────────────────────────────────────────────────────────
// All user-related DB queries extracted from server.js.

const { db } = require('../db');

// ── Score ─────────────────────────────────────────────────────────────────
function getUserTotalScore(userId) {
  const lab = db.prepare(
    `SELECT COALESCE(SUM(pts_awarded),0) as total
     FROM user_answers WHERE user_id=? AND is_correct=1`
  ).get(userId);
  const closure = db.prepare(
    `SELECT COALESCE(SUM(points_awarded),0) as total
     FROM alert_closures WHERE user_id=? AND is_correct=1`
  ).get(userId);
  return (lab?.total || 0) + (closure?.total || 0);
}

// ── Rank ──────────────────────────────────────────────────────────────────
function getUserRank(userId) {
  const scores = db.prepare(
    `SELECT u.id,
            COALESCE(lab.total,0) + COALESCE(closure.total,0) as total
     FROM users u
     LEFT JOIN (
       SELECT user_id, SUM(pts_awarded) as total
       FROM user_answers WHERE is_correct=1 GROUP BY user_id
     ) lab ON lab.user_id = u.id
     LEFT JOIN (
       SELECT user_id, SUM(points_awarded) as total
       FROM alert_closures WHERE is_correct=1 GROUP BY user_id
     ) closure ON closure.user_id = u.id
     WHERE u.role='analyst' AND u.is_active=1
     ORDER BY total DESC, u.username ASC`
  ).all();
  const idx = scores.findIndex(r => r.id === userId && r.total > 0);
  return idx === -1 ? 0 : idx + 1;
}

// ── Alert state ───────────────────────────────────────────────────────────
function getUserAlertStatus(userId, alertId, fallback = 'open') {
  const row = db.prepare(
    `SELECT status FROM user_alert_state WHERE user_id=? AND alert_id=?`
  ).get(userId, alertId);
  return row?.status || fallback;
}

function setUserAlertStatus(userId, alertId, status) {
  db.prepare(
    `INSERT INTO user_alert_state (user_id, alert_id, status, updated_at)
     VALUES (?,?,?,?)
     ON CONFLICT(user_id, alert_id) DO UPDATE SET
       status=excluded.status, updated_at=excluded.updated_at`
  ).run(userId, alertId, status, new Date().toISOString());
}

// ── Hint helpers ──────────────────────────────────────────────────────────
function buildMaskedAnswer(answer) {
  return String(answer || '').trim().split(/(\s+)/).map(token => {
    if (/^\s+$/.test(token)) return token;
    if (token.length <= 1) return token;
    if (token.length === 2) return token[0] + '_';
    return token[0] + ' ' + Array.from({ length: token.length - 1 }, () => '_').join(' ');
  }).join('');
}

function getHintPlan(question) {
  let configured = [];
  try { configured = question.hint_levels ? JSON.parse(question.hint_levels) : []; } catch { configured = []; }
  configured = Array.isArray(configured)
    ? configured.filter(Boolean).map(h => String(h).trim()).filter(Boolean)
    : [];
  if (question.hint) configured.unshift(String(question.hint).trim());
  configured = configured.slice(0, 2);

  const answer = String(question.correct_answer || '').trim();
  const f1 = question.alert_ref
    ? `Focus on the investigation material linked to ${question.alert_ref}. Analyse the logs and evidence carefully.`
    : 'Review the evidence, logs, and investigation notes carefully before answering.';
  const f2 = configured[0] || 'Re-check the exact field, indicator, or value in the evidence.';
  const f3 = configured[1] || `The correct answer matches this pattern: ${buildMaskedAnswer(answer)}`;
  return [f1, f2, f3];
}

function getHintPenalty(basePoints, hintCount) {
  const pts = Math.max(0, parseInt(basePoints) || 0);
  if (hintCount <= 0) return pts;
  if (hintCount === 1) return Math.max(0, pts - 5);
  if (hintCount === 2) return Math.max(0, pts - 15);
  return 0;
}

function getWrongAttemptPenalty(basePoints, wrongCount) {
  const pts = Math.max(0, parseInt(basePoints) || 0);
  return Math.max(0, pts - Math.min(wrongCount, 3) * 3);
}

module.exports = {
  getUserTotalScore,
  getUserRank,
  getUserAlertStatus,
  setUserAlertStatus,
  buildMaskedAnswer,
  getHintPlan,
  getHintPenalty,
  getWrongAttemptPenalty,
};
