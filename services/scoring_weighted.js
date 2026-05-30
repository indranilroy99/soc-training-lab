'use strict';

// ── Weighted Performance Score ───────────────────────────────────────────
// Returns a 0–100 Performance Score built from four weighted pillars.
// This is separate from raw "points" which drive the leaderboard.
//
//  Pillar                  Weight  What it measures
//  ─────────────────────────────────────────────────────────
//  Lab Accuracy             40%    pts_earned / pts_possible on attempted questions
//  Alert Triage Quality     30%    correct_closures / total + IR report depth
//  Efficiency               20%    questions answered with no hints & no retries
//  Coverage & Breadth       10%    % of platform content engaged with

const { db } = require('../db');

function getStudentPerformance(userId) {
  // ── Pillar 1: Lab Accuracy (40%) ──────────────────────────────────────
  const labStats = db.prepare(`
    SELECT
      COUNT(*)                                              AS total_attempted,
      SUM(CASE WHEN is_correct=1 THEN 1 ELSE 0 END)       AS total_correct,
      SUM(CASE WHEN is_correct=1 THEN pts_awarded ELSE 0 END) AS pts_earned,
      SUM(q.points)                                         AS pts_possible
    FROM user_answers ua
    JOIN questions q ON q.id = ua.question_id
    WHERE ua.user_id = ?
  `).get(userId);

  const labAccuracy = labStats.pts_possible > 0
    ? Math.min(100, (labStats.pts_earned / labStats.pts_possible) * 100)
    : 0;

  // ── Pillar 2: Alert Triage Quality (30%) ─────────────────────────────
  const alertStats = db.prepare(`
    SELECT
      COUNT(*)                                          AS total_closures,
      SUM(CASE WHEN is_correct=1 THEN 1 ELSE 0 END)   AS correct_closures,
      COALESCE(AVG(CASE WHEN is_correct=1 THEN investigation_score ELSE NULL END), 0) AS avg_ir_score
    FROM alert_closures
    WHERE user_id = ?
  `).get(userId);

  let alertScore = 0;
  if (alertStats.total_closures > 0) {
    const classificationAcc = (alertStats.correct_closures / alertStats.total_closures) * 100;
    const irQuality         = alertStats.avg_ir_score || 0; // 0-100
    // Weight classification more heavily than IR depth
    alertScore = classificationAcc * 0.6 + irQuality * 0.4;
  }

  // ── Pillar 3: Efficiency (20%) ────────────────────────────────────────
  // Reward clean answers — no hints, no wrong attempts
  const effStats = db.prepare(`
    SELECT
      COUNT(*)                                                  AS total,
      SUM(CASE WHEN hints_used=0 AND wrong_count=0 AND is_correct=1 THEN 1 ELSE 0 END) AS clean_correct,
      SUM(CASE WHEN is_correct=1 THEN 1 ELSE 0 END)            AS total_correct
    FROM user_answers
    WHERE user_id = ?
  `).get(userId);

  let effScore = 0;
  if (effStats.total_correct > 0) {
    effScore = (effStats.clean_correct / effStats.total_correct) * 100;
  }

  // ── Pillar 4: Coverage & Breadth (10%) ───────────────────────────────
  const totalLabs   = db.prepare(`SELECT COUNT(*) as c FROM labs WHERE is_visible=1 OR is_visible IS NULL`).get().c;
  const totalAlerts = db.prepare(`SELECT COUNT(*) as c FROM soc_alerts`).get().c;
  const labsDone    = db.prepare(`SELECT COUNT(*) as c FROM user_progress WHERE user_id=? AND status='completed'`).get(userId).c;
  const alertsDone  = db.prepare(`SELECT COUNT(DISTINCT alert_id) as c FROM alert_closures WHERE user_id=?`).get(userId).c;

  let coverageScore = 0;
  if (totalLabs > 0 || totalAlerts > 0) {
    const labCov   = totalLabs   > 0 ? (labsDone   / totalLabs)   * 100 : 0;
    const alertCov = totalAlerts > 0 ? (alertsDone / totalAlerts) * 100 : 0;
    // Weight labs more, alerts secondary
    coverageScore  = labCov * 0.7 + alertCov * 0.3;
  }

  // ── Composite Score ───────────────────────────────────────────────────
  const dps = Math.round(
    labAccuracy  * 0.40 +
    alertScore   * 0.30 +
    effScore     * 0.20 +
    coverageScore * 0.10
  );

  // ── Grade ─────────────────────────────────────────────────────────────
  const grade =
    dps >= 90 ? 'A+' :
    dps >= 80 ? 'A'  :
    dps >= 70 ? 'B'  :
    dps >= 60 ? 'C'  :
    dps >= 50 ? 'D'  : 'F';

  return {
    dps,
    grade,
    breakdown: {
      lab_accuracy:   { score: Math.round(labAccuracy),   weight: 40, label: 'Lab Accuracy'      },
      alert_quality:  { score: Math.round(alertScore),    weight: 30, label: 'Alert Quality'      },
      efficiency:     { score: Math.round(effScore),      weight: 20, label: 'Answer Efficiency'  },
      coverage:       { score: Math.round(coverageScore), weight: 10, label: 'Platform Coverage'  },
    },
    raw: {
      questions_attempted: labStats.total_attempted || 0,
      questions_correct:   labStats.total_correct   || 0,
      pts_earned:          labStats.pts_earned       || 0,
      pts_possible:        labStats.pts_possible     || 0,
      clean_correct:       effStats.clean_correct    || 0,
      alerts_closed:       alertStats.total_closures || 0,
      alerts_correct:      alertStats.correct_closures || 0,
      labs_completed:      labsDone,
      total_labs:          totalLabs,
    },
  };
}

module.exports = { getStudentPerformance };
