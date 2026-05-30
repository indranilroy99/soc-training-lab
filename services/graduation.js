'use strict';

// ── Graduation Lab System ─────────────────────────────────────────────────
// The Graduation Lab (slug: 'graduation-capstone') is locked behind
// prerequisites. It only unlocks when a student has met the criteria
// configured by the admin (or the defaults below).
//
// Default criteria: complete ALL labs in the 'required' category list.
// The admin can override by setting graduation_criteria in the DB config table.

const { db } = require('../db');

// ── Default prerequisites ─────────────────────────────────────────────────
// Any lab with these session_tags (Stack 2 + Stack 3 core) must be completed.
// A lab is "completed" when status = 'completed' in user_progress.
const GRADUATION_LAB_SLUG = 'graduation-capstone';
const MIN_LABS_REQUIRED   = 10;  // minimum count even if session_tag filtering fails
const REQUIRED_STACKS     = ['Stack 2', 'Stack 3']; // session_tag values

function getPrerequisiteStatus(userId) {
  // Get all required labs (Stack 2 + Stack 3)
  const requiredLabs = db.prepare(`
    SELECT id, slug, title, session_tag, is_visible
    FROM labs
    WHERE (session_tag LIKE 'Stack 2%' OR session_tag LIKE 'Stack 3%')
      AND (is_visible = 1 OR is_visible IS NULL)
      AND slug != ?
    ORDER BY order_index
  `).all(GRADUATION_LAB_SLUG);

  if (!requiredLabs.length) {
    // Fallback: require at least MIN_LABS_REQUIRED completed labs total
    const completed = db.prepare(
      `SELECT COUNT(*) AS c FROM user_progress WHERE user_id=? AND status='completed'`
    ).get(userId)?.c || 0;
    return {
      unlocked: completed >= MIN_LABS_REQUIRED,
      required_count: MIN_LABS_REQUIRED,
      completed_count: completed,
      missing: [],
      criteria: 'minimum_labs',
    };
  }

  // Check completion status for each required lab
  const completedLabIds = new Set(
    db.prepare(
      `SELECT lab_id FROM user_progress WHERE user_id=? AND status='completed'`
    ).all(userId).map(r => r.lab_id)
  );

  const missing = requiredLabs.filter(l => !completedLabIds.has(l.id));

  return {
    unlocked:        missing.length === 0,
    required_count:  requiredLabs.length,
    completed_count: requiredLabs.length - missing.length,
    missing:         missing.slice(0, 10).map(l => ({ slug: l.slug, title: l.title, session_tag: l.session_tag })),
    criteria:        'stack_completion',
    stacks:          REQUIRED_STACKS,
  };
}

// ── Graduation scorecard ──────────────────────────────────────────────────
// Called when the graduation lab is completed.
// Returns a comprehensive final report combining all platform activity.
function generateGraduationReport(userId) {
  const user = db.prepare(`SELECT id, username, created_at FROM users WHERE id=?`).get(userId);
  if (!user) return null;

  // ── Lab performance ───────────────────────────────────────────────────
  const labSummary = db.prepare(`
    SELECT
      COUNT(*) AS total_labs,
      SUM(CASE WHEN up.status='completed' THEN 1 ELSE 0 END)   AS completed_labs,
      SUM(CASE WHEN up.status='in_progress' THEN 1 ELSE 0 END) AS in_progress_labs,
      COALESCE(SUM(up.score), 0) AS total_lab_score
    FROM user_progress up WHERE up.user_id=?
  `).get(userId);

  const questionSummary = db.prepare(`
    SELECT
      COUNT(DISTINCT question_id) AS attempted,
      SUM(CASE WHEN is_correct=1 THEN 1 ELSE 0 END) AS correct,
      SUM(CASE WHEN is_correct=1 THEN pts_awarded ELSE 0 END) AS pts_earned,
      SUM(CASE WHEN hints_used > 0 THEN 1 ELSE 0 END) AS questions_with_hints,
      SUM(CASE WHEN wrong_count > 0 THEN 1 ELSE 0 END) AS questions_with_retries
    FROM user_answers WHERE user_id=?
  `).get(userId);

  const accuracy = questionSummary.attempted > 0
    ? Math.round((questionSummary.correct / questionSummary.attempted) * 100)
    : 0;
  const efficiency = questionSummary.correct > 0
    ? Math.round(((questionSummary.correct - questionSummary.questions_with_hints) / questionSummary.correct) * 100)
    : 0;

  // ── Alert triage performance ──────────────────────────────────────────
  const alertSummary = db.prepare(`
    SELECT
      COUNT(*)                                        AS total,
      SUM(CASE WHEN is_correct=1 THEN 1 ELSE 0 END)  AS correct,
      SUM(points_awarded)                             AS total_pts,
      COALESCE(AVG(CASE WHEN is_correct=1 THEN investigation_score END), 0) AS avg_ir_score
    FROM alert_closures WHERE user_id=?
  `).get(userId);

  // ── Category breakdown ────────────────────────────────────────────────
  const categoryBreakdown = db.prepare(`
    SELECT l.category,
      COUNT(DISTINCT up.lab_id) AS labs_done,
      COALESCE(SUM(up.score), 0) AS score
    FROM user_progress up
    JOIN labs l ON l.id = up.lab_id
    WHERE up.user_id=? AND up.status='completed'
    GROUP BY l.category
    ORDER BY score DESC
  `).all(userId);

  // ── Streak / attendance ───────────────────────────────────────────────
  const streakRow = db.prepare(`SELECT current_streak, longest_streak FROM streaks WHERE user_id=?`).get(userId);

  // ── Final composite score ─────────────────────────────────────────────
  const { getStudentPerformance } = require('./scoring_weighted');
  const perf        = getStudentPerformance(userId);
  const totalScore  = (questionSummary.pts_earned || 0) + (alertSummary.total_pts || 0);

  // Graduation grade (more demanding than regular grade)
  const gradGrade =
    perf.dps >= 85 ? 'Distinction' :
    perf.dps >= 70 ? 'Merit'       :
    perf.dps >= 55 ? 'Pass'        : 'Refer';

  return {
    user: { id: user.id, username: user.username, joined: user.created_at },
    generated_at: new Date().toISOString(),
    verdict: gradGrade,
    dps: perf.dps,
    grade: perf.grade,

    score_summary: {
      total_score:  totalScore,
      lab_score:    questionSummary.pts_earned || 0,
      alert_score:  alertSummary.total_pts     || 0,
    },

    labs: {
      total:        labSummary.total_labs       || 0,
      completed:    labSummary.completed_labs   || 0,
      in_progress:  labSummary.in_progress_labs || 0,
      completion_pct: labSummary.total_labs > 0
        ? Math.round((labSummary.completed_labs / labSummary.total_labs) * 100)
        : 0,
    },

    questions: {
      attempted: questionSummary.attempted    || 0,
      correct:   questionSummary.correct      || 0,
      accuracy,
      efficiency,
    },

    alerts: {
      total:        alertSummary.total         || 0,
      correct:      alertSummary.correct       || 0,
      triage_accuracy: alertSummary.total > 0
        ? Math.round((alertSummary.correct / alertSummary.total) * 100)
        : 0,
      avg_ir_score: Math.round(alertSummary.avg_ir_score || 0),
    },

    performance_pillars: perf.breakdown,
    category_breakdown:  categoryBreakdown,
    streak: {
      current: streakRow?.current_streak || 0,
      longest: streakRow?.longest_streak || 0,
    },
  };
}

module.exports = { getPrerequisiteStatus, generateGraduationReport, GRADUATION_LAB_SLUG };
