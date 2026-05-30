'use strict';

// ── Analyst Profile Service ───────────────────────────────────────────────
// Returns a full per-student profile for the admin dashboard.
// Uses only SQLite 3.7+ compatible syntax (no FILTER clause).

const { db }                    = require('../db');
const { getStudentPerformance } = require('./scoring_weighted');
const { getStreak }             = require('./streaks');

function getAnalystProfile(userId) {
  const user = db.prepare(
    `SELECT id, username, role, is_active, created_at FROM users WHERE id=?`
  ).get(userId);
  if (!user) return null;

  // ── Core stats ────────────────────────────────────────────────────────
  // Use CASE WHEN instead of FILTER (SQLite 3.7+ compatible)
  const labStats = db.prepare(`
    SELECT
      COUNT(DISTINCT up.lab_id)                                     AS labs_done_total,
      COUNT(DISTINCT CASE WHEN up.status='completed'   THEN up.lab_id END) AS labs_done,
      COUNT(DISTINCT CASE WHEN up.status='in_progress' THEN up.lab_id END) AS labs_progress,
      COALESCE(SUM(CASE WHEN ua.is_correct=1 THEN ua.pts_awarded ELSE 0 END), 0) AS lab_pts,
      COUNT(DISTINCT CASE WHEN ua.is_correct=1 THEN ua.question_id END)    AS correct_qs,
      COUNT(DISTINCT ua.question_id)                                        AS attempted_qs
    FROM users u
    LEFT JOIN user_progress up ON up.user_id = u.id
    LEFT JOIN user_answers  ua ON ua.user_id = u.id
    WHERE u.id = ?
  `).get(userId);

  const alertPts = db.prepare(
    `SELECT COALESCE(SUM(points_awarded), 0) AS total FROM alert_closures WHERE user_id=? AND is_correct=1`
  ).get(userId).total;

  const totalScore = (labStats.lab_pts || 0) + (alertPts || 0);
  const totalQ     = labStats.attempted_qs || 0;
  const correctQ   = labStats.correct_qs   || 0;
  const accuracy   = totalQ > 0 ? Math.round((correctQ / totalQ) * 100) : 0;

  // Rank
  const allScores = db.prepare(`
    SELECT u.id,
      COALESCE(la.s, 0) + COALESCE(al.s, 0) AS total
    FROM users u
    LEFT JOIN (SELECT user_id, SUM(CASE WHEN is_correct=1 THEN pts_awarded ELSE 0 END) s FROM user_answers GROUP BY user_id) la ON la.user_id=u.id
    LEFT JOIN (SELECT user_id, SUM(points_awarded) s FROM alert_closures WHERE is_correct=1 GROUP BY user_id) al ON al.user_id=u.id
    WHERE u.role='analyst' AND u.is_active=1
    ORDER BY total DESC
  `).all();
  const rank = allScores.findIndex(r => r.id === userId) + 1;

  const lastSession = db.prepare(
    `SELECT expires_at, created_at FROM sessions WHERE user_id=? ORDER BY expires_at DESC LIMIT 1`
  ).get(userId);

  // ── Performance score ─────────────────────────────────────────────────
  const performance = getStudentPerformance(userId);
  const streak      = getStreak(userId);

  // ── Login history ─────────────────────────────────────────────────────
  const sessions = db.prepare(
    `SELECT created_at, expires_at FROM sessions WHERE user_id=? ORDER BY expires_at DESC LIMIT 20`
  ).all(userId);

  // ── Per-lab activity ──────────────────────────────────────────────────
  const allLabs = db.prepare(`
    SELECT l.id, l.slug, l.title, l.category, l.difficulty, l.points,
           up.status, up.score, up.started_at, up.completed_at
    FROM labs l
    LEFT JOIN user_progress up ON up.lab_id=l.id AND up.user_id=?
    WHERE l.is_visible=1 OR l.is_visible IS NULL
    ORDER BY l.order_index
  `).all(userId);

  const labActivity = allLabs.map(lab => {
    const labQuestions = db.prepare(`
      SELECT q.id, q.question, q.answer_type, q.points, q.order_index,
             ua.is_correct, ua.pts_awarded, ua.hints_used, ua.wrong_count,
             ua.submitted_answer, ua.attempt_number, ua.submitted_at
      FROM questions q
      LEFT JOIN user_answers ua ON ua.question_id=q.id AND ua.user_id=?
      WHERE q.lab_id=?
      ORDER BY q.order_index
    `).all(userId, lab.id);

    const questionsTotal   = labQuestions.length;
    const questionsAnswered = labQuestions.filter(q => q.is_correct !== null || q.wrong_count > 0).length;
    const questionsCorrect  = labQuestions.filter(q => q.is_correct === 1).length;
    const maxScore          = labQuestions.reduce((s, q) => s + (q.points || 0), 0);
    const scoreEarned       = labQuestions.reduce((s, q) => s + (q.pts_awarded || 0), 0);

    let timeSpentMins = null;
    if (lab.started_at && lab.completed_at) {
      timeSpentMins = Math.round((new Date(lab.completed_at) - new Date(lab.started_at)) / 60000);
    } else {
      const times = labQuestions.filter(q => q.submitted_at).map(q => new Date(q.submitted_at));
      if (times.length >= 2) {
        times.sort((a, b) => a - b);
        timeSpentMins = Math.round((times[times.length - 1] - times[0]) / 60000);
      }
    }

    return {
      lab_id: lab.id, slug: lab.slug, title: lab.title,
      category: lab.category, difficulty: lab.difficulty, max_score: maxScore,
      score_earned: scoreEarned, status: lab.status || 'not_started',
      started_at: lab.started_at, completed_at: lab.completed_at,
      time_spent_mins: timeSpentMins,
      questions_total: questionsTotal, questions_answered: questionsAnswered,
      questions_correct: questionsCorrect,
      questions: labQuestions.map(q => ({
        id: q.id, order_index: q.order_index, question: q.question,
        answer_type: q.answer_type, points: q.points,
        is_correct: q.is_correct === 1,
        attempted: q.is_correct !== null || (q.wrong_count || 0) > 0,
        pts_awarded: q.pts_awarded || 0, hints_used: q.hints_used || 0,
        wrong_count: q.wrong_count || 0, submitted_answer: q.submitted_answer || null,
        attempts: q.attempt_number || 0, submitted_at: q.submitted_at || null,
      })),
    };
  });

  // ── Weak areas ────────────────────────────────────────────────────────
  const stuckQuestions = labActivity
    .flatMap(lab => lab.questions
      .filter(q => q.attempted && !q.is_correct)
      .map(q => ({
        lab_title: lab.title, lab_slug: lab.slug, category: lab.category,
        question: q.question.length > 100 ? q.question.slice(0, 100) + '…' : q.question,
        wrong_count: q.wrong_count, hints_used: q.hints_used,
      })))
    .sort((a, b) => b.wrong_count - a.wrong_count)
    .slice(0, 20);

  // Category performance
  const catMap = {};
  labActivity.forEach(lab => {
    const cat = lab.category || 'Uncategorised';
    if (!catMap[cat]) catMap[cat] = { lab_count: 0, labs_done: 0, correct: 0, total: 0 };
    catMap[cat].lab_count++;
    if (lab.status === 'completed') catMap[cat].labs_done++;
    catMap[cat].correct += lab.questions_correct;
    catMap[cat].total   += lab.questions_answered;
  });
  const categoryPerformance = Object.entries(catMap).map(([cat, d]) => ({
    category: cat, lab_count: d.lab_count, labs_done: d.labs_done,
    correct: d.correct, attempted: d.total,
    accuracy: d.total > 0 ? Math.round((d.correct / d.total) * 100) : 0,
  })).sort((a, b) => a.accuracy - b.accuracy);

  // ── Alert history ─────────────────────────────────────────────────────
  const alertHistory = db.prepare(`
    SELECT ac.alert_id, sa.title AS alert_title, sa.severity, sa.category,
           ac.classification, ac.is_correct, ac.points_awarded,
           ac.investigation_score, ac.step_scores, ac.scoring_feedback,
           ac.triage_reason, ac.fp_reason, ac.closed_at
    FROM alert_closures ac
    LEFT JOIN soc_alerts sa ON sa.id = ac.alert_id
    WHERE ac.user_id=?
    ORDER BY ac.closed_at DESC
  `).all(userId).map(a => ({
    alert_id: a.alert_id, alert_title: a.alert_title, severity: a.severity,
    category: a.category, classification: a.classification,
    is_correct: !!a.is_correct, points: a.points_awarded,
    investigation_score: a.investigation_score || 0,
    step_scores:      a.step_scores      ? JSON.parse(a.step_scores)      : {},
    scoring_feedback: a.scoring_feedback ? JSON.parse(a.scoring_feedback) : [],
    triage_reason: a.triage_reason, fp_reason: a.fp_reason, closed_at: a.closed_at,
  }));

  // ── Activity feed ─────────────────────────────────────────────────────
  const answerEvents = db.prepare(`
    SELECT ua.submitted_at AS ts, 'answer' AS type,
           CASE WHEN ua.is_correct=1 THEN 'correct' ELSE 'wrong' END AS result,
           ua.pts_awarded AS pts,
           q.question AS detail, l.title AS lab_title, l.slug AS lab_slug
    FROM user_answers ua
    JOIN questions q ON q.id = ua.question_id
    JOIN labs l ON l.id = ua.lab_id
    WHERE ua.user_id=?
    ORDER BY ua.submitted_at DESC LIMIT 30
  `).all(userId);

  const alertEvents = db.prepare(`
    SELECT ac.closed_at AS ts, 'alert' AS type,
           CASE WHEN ac.is_correct=1 THEN 'correct' ELSE 'wrong' END AS result,
           ac.points_awarded AS pts,
           sa.title AS detail, ac.classification AS lab_title, NULL AS lab_slug
    FROM alert_closures ac
    LEFT JOIN soc_alerts sa ON sa.id = ac.alert_id
    WHERE ac.user_id=?
    ORDER BY ac.closed_at DESC LIMIT 20
  `).all(userId);

  const labEvents = db.prepare(`
    SELECT up.completed_at AS ts, 'lab_complete' AS type, 'completed' AS result,
           up.score AS pts, l.title AS detail, l.slug AS lab_slug, l.title AS lab_title
    FROM user_progress up JOIN labs l ON l.id = up.lab_id
    WHERE up.user_id=? AND up.completed_at IS NOT NULL
    ORDER BY up.completed_at DESC LIMIT 20
  `).all(userId);

  const allEvents = [...answerEvents, ...alertEvents, ...labEvents]
    .filter(e => e.ts)
    .sort((a, b) => new Date(b.ts) - new Date(a.ts))
    .slice(0, 50);

  return {
    user:   { id: user.id, username: user.username, is_active: user.is_active, joined: user.created_at },
    stats:  {
      score: totalScore, rank, accuracy,
      labs_done: labStats.labs_done || 0, labs_progress: labStats.labs_progress || 0,
      correct_answers: correctQ, total_answers: totalQ,
      alerts_closed: alertHistory.length,
      last_seen: lastSession?.expires_at || null,
    },
    performance, streak, sessions,
    lab_activity: labActivity, stuck_questions: stuckQuestions,
    category_performance: categoryPerformance,
    alert_history: alertHistory, activity_feed: allEvents,
  };
}

module.exports = { getAnalystProfile };
