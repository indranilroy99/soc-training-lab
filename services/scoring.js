'use strict';

// ── Rubric scoring engine ─────────────────────────────────────────────────
// Scores analyst IR answers against per-alert rubrics stored in the DB.
// Returns { investigation_score: 0-100, step_scores, feedback, rubric_used }.

const { db } = require('../db');

const STEP_NAMES = ['triage_reason','containment_steps','eradication_steps','recovery_steps','rca_notes'];
const MIN_WORDS_PER_STEP = 15;

function scoreIRAnswers(alertId, answers) {
  const rubricRow = db.prepare('SELECT rubric_json FROM alert_rubrics WHERE alert_id=?').get(alertId);

  // Fallback when no rubric exists: score by total word depth
  if (!rubricRow) {
    const totalWords = Object.values(answers)
      .reduce((sum, v) => sum + (v || '').trim().split(/\s+/).filter(Boolean).length, 0);
    return {
      investigation_score: Math.min(100, Math.round((totalWords / 100) * 100)),
      step_scores: {},
      feedback: ['No rubric available for this alert — scored on response depth.'],
      rubric_used: false,
    };
  }

  let rubric;
  try { rubric = JSON.parse(rubricRow.rubric_json); }
  catch { return { investigation_score: 0, step_scores: {}, feedback: ['Rubric parse error.'], rubric_used: false }; }

  const stepScores = {};
  const feedback   = [];
  let totalEarned   = 0;
  let totalPossible = 0;

  // Global keyword check across all answers combined
  const allText = Object.values(answers).join(' ').toLowerCase();
  if (rubric.required_keywords?.length && rubric.min_keywords_required) {
    const found = rubric.required_keywords.filter(kw => allText.includes(kw.toLowerCase()));
    if (found.length < rubric.min_keywords_required) {
      feedback.push(
        `Answer must reference specific alert evidence. Expected keywords include: ${rubric.required_keywords.slice(0, 3).join(', ')}.`
      );
    }
  }

  for (const stepName of STEP_NAMES) {
    const stepRubric = rubric.steps?.[stepName];
    if (!stepRubric) continue;

    const text      = (answers[stepName] || '').toLowerCase();
    const wordCount = text.trim().split(/\s+/).filter(Boolean).length;
    const stepMax   = stepRubric.max_points || 10;
    totalPossible  += stepMax;

    // Word count gate
    if (wordCount < MIN_WORDS_PER_STEP) {
      feedback.push(`${stepName.replace(/_/g, ' ')}: too brief (${wordCount} words — need at least ${MIN_WORDS_PER_STEP}).`);
      stepScores[stepName] = { earned: 0, max: stepMax, pct: 0 };
      continue;
    }

    // Score each concept bucket
    let stepEarned = 0;
    for (const concept of (stepRubric.concepts || [])) {
      if (concept.keywords.some(kw => text.includes(kw.toLowerCase()))) {
        stepEarned += concept.points;
      }
    }
    stepEarned = Math.min(stepEarned, stepMax);
    totalEarned += stepEarned;
    stepScores[stepName] = { earned: stepEarned, max: stepMax, pct: Math.round((stepEarned / stepMax) * 100) };

    if (stepEarned < stepMax * 0.4) {
      feedback.push(`${stepName.replace(/_/g, ' ')}: weak — include specific technical steps and alert evidence.`);
    }
  }

  const investigationScore = totalPossible > 0
    ? Math.round((totalEarned / totalPossible) * 100)
    : 0;

  return { investigation_score: investigationScore, step_scores: stepScores, feedback, rubric_used: true };
}

// ── Points from investigation score ──────────────────────────────────────
function pointsFromScore(score) {
  if (score >= 90) return 5;
  if (score >= 75) return 4;
  if (score >= 60) return 3;
  if (score >= 40) return 2;
  return 1;
}

module.exports = { scoreIRAnswers, pointsFromScore };
