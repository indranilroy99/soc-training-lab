'use strict';

const { db }           = require('../db');
const { requireAuth }  = require('../middleware/auth');
const { parseBody }    = require('../middleware/security');
const { ok, notFound, badRequest } = require('../middleware/response');
const { getLabsWithProgress }      = require('../services/labs');
const { getUserTotalScore, getHintPlan, getHintPenalty, getWrongAttemptPenalty } = require('../services/users');
const { requireInt }   = require('../middleware/validate');
const { checkAchievements, checkLabAchievements } = require('../services/achievements');
const { updateStreak } = require('../services/streaks');

// GET /api/labs
function listLabs(req, res) {
  const user = requireAuth(req, res); if (!user) return;
  return ok(res, getLabsWithProgress(user.id));
}

// GET /api/labs/:slug
function getLab(req, res, slug) {
  const user = requireAuth(req, res); if (!user) return;
  const lab  = db.prepare(`SELECT * FROM labs WHERE slug=?`).get(slug);
  if (!lab) return notFound(res, 'Lab not found');

  const questions = db.prepare(
    `SELECT id, order_index, question, answer_type, options, points,
            hint, hint_levels, alert_ref
     FROM questions WHERE lab_id=? ORDER BY order_index`
  ).all(lab.id).map(q => ({ ...q, options: q.options ? JSON.parse(q.options) : null }));

  const answeredRows = db.prepare(
    `SELECT question_id, is_correct, pts_awarded, attempt_number,
            hints_used, submitted_answer
     FROM user_answers WHERE user_id=? AND lab_id=? ORDER BY submitted_at DESC`
  ).all(user.id, lab.id);

  const answerMap = {};
  answeredRows.forEach(a => { if (!answerMap[a.question_id]) answerMap[a.question_id] = a; });

  const questionsWithStatus = questions.map(q => ({
    ...q,
    completed:        !!(answerMap[q.id]?.is_correct),
    attempts:         answerMap[q.id]?.attempt_number || 0,
    pts_earned:       answerMap[q.id]?.pts_awarded    || 0,
    hints_used:       answerMap[q.id]?.hints_used     || 0,
    submitted_answer: answerMap[q.id]?.submitted_answer || '',
    hint_plan:        getHintPlan(q),
  }));

  const prog = db.prepare(
    `SELECT status, score, started_at, completed_at FROM user_progress WHERE user_id=? AND lab_id=?`
  ).get(user.id, lab.id);

  let alert_refs = []; let evidence = [];
  try { alert_refs = lab.alert_refs ? JSON.parse(lab.alert_refs) : []; } catch {}
  try { evidence   = lab.evidence   ? JSON.parse(lab.evidence)   : []; } catch {}

  return ok(res, {
    ...lab, alert_refs, evidence,
    questions: questionsWithStatus,
    progress: prog || { status: 'not_started', score: 0 },
  });
}

// POST /api/labs/:slug/submit
async function submitAnswer(req, res, slug) {
  const user = requireAuth(req, res); if (!user) return;
  const lab  = db.prepare(`SELECT * FROM labs WHERE slug=?`).get(slug);
  if (!lab) return notFound(res, 'Lab not found');

  const body        = await parseBody(req);
  const { question_id, answer } = body;
  const questionId  = parseInt(question_id, 10);

  const idErr = requireInt(questionId, 'question_id', { min: 1 });
  if (idErr) return badRequest(res, idErr);
  if (!answer || !String(answer).trim()) return badRequest(res, 'answer is required');

  const question = db.prepare(
    `SELECT id, answer_type, correct_answer, points FROM questions WHERE id=? AND lab_id=?`
  ).get(questionId, lab.id);
  if (!question) return notFound(res, 'Question not found');

  const prior = db.prepare(
    `SELECT attempt_number, hints_used, is_correct, wrong_count, pts_awarded
     FROM user_answers WHERE user_id=? AND question_id=?`
  ).get(user.id, question.id);

  if (prior?.is_correct) {
    return ok(res, {
      correct: true, already_completed: true,
      pts: prior.pts_awarded || getHintPenalty(question.points, prior.hints_used || 0),
      hints_used: prior.hints_used || 0,
      total_score: getUserTotalScore(user.id),
      message: 'Question already completed.',
    });
  }

  const submitted    = String(answer).trim();
  const subLower     = submitted.toLowerCase();
  const correctLower = String(question.correct_answer || '').trim().toLowerCase();

  const isCorrect = question.answer_type === 'choice'
    ? subLower === correctLower
    : (() => {
        const keywords = correctLower.split(/\s+/).filter(w => w.length > 4);
        if (!keywords.length) return subLower === correctLower;
        const matched = keywords.filter(k => subLower.includes(k)).length;
        return matched >= Math.ceil(keywords.length * 0.35);
      })();

  const nextAttempt = (prior?.attempt_number || 0) + 1;
  const hintsUsed   = prior?.hints_used || 0;
  const wrongCount  = !isCorrect ? (prior?.wrong_count || 0) + 1 : (prior?.wrong_count || 0);
  const locked      = wrongCount >= 3 && hintsUsed === 0;
  const ptsAwarded  = isCorrect ? getHintPenalty(question.points, hintsUsed) : 0;
  const potentialPts = getWrongAttemptPenalty(getHintPenalty(question.points, hintsUsed), wrongCount);
  const now         = new Date().toISOString();

  // Wrap the save + progress update in one transaction
  db.transaction(() => {
    db.prepare(
      `INSERT INTO user_answers
         (user_id, lab_id, question_id, submitted_answer, is_correct, pts_awarded,
          hints_used, attempt_number, wrong_count, submitted_at)
       VALUES (?,?,?,?,?,?,?,?,?,?)
       ON CONFLICT(user_id, question_id) DO UPDATE SET
         submitted_answer=excluded.submitted_answer,
         is_correct=excluded.is_correct, pts_awarded=excluded.pts_awarded,
         hints_used=excluded.hints_used, attempt_number=excluded.attempt_number,
         wrong_count=excluded.wrong_count, submitted_at=excluded.submitted_at`
    ).run(user.id, lab.id, question.id, submitted, isCorrect ? 1 : 0,
          ptsAwarded, hintsUsed, nextAttempt, wrongCount, now);

    const totalQ = db.prepare(`SELECT COUNT(*) as c FROM questions WHERE lab_id=?`).get(lab.id).c;
    const doneQ  = db.prepare(
      `SELECT COUNT(*) as c FROM user_answers WHERE user_id=? AND lab_id=? AND is_correct=1`
    ).get(user.id, lab.id).c;
    const currentScore = db.prepare(
      `SELECT COALESCE(SUM(pts_awarded),0) as t FROM user_answers WHERE user_id=? AND lab_id=? AND is_correct=1`
    ).get(user.id, lab.id).t;
    const completed = doneQ >= totalQ && totalQ > 0;

    const existing = db.prepare(
      `SELECT id, started_at FROM user_progress WHERE user_id=? AND lab_id=?`
    ).get(user.id, lab.id);
    const startedAt = existing?.started_at || now;

    if (existing) {
      db.prepare(
        `UPDATE user_progress SET status=?, score=?, started_at=?, completed_at=? WHERE user_id=? AND lab_id=?`
      ).run(completed ? 'completed' : 'in_progress', currentScore, startedAt, completed ? now : null, user.id, lab.id);
    } else {
      db.prepare(
        `INSERT INTO user_progress (user_id, lab_id, status, score, started_at, completed_at) VALUES (?,?,?,?,?,?)`
      ).run(user.id, lab.id, completed ? 'completed' : 'in_progress', currentScore, startedAt, completed ? now : null);
    }
  })();

  const totalQ = db.prepare(`SELECT COUNT(*) as c FROM questions WHERE lab_id=?`).get(lab.id).c;
  const doneQ  = db.prepare(
    `SELECT COUNT(*) as c FROM user_answers WHERE user_id=? AND lab_id=? AND is_correct=1`
  ).get(user.id, lab.id).c;

  // ── Update streak on any attempt (attendance = any activity) ──────────
  const streakResult = updateStreak(user.id);

  // ── Award achievements on correct answer ─────────────────────────────
  let newAchievements = [];
  if (isCorrect) {
    newAchievements = checkAchievements(user.id);
    // Lab-level quality achievements when lab completes
    if (doneQ >= totalQ && totalQ > 0) {
      const labAchs = checkLabAchievements(user.id, lab.id);
      newAchievements = newAchievements.concat(labAchs);
    }
  }

  return ok(res, {
    correct: isCorrect, pts: ptsAwarded, hints_used: hintsUsed,
    streak: streakResult.current, streak_bonus: streakResult.bonus,
    attempts: nextAttempt, wrong_count: wrongCount,
    potential_points: potentialPts, locked,
    lab_status: doneQ >= totalQ && totalQ > 0 ? 'completed' : 'in_progress',
    completed_questions: doneQ, total_questions: totalQ,
    total_score: getUserTotalScore(user.id),
    new_achievements: newAchievements,
    message: isCorrect
      ? (doneQ >= totalQ && totalQ > 0 ? 'Lab completed!' : 'Correct. Move to the next question.')
      : (locked ? 'Maximum attempts reached. Request a hint to continue.' : 'Incorrect. Review the evidence and try again.'),
  });
}

// POST /api/labs/:slug/hint
async function requestHint(req, res, slug) {
  const user = requireAuth(req, res); if (!user) return;
  const lab  = db.prepare(`SELECT * FROM labs WHERE slug=?`).get(slug);
  if (!lab) return notFound(res, 'Lab not found');

  const { question_id } = await parseBody(req);
  const questionId = parseInt(question_id, 10);
  const err = requireInt(questionId, 'question_id', { min: 1 });
  if (err) return badRequest(res, err);

  const question = db.prepare(
    `SELECT id, points, correct_answer, hint, hint_levels, alert_ref FROM questions WHERE id=? AND lab_id=?`
  ).get(questionId, lab.id);
  if (!question) return notFound(res, 'Question not found');

  const current = db.prepare(
    `SELECT submitted_answer, is_correct, attempt_number, hints_used
     FROM user_answers WHERE user_id=? AND question_id=?`
  ).get(user.id, question.id);

  if (current?.is_correct) {
    return ok(res, { already_completed: true, hints_used: current.hints_used || 0, message: 'Already completed.' });
  }

  const plan          = getHintPlan(question);
  const currentHints  = current?.hints_used || 0;
  const nextIndex     = Math.min(currentHints, plan.length - 1);
  const nextHintsUsed = Math.min(currentHints + 1, plan.length);
  const now           = new Date().toISOString();

  db.prepare(
    `INSERT INTO user_answers
       (user_id, lab_id, question_id, submitted_answer, is_correct, pts_awarded,
        hints_used, attempt_number, submitted_at)
     VALUES (?,?,?,?,?,?,?,?,?)
     ON CONFLICT(user_id, question_id) DO UPDATE SET
       hints_used=excluded.hints_used,
       attempt_number=user_answers.attempt_number,
       submitted_at=excluded.submitted_at`
  ).run(user.id, lab.id, question.id, current?.submitted_answer || '',
        0, 0, nextHintsUsed, current?.attempt_number || 0, now);

  const existing = db.prepare(`SELECT started_at FROM user_progress WHERE user_id=? AND lab_id=?`).get(user.id, lab.id);
  if (existing) {
    db.prepare(`UPDATE user_progress SET status='in_progress', started_at=? WHERE user_id=? AND lab_id=?`)
      .run(existing.started_at || now, user.id, lab.id);
  } else {
    db.prepare(`INSERT INTO user_progress (user_id, lab_id, status, score, started_at) VALUES (?,?,?,?,?)`)
      .run(user.id, lab.id, 'in_progress', 0, now);
  }

  return ok(res, {
    hint_level: nextHintsUsed,
    max_hints:  plan.length,
    hint:       plan[nextIndex],
    message:    nextHintsUsed >= plan.length ? 'Maximum hints reached.' : 'Hint unlocked.',
  });
}

// POST /api/labs/:slug/reset
async function resetLab(req, res, slug) {
  const user = requireAuth(req, res); if (!user) return;
  const lab  = db.prepare(`SELECT * FROM labs WHERE slug=?`).get(slug);
  if (!lab) return notFound(res, 'Lab not found');

  db.transaction(() => {
    // Delete all answers for questions in this lab
    const qIds = db.prepare(`SELECT id FROM questions WHERE lab_id=?`).all(lab.id).map(q => q.id);
    if (qIds.length) {
      db.prepare(`DELETE FROM user_answers WHERE user_id=? AND question_id IN (${qIds.map(() => '?').join(',')})`)
        .run(user.id, ...qIds);
    }
    // Delete draft answers
    db.prepare(`DELETE FROM draft_answers WHERE user_id=? AND lab_id=?`).run(user.id, lab.id);
    // Delete progress
    db.prepare(`DELETE FROM user_progress WHERE user_id=? AND lab_id=?`).run(user.id, lab.id);
    // Delete notes (keep — user may want to keep them)
  })();

  return ok(res, { reset: true, message: 'Lab progress reset. You can start fresh.' });
}

module.exports = { listLabs, getLab, submitAnswer, requestHint, resetLab };
