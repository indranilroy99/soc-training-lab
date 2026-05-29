'use strict';

// ── Lab services ─────────────────────────────────────────────────────────
// Batch queries: 4 queries to load all labs with progress instead of N*3+1.

const { db } = require('../db');

function getLabsWithProgress(userId) {
  // 1. All visible labs
  const labs = db.prepare(
    `SELECT * FROM labs WHERE is_visible=1 OR is_visible IS NULL ORDER BY order_index`
  ).all();

  // 2. This user's progress across all labs (one query)
  const progressRows = db.prepare(
    `SELECT lab_id, status, score, started_at, completed_at
     FROM user_progress WHERE user_id=?`
  ).all(userId);
  const progressMap = Object.fromEntries(progressRows.map(r => [r.lab_id, r]));

  // 3. Total question count per lab (one query)
  const totalQRows = db.prepare(
    `SELECT lab_id, COUNT(*) as c FROM questions GROUP BY lab_id`
  ).all();
  const totalQMap = Object.fromEntries(totalQRows.map(r => [r.lab_id, r.c]));

  // 4. Questions this user answered correctly per lab (one query)
  const doneQRows = db.prepare(
    `SELECT lab_id, COUNT(DISTINCT question_id) as c
     FROM user_answers WHERE user_id=? AND is_correct=1 GROUP BY lab_id`
  ).all(userId);
  const doneQMap = Object.fromEntries(doneQRows.map(r => [r.lab_id, r.c]));

  return labs.map(lab => {
    const prog = progressMap[lab.id];
    let alert_refs = [];
    let evidence   = [];
    try { alert_refs = lab.alert_refs ? JSON.parse(lab.alert_refs) : []; } catch {}
    try { evidence   = lab.evidence   ? JSON.parse(lab.evidence)   : []; } catch {}
    return {
      ...lab,
      alert_refs,
      evidence,
      status:          prog?.status        || 'not_started',
      score:           prog?.score         || 0,
      started_at:      prog?.started_at    || null,
      completed_at:    prog?.completed_at  || null,
      questions_total: totalQMap[lab.id]   || 0,
      questions_done:  doneQMap[lab.id]    || 0,
    };
  });
}

module.exports = { getLabsWithProgress };
