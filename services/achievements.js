'use strict';

// ── Achievement system ────────────────────────────────────────────────────
// Defines all 25 achievements and provides checkAchievements() which is
// called after every answer submission and alert closure to award badges.

const { db } = require('../db');
const { logger } = require('../middleware/logger');

// ── Achievement definitions ───────────────────────────────────────────────
const ACHIEVEMENTS = [
  // ── First steps
  { id: 'first_login',       title: 'Logged In',            desc: 'Welcome to DIAAS-SEC. Your SOC training begins now.', icon: '🔐', pts: 10,  cat: 'general' },
  { id: 'first_blood',       title: 'First Blood',          desc: 'Answered your first question correctly.',              icon: '🩸', pts: 25,  cat: 'general' },
  { id: 'first_lab',         title: 'Lab Rat',              desc: 'Completed your first lab.',                           icon: '🧪', pts: 50,  cat: 'general' },
  { id: 'first_alert',       title: 'Alert Analyst',        desc: 'Closed your first SOC alert.',                        icon: '🚨', pts: 30,  cat: 'soc' },

  // ── Lab completion milestones
  { id: 'labs_5',            title: 'Getting Started',      desc: 'Completed 5 labs.',                                   icon: '📚', pts: 75,  cat: 'labs' },
  { id: 'labs_10',           title: 'On a Roll',            desc: 'Completed 10 labs.',                                  icon: '🔥', pts: 100, cat: 'labs' },
  { id: 'labs_25',           title: 'Lab Veteran',          desc: 'Completed 25 labs.',                                  icon: '⚡', pts: 200, cat: 'labs' },
  { id: 'labs_all_stack2',   title: 'Stack 2 Complete',     desc: 'Completed all Stack 2 Technology Foundation labs.',   icon: '🏗️', pts: 300, cat: 'labs' },
  { id: 'labs_all_stack3',   title: 'SOC Analyst Certified',desc: 'Completed all Stack 3 Core SOC Skills labs.',         icon: '🎓', pts: 500, cat: 'labs' },

  // ── Score milestones
  { id: 'score_100',         title: 'Century',              desc: 'Earned 100 total points.',                            icon: '💯', pts: 0,   cat: 'score' },
  { id: 'score_500',         title: 'High Scorer',          desc: 'Earned 500 total points.',                            icon: '💰', pts: 0,   cat: 'score' },
  { id: 'score_1000',        title: 'Point Machine',        desc: 'Earned 1,000 total points.',                          icon: '🏆', pts: 0,   cat: 'score' },
  { id: 'score_2500',        title: 'Elite Analyst',        desc: 'Earned 2,500 total points.',                          icon: '💎', pts: 0,   cat: 'score' },

  // ── Quality / technique
  { id: 'no_hints_lab',      title: 'No Lifelines',         desc: 'Completed a full lab without using any hints.',       icon: '🧠', pts: 75,  cat: 'skill' },
  { id: 'perfect_lab',       title: 'Perfect Score',        desc: 'Completed a lab with maximum points (zero hints, zero wrong answers).', icon: '⭐', pts: 100, cat: 'skill' },
  { id: 'questions_50',      title: 'Question Crusher',     desc: 'Answered 50 questions correctly.',                    icon: '✅', pts: 100, cat: 'skill' },
  { id: 'questions_100',     title: 'Centurion',            desc: 'Answered 100 questions correctly.',                   icon: '🎯', pts: 200, cat: 'skill' },

  // ── SOC workflow
  { id: 'alerts_5',          title: 'Alert Ace',            desc: 'Correctly triaged 5 SOC alerts.',                     icon: '🔎', pts: 100, cat: 'soc' },
  { id: 'alerts_10',         title: 'Triage Master',        desc: 'Correctly triaged 10 SOC alerts.',                    icon: '🛡️', pts: 200, cat: 'soc' },
  { id: 'fp_finder',         title: 'False Positive Hunter',desc: 'Correctly identified 3 false positive alerts.',       icon: '🕵️', pts: 75,  cat: 'soc' },

  // ── Category specialists
  { id: 'windows_specialist',title: 'Windows Defender',     desc: 'Completed all Windows Security labs.',                icon: '🪟', pts: 150, cat: 'specialist' },
  { id: 'linux_specialist',  title: 'Linux Guardian',       desc: 'Completed all Linux Security labs.',                  icon: '🐧', pts: 150, cat: 'specialist' },
  { id: 'cloud_specialist',  title: 'Cloud Protector',      desc: 'Completed all Cloud Security labs.',                  icon: '☁️', pts: 150, cat: 'specialist' },
  { id: 'network_specialist',title: 'Network Sentinel',     desc: 'Completed all Network Security labs.',                icon: '🌐', pts: 150, cat: 'specialist' },

  // ── Streaks
  { id: 'streak_3',          title: 'Consistent',           desc: '3-day learning streak.',                              icon: '📅', pts: 30,  cat: 'streak' },
  { id: 'streak_7',          title: 'Dedicated',            desc: '7-day learning streak.',                              icon: '🗓️', pts: 75,  cat: 'streak' },
];

// ── Seed achievements into DB ─────────────────────────────────────────────
function seedAchievements() {
  const insert = db.prepare(
    `INSERT OR IGNORE INTO achievements (id, title, description, icon, points, category)
     VALUES (?,?,?,?,?,?)`
  );
  const tx = db.transaction(() => {
    for (const a of ACHIEVEMENTS) {
      insert.run(a.id, a.title, a.desc, a.icon, a.pts, a.cat);
    }
  });
  tx();
}

// ── Award an achievement ──────────────────────────────────────────────────
function award(userId, achievementId) {
  try {
    const exists = db.prepare(
      `SELECT id FROM user_achievements WHERE user_id=? AND achievement_id=?`
    ).get(userId, achievementId);
    if (exists) return null;

    db.prepare(
      `INSERT INTO user_achievements (user_id, achievement_id, earned_at)
       VALUES (?,?,?)`
    ).run(userId, achievementId, new Date().toISOString());

    const ach = ACHIEVEMENTS.find(a => a.id === achievementId);
    logger.info('achievement_earned', { userId, achievementId, title: ach?.title });
    return ach;
  } catch (e) {
    logger.error('achievement_award_error', { userId, achievementId, error: e.message });
    return null;
  }
}

// ── Check + award all applicable achievements ─────────────────────────────
// Called after every answer submit and alert close.
// Returns array of newly-earned achievement objects (may be empty).
function checkAchievements(userId) {
  const earned = [];

  const ea = id => {
    const a = award(userId, id);
    if (a) earned.push(a);
  };

  // ── Count stats once ──────────────────────────────────────────────────
  const labsDone = db.prepare(
    `SELECT COUNT(*) as c FROM user_progress WHERE user_id=? AND status='completed'`
  ).get(userId).c;

  const totalScore = db.prepare(
    `SELECT COALESCE(SUM(pts_awarded),0)+
            (SELECT COALESCE(SUM(points_awarded),0) FROM alert_closures WHERE user_id=? AND is_correct=1)
            as total FROM user_answers WHERE user_id=? AND is_correct=1`
  ).get(userId, userId).total;

  const questionsCorrect = db.prepare(
    `SELECT COUNT(*) as c FROM user_answers WHERE user_id=? AND is_correct=1`
  ).get(userId).c;

  const alertsCorrect = db.prepare(
    `SELECT COUNT(*) as c FROM alert_closures WHERE user_id=? AND is_correct=1`
  ).get(userId).c;

  const fpCorrect = db.prepare(
    `SELECT COUNT(*) as c FROM alert_closures WHERE user_id=? AND classification='false_positive' AND is_correct=1`
  ).get(userId).c;

  // ── First actions ────────────────────────────────────────────────────
  if (questionsCorrect >= 1) ea('first_blood');
  if (labsDone >= 1)         ea('first_lab');
  if (alertsCorrect >= 1)    ea('first_alert');

  // ── Lab milestones ───────────────────────────────────────────────────
  if (labsDone >= 5)  ea('labs_5');
  if (labsDone >= 10) ea('labs_10');
  if (labsDone >= 25) ea('labs_25');

  // ── Score milestones ─────────────────────────────────────────────────
  if (totalScore >= 100)  ea('score_100');
  if (totalScore >= 500)  ea('score_500');
  if (totalScore >= 1000) ea('score_1000');
  if (totalScore >= 2500) ea('score_2500');

  // ── Question milestones ──────────────────────────────────────────────
  if (questionsCorrect >= 50)  ea('questions_50');
  if (questionsCorrect >= 100) ea('questions_100');

  // ── Alert milestones ─────────────────────────────────────────────────
  if (alertsCorrect >= 5)  ea('alerts_5');
  if (alertsCorrect >= 10) ea('alerts_10');
  if (fpCorrect >= 3)      ea('fp_finder');

  // ── Stack completion ─────────────────────────────────────────────────
  const stack2Done = checkStackComplete(userId, 'Stack 2');
  const stack3Done = checkStackComplete(userId, 'Stack 3');
  if (stack2Done) ea('labs_all_stack2');
  if (stack3Done) ea('labs_all_stack3');

  // ── Category specialists ─────────────────────────────────────────────
  if (checkCategoryComplete(userId, 'Windows Security')) ea('windows_specialist');
  if (checkCategoryComplete(userId, 'Linux Security'))   ea('linux_specialist');
  if (checkCategoryComplete(userId, 'Cloud Security'))   ea('cloud_specialist');
  if (checkCategoryComplete(userId, 'Network Security')) ea('network_specialist');

  // ── Quality achievements checked per lab in routes/labs.js ───────────
  // (no_hints_lab, perfect_lab) — those need per-lab context

  return earned;
}

// ── Helper: check if all labs in a stack are completed ───────────────────
function checkStackComplete(userId, stackPrefix) {
  const stackLabs = db.prepare(
    `SELECT id FROM labs WHERE session_tag LIKE ? AND (is_visible=1 OR is_visible IS NULL)`
  ).all(`${stackPrefix}%`);
  if (!stackLabs.length) return false;
  const done = db.prepare(
    `SELECT COUNT(*) as c FROM user_progress WHERE user_id=? AND lab_id IN (${stackLabs.map(() => '?').join(',')}) AND status='completed'`
  ).get(userId, ...stackLabs.map(l => l.id)).c;
  return done >= stackLabs.length;
}

// ── Helper: check if all labs in a category are completed ────────────────
function checkCategoryComplete(userId, category) {
  const catLabs = db.prepare(
    `SELECT id FROM labs WHERE category=? AND (is_visible=1 OR is_visible IS NULL)`
  ).all(category);
  if (!catLabs.length) return false;
  const done = db.prepare(
    `SELECT COUNT(*) as c FROM user_progress WHERE user_id=? AND lab_id IN (${catLabs.map(() => '?').join(',')}) AND status='completed'`
  ).get(userId, ...catLabs.map(l => l.id)).c;
  return done >= catLabs.length;
}

// ── Check lab-specific quality achievements ───────────────────────────────
function checkLabAchievements(userId, labId) {
  const earned = [];

  // No-hints lab: completed with 0 hints across all questions
  const labQuestions = db.prepare(
    `SELECT id FROM questions WHERE lab_id=?`
  ).all(labId);
  if (labQuestions.length) {
    const qIds = labQuestions.map(q => q.id);
    const withHints = db.prepare(
      `SELECT COUNT(*) as c FROM user_answers
       WHERE user_id=? AND question_id IN (${qIds.map(() => '?').join(',')}) AND hints_used > 0`
    ).get(userId, ...qIds).c;
    const allCorrect = db.prepare(
      `SELECT COUNT(*) as c FROM user_answers
       WHERE user_id=? AND question_id IN (${qIds.map(() => '?').join(',')}) AND is_correct=1`
    ).get(userId, ...qIds).c;
    const completed = allCorrect >= labQuestions.length;

    if (completed && withHints === 0) {
      const a = award(userId, 'no_hints_lab');
      if (a) earned.push(a);
    }

    // Perfect lab: completed with 0 hints AND 0 wrong attempts
    if (completed && withHints === 0) {
      const withWrong = db.prepare(
        `SELECT COUNT(*) as c FROM user_answers
         WHERE user_id=? AND question_id IN (${qIds.map(() => '?').join(',')}) AND wrong_count > 0`
      ).get(userId, ...qIds).c;
      if (withWrong === 0) {
        const a = award(userId, 'perfect_lab');
        if (a) earned.push(a);
      }
    }
  }
  return earned;
}

// ── Get all achievements for a user ──────────────────────────────────────
function getUserAchievements(userId) {
  const earned = db.prepare(
    `SELECT achievement_id, earned_at FROM user_achievements WHERE user_id=? ORDER BY earned_at DESC`
  ).all(userId);
  const earnedMap = Object.fromEntries(earned.map(e => [e.achievement_id, e.earned_at]));

  return ACHIEVEMENTS.map(a => ({
    id:          a.id,
    title:       a.title,
    description: a.desc,
    icon:        a.icon,
    points:      a.pts,
    category:    a.cat,
    earned:      !!earnedMap[a.id],
    earned_at:   earnedMap[a.id] || null,
  }));
}

module.exports = { ACHIEVEMENTS, seedAchievements, checkAchievements, checkLabAchievements, getUserAchievements, award };
