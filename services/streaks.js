'use strict';

// ── Streak service ─────────────────────────────────────────────────────────
// Counts consecutive DAYS with any learning activity (right OR wrong answers,
// alert closures — anything that shows the student is working).
//
// Streak bonus: when a student extends their streak into a new day, they earn
// +5 attendance points automatically. This is the attendance incentive.

const { db }    = require('../db');
const { award } = require('./achievements');

const STREAK_BONUS_PTS = 5;

function updateStreak(userId) {
  // Use local date (not UTC) so midnight resets correctly for the server's timezone
  // Set TZ env variable on server to match your classroom timezone (e.g. Asia/Kolkata)
  const now = new Date();
  const localDate = new Date(now.getTime() - now.getTimezoneOffset() * 60000);
  const today = localDate.toISOString().slice(0, 10); // YYYY-MM-DD in server local time

  const row = db.prepare(
    `SELECT current_streak, longest_streak, last_active_date
     FROM streaks WHERE user_id=?`
  ).get(userId);

  let current  = row?.current_streak  || 0;
  let longest  = row?.longest_streak  || 0;
  const lastDate = row?.last_active_date;
  let isNew    = false;
  let bonus    = 0;

  if (lastDate === today) {
    // Already marked active today — return current state, no bonus
    return { current, longest, isNew: false, bonus: 0 };
  }

  const yesterdayLocal = new Date(now.getTime() - now.getTimezoneOffset() * 60000);
  yesterdayLocal.setDate(yesterdayLocal.getDate() - 1);
  const yStr = yesterdayLocal.toISOString().slice(0, 10);

  if (lastDate === yStr) {
    // Active yesterday — extend the streak
    current += 1;
    isNew    = true;
  } else {
    // First ever, or gap in activity — reset to 1
    current  = 1;
    isNew    = true;
  }

  longest = Math.max(longest, current);

  // Persist
  db.prepare(
    `INSERT INTO streaks (user_id, current_streak, longest_streak, last_active_date)
     VALUES (?,?,?,?)
     ON CONFLICT(user_id) DO UPDATE SET
       current_streak=excluded.current_streak,
       longest_streak=excluded.longest_streak,
       last_active_date=excluded.last_active_date`
  ).run(userId, current, longest, today);

  // Award streak attendance bonus
  if (isNew) {
    bonus = STREAK_BONUS_PTS;
    db.prepare(`UPDATE users SET points=COALESCE(points,0)+? WHERE id=?`).run(bonus, userId);
  }

  // Unlock streak achievements
  if (current >= 3) award(userId, 'streak_3');
  if (current >= 7) award(userId, 'streak_7');

  return { current, longest, isNew, bonus };
}

function getStreak(userId) {
  const row = db.prepare(
    `SELECT current_streak, longest_streak, last_active_date FROM streaks WHERE user_id=?`
  ).get(userId);
  if (!row) return { current: 0, longest: 0, last_active_date: null, active_today: false };
  const nowGet = new Date();
  const today = new Date(nowGet.getTime() - nowGet.getTimezoneOffset() * 60000).toISOString().slice(0, 10);
  return {
    current:          row.current_streak,
    longest:          row.longest_streak,
    last_active_date: row.last_active_date,
    active_today:     row.last_active_date === today,
  };
}

module.exports = { updateStreak, getStreak, STREAK_BONUS_PTS };
