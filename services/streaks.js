'use strict';

// ── Streak service ────────────────────────────────────────────────────────
// Tracks daily learning streaks. Called on every answer submit and alert close.

const { db }     = require('../db');
const { award }  = require('./achievements');

// ── Update streak for a user ──────────────────────────────────────────────
// Call after any learning activity. Returns { current, longest, isNew }.
function updateStreak(userId) {
  const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD

  const row = db.prepare(
    `SELECT current_streak, longest_streak, last_active_date
     FROM streaks WHERE user_id=?`
  ).get(userId);

  let current = row?.current_streak || 0;
  let longest = row?.longest_streak || 0;
  const lastDate = row?.last_active_date;
  let isNew = false;

  if (lastDate === today) {
    // Already active today — no change
    return { current, longest, isNew: false };
  }

  const yesterday = new Date();
  yesterday.setDate(yesterday.getDate() - 1);
  const yStr = yesterday.toISOString().slice(0, 10);

  if (lastDate === yStr) {
    // Active yesterday — extend streak
    current += 1;
    isNew = true;
  } else if (!lastDate) {
    // First ever activity
    current = 1;
    isNew = true;
  } else {
    // Gap — reset streak
    current = 1;
    isNew = true;
  }

  longest = Math.max(longest, current);

  db.prepare(
    `INSERT INTO streaks (user_id, current_streak, longest_streak, last_active_date)
     VALUES (?,?,?,?)
     ON CONFLICT(user_id) DO UPDATE SET
       current_streak=excluded.current_streak,
       longest_streak=excluded.longest_streak,
       last_active_date=excluded.last_active_date`
  ).run(userId, current, longest, today);

  // Check streak achievements
  if (current >= 3) award(userId, 'streak_3');
  if (current >= 7) award(userId, 'streak_7');

  return { current, longest, isNew };
}

// ── Get streak for a user ─────────────────────────────────────────────────
function getStreak(userId) {
  const row = db.prepare(
    `SELECT current_streak, longest_streak, last_active_date FROM streaks WHERE user_id=?`
  ).get(userId);
  if (!row) return { current: 0, longest: 0, last_active_date: null, active_today: false };

  const today = new Date().toISOString().slice(0, 10);
  return {
    current:          row.current_streak,
    longest:          row.longest_streak,
    last_active_date: row.last_active_date,
    active_today:     row.last_active_date === today,
  };
}

module.exports = { updateStreak, getStreak };
