'use strict';

const { requireAuth } = require('../middleware/auth');
const { ok }          = require('../middleware/response');
const { getUserAchievements } = require('../services/achievements');
const { getStreak }   = require('../services/streaks');

// GET /api/achievements
function listAchievements(req, res) {
  const user = requireAuth(req, res); if (!user) return;
  const achievements = getUserAchievements(user.id);
  const streak = getStreak(user.id);
  const earnedCount = achievements.filter(a => a.earned).length;
  const totalPoints = achievements.filter(a => a.earned).reduce((s, a) => s + a.points, 0);
  return ok(res, { achievements, earned_count: earnedCount, total: achievements.length, streak, bonus_points: totalPoints });
}

module.exports = { listAchievements };
