'use strict';

const { db }  = require('../db');
const cfg     = require('../config');
const { requireAuth } = require('../middleware/auth');
const { ok }          = require('../middleware/response');

// ── 10-second leaderboard cache ───────────────────────────────────────────
// 60 students refreshing simultaneously = 1 DB query, not 60.
let _lbCache   = null;
let _lbCacheTs = 0;

function invalidateLeaderboardCache() {
  _lbCache   = null;
  _lbCacheTs = 0;
}

// GET /api/leaderboard
function getLeaderboard(req, res) {
  const user = requireAuth(req, res); if (!user) return;
  const now  = Date.now();

  if (!_lbCache || (now - _lbCacheTs) > cfg.LB_CACHE_TTL_MS) {
    const rows = db.prepare(
      `SELECT u.id, u.username,
         COALESCE(lab.score,0) + COALESCE(closure.score,0) as score,
         COALESCE(lab.correct_answers,0) as correct_answers,
         COALESCE(progress.labs_done,0) as labs_done,
         COALESCE(lab.total_answers,0)  as total_answers
       FROM users u
       LEFT JOIN (
         SELECT user_id,
                SUM(CASE WHEN is_correct=1 THEN pts_awarded ELSE 0 END) as score,
                COUNT(DISTINCT CASE WHEN is_correct=1 THEN question_id END) as correct_answers,
                COUNT(DISTINCT question_id) as total_answers
         FROM user_answers GROUP BY user_id
       ) lab ON lab.user_id = u.id
       LEFT JOIN (
         SELECT user_id, SUM(points_awarded) as score
         FROM alert_closures WHERE is_correct=1 GROUP BY user_id
       ) closure ON closure.user_id = u.id
       LEFT JOIN (
         SELECT user_id, COUNT(DISTINCT lab_id) as labs_done
         FROM user_progress WHERE status='completed' GROUP BY user_id
       ) progress ON progress.user_id = u.id
       WHERE u.role='analyst' AND u.is_active=1
       ORDER BY score DESC, u.username ASC LIMIT 50`
    ).all();
    _lbCache   = rows;
    _lbCacheTs = now;
  }

  const board = _lbCache.map((r, i) => ({
    rank:            r.score > 0 ? i + 1 : 0,
    id:              r.id,
    username:        r.username,
    score:           r.score,
    labs_done:       r.labs_done,
    correct_answers: r.correct_answers,
    accuracy:        r.total_answers > 0 ? Math.round((r.correct_answers / r.total_answers) * 100) : 0,
    is_me:           r.id === user.id,
  }));
  return ok(res, board);
}

module.exports = { getLeaderboard, invalidateLeaderboardCache };
