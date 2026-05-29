'use strict';

// ── Database layer ────────────────────────────────────────────────────────
// Single source of truth for the DB connection, all migrations, and indexes.
// Import this module everywhere you need the DB — it is a singleton.

const Database = require('better-sqlite3');
const cfg      = require('./config');

const db = new Database(cfg.DB_PATH);
db.pragma('journal_mode = WAL');    // concurrent readers, fast writes
db.pragma('foreign_keys = ON');     // enforce referential integrity
db.pragma('synchronous = NORMAL');  // safe + fast (WAL makes full sync unnecessary)
db.pragma('cache_size = -32000');   // 32MB page cache — reduces disk I/O under load
db.pragma('temp_store = MEMORY');   // temp tables in RAM

// ── Schema migrations (idempotent — safe to run on every startup) ─────────
function runMigrations() {
  const cols = [
    [`ALTER TABLE labs ADD COLUMN is_visible INTEGER DEFAULT 1`,             'labs.is_visible'],
    [`ALTER TABLE labs ADD COLUMN evidence TEXT`,                             'labs.evidence'],
    [`ALTER TABLE labs ADD COLUMN lab_id TEXT`,                              'labs.lab_id'],
    [`ALTER TABLE labs ADD COLUMN session_tag TEXT`,                         'labs.session_tag'],
    [`ALTER TABLE questions ADD COLUMN alert_ref TEXT`,                      'questions.alert_ref'],
    [`ALTER TABLE questions ADD COLUMN hint_levels TEXT`,                    'questions.hint_levels'],
    [`ALTER TABLE user_answers ADD COLUMN hints_used INTEGER DEFAULT 0`,     'user_answers.hints_used'],
    [`ALTER TABLE user_answers ADD COLUMN wrong_count INTEGER DEFAULT 0`,    'user_answers.wrong_count'],
    [`ALTER TABLE user_answers ADD COLUMN submitted_answer TEXT`,            'user_answers.submitted_answer'],
    [`ALTER TABLE users ADD COLUMN points INTEGER DEFAULT 0`,                'users.points'],
  ];

  for (const [sql, label] of cols) {
    try { db.prepare(sql).run(); console.log(`[db:migrate] Added ${label}`); }
    catch { /* column already exists — ignore */ }
  }

  // Tables added after initial schema
  db.prepare(`CREATE TABLE IF NOT EXISTS alert_closures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    classification TEXT NOT NULL,
    triage_reason TEXT, containment_steps TEXT, eradication_steps TEXT,
    recovery_steps TEXT, rca_notes TEXT, fp_reason TEXT,
    is_correct INTEGER DEFAULT 0, points_awarded INTEGER DEFAULT 0,
    investigation_score INTEGER DEFAULT 0,
    step_scores TEXT DEFAULT '{}',
    scoring_feedback TEXT DEFAULT '[]',
    closed_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(user_id)  REFERENCES users(id)     ON DELETE CASCADE,
    FOREIGN KEY(alert_id) REFERENCES soc_alerts(id) ON DELETE CASCADE
  )`).run();

  const closureCols = [
    [`ALTER TABLE alert_closures ADD COLUMN investigation_score INTEGER DEFAULT 0`],
    [`ALTER TABLE alert_closures ADD COLUMN step_scores TEXT DEFAULT '{}'`],
    [`ALTER TABLE alert_closures ADD COLUMN scoring_feedback TEXT DEFAULT '[]'`],
    [`ALTER TABLE alert_rubrics ADD COLUMN created_at TEXT DEFAULT (datetime('now'))`],
  ];
  for (const [sql] of closureCols) {
    try { db.prepare(sql).run(); } catch { /* already exists */ }
  }

  db.prepare(`CREATE TABLE IF NOT EXISTS user_alert_state (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    alert_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    updated_at TEXT DEFAULT (datetime('now')),
    UNIQUE(user_id, alert_id),
    FOREIGN KEY(user_id)  REFERENCES users(id)     ON DELETE CASCADE,
    FOREIGN KEY(alert_id) REFERENCES soc_alerts(id) ON DELETE CASCADE
  )`).run();

  db.prepare(`CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    title TEXT,
    stage TEXT NOT NULL DEFAULT 'identification',
    containment_at TEXT, eradication_at TEXT, recovery_at TEXT, rca_at TEXT, closed_at TEXT,
    notes TEXT DEFAULT '{}',
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(user_id)  REFERENCES users(id)     ON DELETE CASCADE,
    FOREIGN KEY(alert_id) REFERENCES soc_alerts(id) ON DELETE CASCADE
  )`).run();
}

// ── Performance indexes (CREATE IF NOT EXISTS — idempotent) ───────────────
function ensureIndexes() {
  const indexes = [
    // sessions: looked up on every authenticated request
    `CREATE INDEX IF NOT EXISTS idx_sessions_token       ON sessions(token)`,
    `CREATE INDEX IF NOT EXISTS idx_sessions_user        ON sessions(user_id, expires_at)`,
    // user_answers: hot path for progress loading, leaderboard, scoring
    `CREATE INDEX IF NOT EXISTS idx_answers_user_correct ON user_answers(user_id, is_correct)`,
    `CREATE INDEX IF NOT EXISTS idx_answers_user_lab     ON user_answers(user_id, lab_id, is_correct)`,
    `CREATE INDEX IF NOT EXISTS idx_answers_question     ON user_answers(question_id)`,
    // user_progress: batch-loaded in labs service
    `CREATE INDEX IF NOT EXISTS idx_progress_user        ON user_progress(user_id)`,
    `CREATE INDEX IF NOT EXISTS idx_progress_lab_status  ON user_progress(lab_id, status)`,
    // questions: batch-counted in labs service
    `CREATE INDEX IF NOT EXISTS idx_questions_lab        ON questions(lab_id, order_index)`,
    // alert_closures: leaderboard and admin activity
    `CREATE INDEX IF NOT EXISTS idx_closures_user        ON alert_closures(user_id)`,
    `CREATE INDEX IF NOT EXISTS idx_closures_correct     ON alert_closures(user_id, is_correct)`,
    // soc_alerts: filter by severity/category
    `CREATE INDEX IF NOT EXISTS idx_alerts_severity      ON soc_alerts(severity)`,
    `CREATE INDEX IF NOT EXISTS idx_alerts_category      ON soc_alerts(category)`,
    // user_alert_state: per-user alert status lookups
    `CREATE INDEX IF NOT EXISTS idx_alert_state_user     ON user_alert_state(user_id)`,
  ];
  for (const sql of indexes) db.prepare(sql).run();
  console.log(`[db:indexes] ${indexes.length} indexes ensured`);
}

// ── Session cleanup (call from server startup) ────────────────────────────
function startSessionCleanup() {
  const cleanup = () => {
    const r = db.prepare(`DELETE FROM sessions WHERE expires_at < datetime('now')`).run();
    if (r.changes > 0) console.log(`[db:cleanup] Removed ${r.changes} expired sessions`);
  };
  cleanup();                        // run once immediately
  return setInterval(cleanup, 3600_000); // then every hour
}

// ── Health check ──────────────────────────────────────────────────────────
function healthCheck() {
  try {
    db.prepare(`SELECT 1`).get();
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

runMigrations();
ensureIndexes();

module.exports = { db, startSessionCleanup, healthCheck };
