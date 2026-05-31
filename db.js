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
  const sessionSQL = `ALTER TABLE sessions ADD COLUMN created_at TEXT DEFAULT (datetime('now'))`;
  try { db.prepare(sessionSQL).run(); } catch (e) { /* already exists */ }
  const lastSeenSQL = `ALTER TABLE sessions ADD COLUMN last_seen_at TEXT DEFAULT (datetime('now'))`;
  try { db.prepare(lastSeenSQL).run(); } catch (e) { /* already exists */ }

  // Extended user profile fields
  const profileCols = [
    `ALTER TABLE users ADD COLUMN display_name    TEXT`,
    `ALTER TABLE users ADD COLUMN dob             TEXT`,
    `ALTER TABLE users ADD COLUMN institution     TEXT`,
    `ALTER TABLE users ADD COLUMN bio             TEXT`,
    `ALTER TABLE users ADD COLUMN profile_image   TEXT`,
    `ALTER TABLE users ADD COLUMN force_pw_change INTEGER DEFAULT 1`,
    `ALTER TABLE users ADD COLUMN email           TEXT`,
    `ALTER TABLE users ADD COLUMN extra_labs_bonus INTEGER DEFAULT 0`,
  ];
  for (const sql of profileCols) {
    try { db.prepare(sql).run(); } catch { /* already exists */ }
  }

  // Batch management
  db.prepare(`CREATE TABLE IF NOT EXISTS batch_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reset_by INTEGER NOT NULL,
    reset_at TEXT DEFAULT (datetime('now')),
    note     TEXT,
    users_affected INTEGER DEFAULT 0
  )`).run();

  // Bonus lab tracking
  db.prepare(`CREATE TABLE IF NOT EXISTS bonus_lab_completions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    lab_id  INTEGER NOT NULL,
    bonus_pts INTEGER DEFAULT 0,
    awarded_at TEXT DEFAULT (datetime('now')),
    UNIQUE(user_id, lab_id),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  )`).run();

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

  // ── Commercial platform tables ─────────────────────────────────────────
  db.prepare(`CREATE TABLE IF NOT EXISTS achievements (
    id          TEXT PRIMARY KEY,
    title       TEXT NOT NULL,
    description TEXT NOT NULL,
    icon        TEXT NOT NULL,
    points      INTEGER DEFAULT 0,
    category    TEXT DEFAULT 'general'
  )`).run();

  db.prepare(`CREATE TABLE IF NOT EXISTS user_achievements (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id        INTEGER NOT NULL,
    achievement_id TEXT NOT NULL,
    earned_at      TEXT DEFAULT (datetime('now')),
    UNIQUE(user_id, achievement_id),
    FOREIGN KEY(user_id)        REFERENCES users(id)        ON DELETE CASCADE,
    FOREIGN KEY(achievement_id) REFERENCES achievements(id) ON DELETE CASCADE
  )`).run();

  db.prepare(`CREATE TABLE IF NOT EXISTS lab_notes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    lab_id     INTEGER NOT NULL,
    content    TEXT NOT NULL DEFAULT '',
    updated_at TEXT DEFAULT (datetime('now')),
    UNIQUE(user_id, lab_id),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(lab_id)  REFERENCES labs(id)  ON DELETE CASCADE
  )`).run();

  db.prepare(`CREATE TABLE IF NOT EXISTS streaks (
    user_id          INTEGER PRIMARY KEY,
    current_streak   INTEGER DEFAULT 0,
    longest_streak   INTEGER DEFAULT 0,
    last_active_date TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  )`).run();

  db.prepare(`CREATE TABLE IF NOT EXISTS learning_paths (
    id               TEXT PRIMARY KEY,
    title            TEXT NOT NULL,
    description      TEXT NOT NULL,
    icon             TEXT DEFAULT '📚',
    difficulty       TEXT DEFAULT 'intermediate',
    estimated_hours  INTEGER DEFAULT 0,
    tags             TEXT DEFAULT '[]',
    lab_slugs        TEXT NOT NULL DEFAULT '[]',
    order_index      INTEGER DEFAULT 0
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
    // achievements
    `CREATE INDEX IF NOT EXISTS idx_user_achievements    ON user_achievements(user_id)`,
    // lab notes
    `CREATE INDEX IF NOT EXISTS idx_lab_notes_user       ON lab_notes(user_id)`,
    // streaks
    `CREATE INDEX IF NOT EXISTS idx_streaks_user         ON streaks(user_id)`,
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
