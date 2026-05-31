-- DIAAS-SEC Platform Schema v2.1

CREATE TABLE IF NOT EXISTS users (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  username     TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role         TEXT NOT NULL DEFAULT 'analyst',
  is_active    INTEGER NOT NULL DEFAULT 1,
  is_deleted   INTEGER NOT NULL DEFAULT 0,  -- Soft delete flag
  deleted_at   TEXT,                        -- When soft-deleted
  deleted_by   INTEGER,                     -- Admin who deleted
  points       INTEGER DEFAULT 0,
  last_lab_slug TEXT,                       -- Last lab user was viewing
  last_question_id INTEGER,                 -- Last question user was on
  last_active_at TEXT,                      -- Last activity timestamp
  created_at       TEXT DEFAULT (datetime('now')),
  display_name     TEXT,
  dob              TEXT,
  institution      TEXT,
  bio              TEXT,
  profile_image    TEXT,
  email            TEXT,
  force_pw_change  INTEGER DEFAULT 1,
  extra_labs_bonus INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id       INTEGER NOT NULL,
  token         TEXT UNIQUE NOT NULL,
  expires_at    TEXT NOT NULL,
  created_at    TEXT DEFAULT (datetime('now')),
  last_seen_at  TEXT DEFAULT (datetime('now')),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS labs (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  slug        TEXT UNIQUE NOT NULL,
  title       TEXT NOT NULL,
  lab_id      TEXT,
  session_tag TEXT,
  description TEXT,
  difficulty  TEXT,
  category    TEXT,
  points      INTEGER DEFAULT 100,
  alert_refs  TEXT DEFAULT '[]',
  evidence    TEXT,
  order_index INTEGER DEFAULT 0,
  is_visible  INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS questions (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  lab_id         INTEGER NOT NULL,
  order_index    INTEGER DEFAULT 0,
  points         INTEGER DEFAULT 20,
  difficulty     TEXT DEFAULT 'medium',
  answer_type    TEXT DEFAULT 'choice',
  question       TEXT NOT NULL,
  options        TEXT,
  correct_answer TEXT NOT NULL,
  hint           TEXT,
  hint_levels    TEXT,
  explanation    TEXT,
  alert_ref      TEXT,
  FOREIGN KEY(lab_id) REFERENCES labs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_progress (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id      INTEGER NOT NULL,
  lab_id       INTEGER NOT NULL,
  status       TEXT DEFAULT 'not_started',
  score        INTEGER DEFAULT 0,
  started_at   TEXT,
  completed_at TEXT,
  UNIQUE(user_id, lab_id),
  FOREIGN KEY(user_id)  REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(lab_id)   REFERENCES labs(id)  ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_answers (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id          INTEGER NOT NULL,
  lab_id           INTEGER NOT NULL,
  question_id      INTEGER NOT NULL,
  submitted_answer TEXT NOT NULL,
  is_correct       INTEGER DEFAULT 0,
  pts_awarded      INTEGER DEFAULT 0,
  hints_used       INTEGER DEFAULT 0,
  attempt_number   INTEGER DEFAULT 1,
  wrong_count      INTEGER DEFAULT 0,
  submitted_at     TEXT DEFAULT (datetime('now')),
  UNIQUE(user_id, question_id),
  FOREIGN KEY(user_id)     REFERENCES users(id)     ON DELETE CASCADE,
  FOREIGN KEY(question_id) REFERENCES questions(id) ON DELETE CASCADE
);

-- Draft answers for autosave (not yet submitted)
CREATE TABLE IF NOT EXISTS draft_answers (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id      INTEGER NOT NULL,
  lab_id       INTEGER NOT NULL,
  question_id  INTEGER NOT NULL,
  draft_answer TEXT NOT NULL,
  saved_at     TEXT DEFAULT (datetime('now')),
  UNIQUE(user_id, lab_id, question_id),
  FOREIGN KEY(user_id)     REFERENCES users(id)     ON DELETE CASCADE,
  FOREIGN KEY(lab_id)     REFERENCES labs(id)       ON DELETE CASCADE,
  FOREIGN KEY(question_id) REFERENCES questions(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_drafts_user ON draft_answers(user_id);
CREATE INDEX IF NOT EXISTS idx_drafts_lab ON draft_answers(lab_id);

CREATE TABLE IF NOT EXISTS leaderboard (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id        INTEGER UNIQUE NOT NULL,
  total_score    INTEGER DEFAULT 0,
  rank           INTEGER DEFAULT 0,
  labs_completed INTEGER DEFAULT 0,
  accuracy       REAL DEFAULT 0.0,
  last_updated   TEXT DEFAULT (datetime('now')),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS soc_alerts (
  id              TEXT PRIMARY KEY,
  severity        TEXT,
  category        TEXT,
  title           TEXT,
  source          TEXT,
  host            TEXT,
  src_ip          TEXT,
  dst_ip          TEXT,
  username        TEXT,
  process         TEXT,
  event_id        INTEGER,
  mitre_tactic    TEXT,
  mitre_technique TEXT,
  status          TEXT DEFAULT 'open',
  timestamp       TEXT,
  description     TEXT,
  raw_log         TEXT,
  iocs            TEXT,
  timeline        TEXT,
  network_flow    TEXT,
  recommendations TEXT
);

CREATE INDEX IF NOT EXISTS idx_sessions_token   ON sessions(token);
CREATE INDEX IF NOT EXISTS idx_progress_user    ON user_progress(user_id);
CREATE INDEX IF NOT EXISTS idx_answers_user_lab ON user_answers(user_id, lab_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity  ON soc_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_category  ON soc_alerts(category);
CREATE INDEX IF NOT EXISTS idx_alerts_status    ON soc_alerts(status);

CREATE TABLE IF NOT EXISTS escalations (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  alert_id     TEXT NOT NULL,
  user_id      INTEGER NOT NULL,
  level        TEXT NOT NULL DEFAULT 'L2',
  justification TEXT,
  status       TEXT DEFAULT 'pending',
  created_at   TEXT DEFAULT (datetime('now')),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(alert_id) REFERENCES soc_alerts(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_escalations_alert ON escalations(alert_id);
CREATE INDEX IF NOT EXISTS idx_escalations_user  ON escalations(user_id);

-- ── Incident Response Workflow ────────────────────────────────────
CREATE TABLE IF NOT EXISTS incidents (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  alert_id        TEXT NOT NULL,
  user_id         INTEGER NOT NULL,
  title           TEXT,
  stage           TEXT NOT NULL DEFAULT 'identification',
  containment_at  TEXT,
  eradication_at  TEXT,
  recovery_at     TEXT,
  rca_at          TEXT,
  closed_at       TEXT,
  notes           TEXT DEFAULT '{}',
  created_at      TEXT DEFAULT (datetime('now')),
  updated_at      TEXT DEFAULT (datetime('now')),
  FOREIGN KEY(user_id)  REFERENCES users(id)      ON DELETE CASCADE,
  FOREIGN KEY(alert_id) REFERENCES soc_alerts(id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_incidents_alert ON incidents(alert_id);
CREATE INDEX IF NOT EXISTS idx_incidents_stage ON incidents(stage);

-- ── Alert Closures (per-analyst triage decisions with IR steps) ──────────────
CREATE TABLE IF NOT EXISTS alert_closures (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  alert_id          TEXT NOT NULL,
  user_id           INTEGER NOT NULL,
  classification    TEXT NOT NULL,           -- 'closed' | 'false_positive'
  triage_reason     TEXT,                    -- why analyst thinks it's TP
  containment_steps TEXT,                    -- what containment was done
  eradication_steps TEXT,                    -- what eradication was done
  recovery_steps    TEXT,                    -- what recovery was done
  rca_notes         TEXT,                    -- root cause analysis
  fp_reason         TEXT,                    -- justification if FP
  is_correct        INTEGER DEFAULT 0,       -- 1 if classification matches ground truth
  points_awarded    INTEGER DEFAULT 0,
  closed_at         TEXT DEFAULT (datetime('now')),
  FOREIGN KEY(user_id)  REFERENCES users(id)      ON DELETE CASCADE,
  FOREIGN KEY(alert_id) REFERENCES soc_alerts(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_closures_user  ON alert_closures(user_id);
CREATE INDEX IF NOT EXISTS idx_closures_alert ON alert_closures(alert_id);

-- ── Alert Rubrics (per-alert, per-step scoring rubrics) ──────────
CREATE TABLE IF NOT EXISTS alert_rubrics (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  alert_id    TEXT NOT NULL UNIQUE,
  rubric_json TEXT NOT NULL,           -- full rubric as JSON
  created_at  TEXT DEFAULT (datetime('now')),
  FOREIGN KEY(alert_id) REFERENCES soc_alerts(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_rubrics_alert ON alert_rubrics(alert_id);

-- ── Deleted Users Archive (for restoring progress if needed) ──────────────────────
CREATE TABLE IF NOT EXISTS deleted_users_archive (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  original_user_id  INTEGER NOT NULL,
  username          TEXT NOT NULL,
  role              TEXT NOT NULL,
  total_score       INTEGER DEFAULT 0,
  labs_completed    INTEGER DEFAULT 0,
  progress_json     TEXT,                    -- Full user_progress snapshot
  answers_json      TEXT,                    -- Full user_answers snapshot
  deleted_at        TEXT DEFAULT (datetime('now')),
  deleted_by        INTEGER,
  restored_at       TEXT,                    -- If restored, when
  restored_to_user_id INTEGER,               -- New user ID if restored
  notes             TEXT                     -- Admin notes on deletion
);

CREATE INDEX IF NOT EXISTS idx_deleted_archive_user ON deleted_users_archive(original_user_id);
CREATE INDEX IF NOT EXISTS idx_deleted_archive_username ON deleted_users_archive(username);
