-- DIAAS-SEC Platform Schema v2.1

CREATE TABLE IF NOT EXISTS users (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  username     TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role         TEXT NOT NULL DEFAULT 'analyst',
  is_active    INTEGER NOT NULL DEFAULT 1,
  created_at   TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL,
  token      TEXT UNIQUE NOT NULL,
  expires_at TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS labs (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  slug        TEXT UNIQUE NOT NULL,
  title       TEXT NOT NULL,
  description TEXT,
  difficulty  TEXT,
  category    TEXT,
  points      INTEGER DEFAULT 100,
  alert_refs  TEXT DEFAULT '[]',
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
  explanation    TEXT,
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
  attempt_number   INTEGER DEFAULT 1,
  submitted_at     TEXT DEFAULT (datetime('now')),
  UNIQUE(user_id, question_id),
  FOREIGN KEY(user_id)     REFERENCES users(id)     ON DELETE CASCADE,
  FOREIGN KEY(question_id) REFERENCES questions(id) ON DELETE CASCADE
);

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
