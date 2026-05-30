# DIAAS-SEC — Security Operations Centre Training Platform

A self-hosted SOC analyst training platform built for classroom deployment. Analysts complete hands-on labs, answer investigation questions tied to real alert evidence, and close alerts through a structured 5-step Incident Response workflow. Every answer is scored — filler text earns nothing. Admins see a full per-student profiling dashboard.

No cloud. No Docker. No external dependencies beyond Node.js.

---

## Platform Overview

- **85+ hands-on labs** across 4 stacks — Stack 2 (Technology Foundations), Stack 3 (Core SOC Skills), Stack 4 (Advanced), Stack Plus (Elite)
- **200+ training alerts** — raw logs, IOCs, timelines, MITRE ATT&CK mappings, per-severity triage
- **5-step IR workflow** — Triage (5W+H) → Containment → Eradication → Recovery → Root Cause Analysis
- **Rubric-based scoring** — IR answers scored against keyword-concept rubrics built from actual alert fields
- **25-badge achievement system** — 7 categories: First Steps, Lab Completion, Score, Skill, SOC Workflow, Specialist, Consistency
- **Daily streak tracking** — +5 attendance bonus points per new streak day
- **Weighted Performance Score (0–100)** — 4-pillar evaluation: Lab Accuracy 40% + Alert Quality 30% + Efficiency 20% + Coverage 10%
- **Admin analyst profiling** — per-student drill-down: every question result, time per lab, stuck points, category weaknesses, full activity feed
- **Cluster mode** — multi-worker Node.js, auto-restart on crash
- **Security hardened** — 8 HTTP security headers, rate limiting, input validation, constant-time auth

---

## Requirements

| Requirement | Version |
|-------------|---------|
| Node.js | 18 or higher |
| npm | comes with Node |
| git | any recent version |
| OS | macOS, Ubuntu, Debian, RHEL/CentOS |

---

## Install

```bash
# One-command installer
curl -fsSL https://raw.githubusercontent.com/indranilroy99/soc-training-lab/main/install.sh | bash

# Or manually
git clone https://github.com/indranilroy99/soc-training-lab ~/diaas-sec
cd ~/diaas-sec
npm install
node database/seed.js
node server.js
```

The installer: checks for Node.js, clones the repo, runs `npm install`, seeds the database, registers a background service (launchd on Mac, systemd on Linux).

---

## Default Credentials

| Role | Username | Password |
|------|----------|----------|
| Admin | `admin` | `Admin@2024` |
| Analyst | `analyst_01` to `analyst_10` | `Analyst@2024` |

**Change all passwords before sharing with students.** Admin → Manage Users → Reset PW.

---

## Access

```
http://<server-ip>:3000          ← login page
http://<server-ip>:3000/analyst  ← analyst dashboard
http://<server-ip>:3000/admin    ← admin panel
http://<server-ip>:3000/health   ← health check (returns JSON)
```

To find your server's IP: `ipconfig getifaddr en0` (macOS) or `hostname -I` (Linux).

---

## Start / Stop / Update

**macOS (launchd)**
```bash
launchctl load   ~/Library/LaunchAgents/com.diaas-sec.plist
launchctl unload ~/Library/LaunchAgents/com.diaas-sec.plist
tail -f ~/diaas-sec/logs/server.log
```

**Linux (systemd)**
```bash
sudo systemctl start  diaas-sec
sudo systemctl stop   diaas-sec
sudo systemctl status diaas-sec
journalctl -u diaas-sec -f
```

**Manual**
```bash
cd ~/diaas-sec
nohup node server.js >> logs/server.log 2>&1 &
tail -f logs/server.log
```

**Update to latest**
```bash
cd ~/diaas-sec
git pull origin main
npm install
kill $(lsof -ti:3000) 2>/dev/null; sleep 1
nohup node server.js >> logs/server.log 2>&1 &
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | HTTP port |
| `HOST` | `0.0.0.0` | Bind address |
| `DB_PATH` | `database/diaas.db` | SQLite database path |
| `NODE_ENV` | — | Set to `production` to suppress stack traces in logs |

---

## Project Structure

```
diaas-sec/
│
├── server.js           ← Cluster entry point only (41 lines). Forks workers.
├── app.js              ← HTTP server, middleware chain, graceful shutdown
├── config.js           ← All constants (ports, TTLs, rate limits, security headers)
├── db.js               ← DB connection, all migrations, 13 performance indexes
│
├── middleware/
│   ├── auth.js         ← requireAuth(), requireAdmin()
│   ├── logger.js       ← Structured JSON request + error logging
│   ├── rateLimit.js    ← Per-IP sliding window (API routes + submit endpoint)
│   ├── response.js     ← ok(), created(), notFound(), badRequest() helpers
│   ├── security.js     ← 8 security headers, CORS, body size limit, request ID
│   └── validate.js     ← Input validation and sanitisation
│
├── routes/
│   ├── index.js        ← Central URL dispatcher — all routes in one place
│   ├── auth.js         ← POST /api/auth/login|logout
│   ├── user.js         ← GET /api/me, /api/me/closures, POST /api/user/password
│   ├── labs.js         ← Labs, submit, hint, reset
│   ├── alerts.js       ← SOC alerts, IR workflow, escalation
│   ├── leaderboard.js  ← Leaderboard with 10-second cache
│   ├── achievements.js ← GET /api/achievements
│   ├── notes.js        ← GET/PUT /api/labs/:slug/notes
│   ├── performance.js  ← GET /api/me/performance, /api/admin/performance/all
│   └── admin.js        ← All /api/admin/* routes
│
├── services/
│   ├── scoring.js          ← Rubric IR scoring engine
│   ├── scoring_weighted.js ← Weighted Performance Score (0–100, 4 pillars)
│   ├── analyst_profile.js  ← Full per-student profiling (all activity, weak areas)
│   ├── labs.js             ← getLabsWithProgress() — 4 batch queries
│   ├── users.js            ← Scores, ranks, hint helpers, alert state
│   ├── achievements.js     ← 25 achievement definitions + award engine
│   └── streaks.js          ← Daily streak tracking + attendance bonus
│
├── database/
│   ├── schema.sql      ← All table definitions
│   ├── seed.js         ← Populates DB: users, labs, questions, alerts, rubrics
│   └── diaas.db        ← SQLite file (created by seed.js, gitignored)
│
└── public/
    ├── login.html           ← Login page
    ├── analyst/index.html   ← Analyst dashboard (single-page app)
    └── admin/index.html     ← Admin dashboard (single-page app)
```

**Files you will edit most often:**
- `database/seed.js` — add labs, alerts, questions, rubrics
- `routes/` — add or modify API endpoints
- `public/analyst/index.html` — analyst-facing UI
- `public/admin/index.html` — admin-facing UI

---

## How It Works

### Analyst workflow

```
Login → Analyst Dashboard
   │
   ├── My Labs
   │     └── Select lab → view description + evidence
   │           → Answer questions (MCQ or text)
   │           → Request hints (−5 pts / −10 pts per hint)
   │           → Wrong attempt penalty (−3 pts per retry, up to 3 retries)
   │           → Lab Notes — autosaved per-lab notepad
   │
   ├── SOC Dashboard
   │     └── Browse alerts → filter by severity / category / status
   │           → Click alert → raw log, IOCs, timeline, MITRE mapping
   │           │
   │           ├── [Close as Resolved] → 5-step IR modal
   │           │     Step 1: Triage (5W+H — Who/What/When/Where/Why/How)
   │           │     Step 2: Containment steps
   │           │     Step 3: Eradication steps
   │           │     Step 4: Recovery steps
   │           │     Step 5: Root Cause Analysis
   │           │     15 words minimum per step. Scored against rubric. 1–5 pts.
   │           │
   │           └── [False Positive] → written justification required. 3 pts if correct.
   │
   ├── Achievements  — 25 badges across 7 categories, unlocked automatically
   ├── Leaderboard   — live rankings by raw score
   └── My Profile    — stats + weighted performance breakdown (DPS 0–100)
```

### Admin workflow

```
Login → Admin Dashboard
   │
   ├── Overview      — class stats, top performers, lab completion rates
   ├── Manage Users  — create / enable / disable / reset analyst accounts
   ├── Progress      — completion matrix: every analyst × every lab
   ├── Performance   — weighted DPS table: all students with 4-pillar breakdown
   ├── Labs          — view, create, edit, delete labs and questions
   ├── Leaderboard   — ranked scores
   └── Click any analyst → Full Profile
         ├── Overview tab: grade, DPS, performance pillars, category weaknesses,
         │                 stuck questions (repeated wrong attempts)
         ├── Labs tab:     every lab attempted — score, time spent, per-question
         │                 result (correct/wrong count/hints/pts earned)
         ├── Alert Triage: every alert closed — severity, classification, IR score
         └── Activity Feed: chronological last-50 events with timestamps
```

---

## Points System

### Lab questions

| Outcome | Points |
|---------|--------|
| Correct, first attempt, no hints | Full points |
| Hint 1 used | −5 pts |
| Hint 2 used | −10 pts (cumulative) |
| Wrong attempt penalty | −3 pts per wrong attempt (max 3 retries) |
| After 3 wrong attempts | Submit locked until a hint is used |

### Alert triage

| Outcome | Points |
|---------|--------|
| Correct TP closure, IR score 90–100% | 5 pts |
| Correct TP closure, IR score 75–89% | 4 pts |
| Correct TP closure, IR score 60–74% | 3 pts |
| Correct TP closure, IR score 40–59% | 2 pts |
| Correct TP closure, IR score 0–39% | 1 pt |
| Correct FP classification | 3 pts |
| Wrong classification | 0 pts |

### Attendance streak

| Outcome | Points |
|---------|--------|
| First activity of a new consecutive day | +5 pts attendance bonus |

The streak counter increments on any activity (right or wrong answers, alert work). Miss a day and it resets to 1 on your next session.

---

## Weighted Performance Score (DPS)

Every analyst has a **DPS (0–100)** alongside their raw points. It rewards quality over quantity — a student who answers 5 labs perfectly outscores one who does 50 sloppily.

| Pillar | Weight | How it's calculated |
|--------|--------|---------------------|
| Lab Accuracy | 40% | Points earned / points possible on all attempted questions |
| Alert Quality | 30% | Correct closures (60%) + average IR report depth score (40%) |
| Efficiency | 20% | Questions answered correctly with zero hints and zero retries |
| Coverage | 10% | % of labs completed + % of alerts engaged with |

**Letter grade:** A+ ≥ 90, A ≥ 80, B ≥ 70, C ≥ 60, D ≥ 50, F below 50.

Visible to analysts on their Profile page. Visible to admins on the Performance page and per-analyst profile.

---

## IR Scoring Engine

The rubric engine lives in `services/scoring.js`.

1. Each of the 5 IR steps has a maximum of 10 points
2. Each step has concept buckets — a set of keywords and a point value
3. If any keyword in a bucket is found in the analyst's answer, those points are awarded
4. A step needs at least **15 words** to score anything
5. Investigation score = (earned / possible) × 100
6. If no rubric exists for an alert, scoring falls back to total word count depth

Points awarded: 5 pts for score ≥ 90%, 4 pts for ≥ 75%, 3 pts for ≥ 60%, 2 pts for ≥ 40%, 1 pt otherwise.

---

## Database Tables

Base tables are in `database/schema.sql`. Additional tables and columns are added automatically via idempotent migrations in `db.js` on every server start.

| Table | What it stores |
|-------|----------------|
| `users` | All accounts (analysts + admins). Includes `points`, `is_active`. |
| `sessions` | Auth tokens. 24-hour TTL. Includes `created_at` for login history. |
| `labs` | Lab metadata — title, slug, category, difficulty, alert references, evidence. |
| `questions` | Questions linked to a lab. Includes `correct_answer`, `options`, `hint`, `points`. |
| `user_progress` | One row per user per lab — status, score, `started_at`, `completed_at`. |
| `user_answers` | Every answer submitted — correct, pts_awarded, hints_used, wrong_count, submitted_at. |
| `draft_answers` | Autosaved in-progress answers before submission. |
| `soc_alerts` | All training alerts — raw_log, iocs, timeline, MITRE fields, severity. |
| `alert_closures` | Every IR close — all 5 step answers, classification, investigation_score, step_scores (JSON), scoring_feedback (JSON), points. |
| `alert_rubrics` | Per-alert scoring rubrics. JSON blob, queried by `scoreIRAnswers()`. |
| `user_alert_state` | Per-user alert status (open / investigating / closed / false_positive). |
| `incidents` | Incident records tracking IR stage progression. |
| `escalations` | Alert escalation history (L2/L3). |
| `achievements` | Achievement definitions (25 rows, seeded at startup). |
| `user_achievements` | Which analysts have earned which badges, with timestamps. |
| `lab_notes` | Per-user per-lab investigation notes. Autosaved from the analyst UI. |
| `streaks` | Daily streak tracking per user — current, longest, last_active_date. |

---

## Security

The following headers are set on every response:

| Header | Value |
|--------|-------|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `X-XSS-Protection` | `1; mode=block` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | camera, mic, geolocation, payment all disabled |
| `Content-Security-Policy` | scripts/styles/fonts restricted to same origin + Google Fonts |
| `Cache-Control` | `no-store` on all API responses |

Additional measures:
- CORS restricted to localhost and RFC1918 private IPs (LAN deployment only)
- Per-IP rate limiting: 300 req/min on all API routes, 30/min on answer submission
- Input validation and null-byte sanitisation on all routes
- Constant-time password comparison (prevents timing attacks)
- Structured JSON error logging (stack traces never sent to clients in production)
- Graceful shutdown on SIGTERM/SIGINT — no DB corruption on restart
- Workers auto-restart on crash (cluster mode)

---

## API Routes

Every route except `/health`, `/`, `/login`, `/analyst`, `/admin` requires `Authorization: Bearer <token>`.

### Auth
| Method | Route | Description |
|--------|-------|-------------|
| POST | `/api/auth/login` | Login. Returns session token + user object. |
| POST | `/api/auth/logout` | Invalidates session token. |

### Analyst
| Method | Route | Description |
|--------|-------|-------------|
| GET | `/api/me` | Current user's stats, score, rank, streak. |
| GET | `/api/me/closures` | All alert closes submitted by this user. |
| GET | `/api/me/performance` | Weighted DPS score + 4-pillar breakdown. |
| GET | `/api/labs` | All visible labs with user progress (batch queries). |
| GET | `/api/labs/:slug` | Lab detail — questions, evidence, progress. |
| POST | `/api/labs/:slug/submit` | Submit an answer. Returns correct/wrong + achievements. |
| POST | `/api/labs/:slug/hint` | Request a hint. Deducts from potential points. |
| POST | `/api/labs/:slug/reset` | Reset progress on a lab. |
| GET | `/api/labs/:slug/notes` | Get autosaved lab notes. |
| PUT | `/api/labs/:slug/notes` | Save lab notes (max 10,000 chars). |
| GET | `/api/achievements` | All 25 achievements with earned status + streak info. |
| GET | `/api/leaderboard` | All analysts ranked by score (10-second cache). |
| GET | `/api/alerts` | All alerts — filter by severity, category, status, search. |
| GET | `/api/alerts/:id` | Single alert — raw log, IOCs, timeline, MITRE. |
| POST | `/api/alerts/:id/status` | Close as TP (resolved) or FP. Triggers rubric scoring. |
| GET | `/api/alerts/:id/incident` | Fetch incident record. |
| POST | `/api/alerts/:id/incident` | Create or update incident record. |
| POST | `/api/alerts/:id/escalate` | Escalate to L2/L3. |
| GET | `/api/alerts/:id/escalations` | Escalation history. |
| POST | `/api/user/password` | Change own password. Invalidates all sessions. |

### Admin (admin role required)
| Method | Route | Description |
|--------|-------|-------------|
| GET | `/api/admin/stats` | Platform-wide stats. |
| GET | `/api/admin/users` | All analysts with score + labs + last session. |
| POST | `/api/admin/users` | Create analyst account. |
| PUT | `/api/admin/users/:id` | Update account (active status, password reset). |
| DELETE | `/api/admin/users/:id` | Delete account. |
| GET | `/api/admin/progress` | Lab completion matrix — all users × all labs. |
| GET | `/api/admin/performance/all` | Weighted DPS scores for all students. |
| GET | `/api/admin/labs` | All labs with question count + completion stats. |
| POST | `/api/admin/labs` | Create a lab. |
| PUT | `/api/admin/labs/:id` | Update lab metadata. |
| DELETE | `/api/admin/labs/:id` | Delete lab. |
| GET | `/api/admin/labs/:id/questions` | All questions for a lab. |
| POST | `/api/admin/labs/:id/questions` | Add a question. |
| PUT | `/api/admin/questions/:id` | Edit a question. |
| DELETE | `/api/admin/questions/:id` | Delete a question. |
| GET | `/api/admin/analysts/:id/activity` | Alert triage history for one analyst. |
| GET | `/api/admin/analysts/:id/profile` | Full analyst profile — labs, questions, weak areas, activity. |

### Monitoring
| Method | Route | Description |
|--------|-------|-------------|
| GET | `/health` | Returns `{"ok":true,"pid":...}`. No auth required. |

---

## Making Changes

### Add a new lab or question
Edit `database/seed.js`. Add to the labs array (title, slug, category, difficulty, points, description, evidence, alert_refs) and to the questions array. Then reseed:
```bash
node database/seed.js
```

### Add a new API route
Create or edit a file in `routes/`. Then register it in `routes/index.js`:
```javascript
// In routes/index.js
if (method === 'GET' && url === '/api/your-route') {
  return yourRouteHandler(req, res);
}
```
Route handlers follow this pattern:
```javascript
// In routes/something.js
const { requireAuth } = require('../middleware/auth');
const { ok, badRequest } = require('../middleware/response');
const { parseBody } = require('../middleware/security');

async function myHandler(req, res) {
  const user = requireAuth(req, res); if (!user) return;
  const body = await parseBody(req);
  return ok(res, { result: 'done' });
}
module.exports = { myHandler };
```

### Change the UI
- Analyst view → `public/analyst/index.html`
- Admin view → `public/admin/index.html`
- Login page → `public/login.html`

All three are self-contained single-page apps — CSS in `<style>`, JS in `<script>`. No build step, no bundler.

### Add a rubric for an alert
Edit the rubrics array in `database/seed.js`. Copy an existing entry, update `alert_id`, `required_keywords`, and `steps` concept buckets. Reseed with `node database/seed.js`.

---

## Re-seed the Database

To reset all progress and start fresh:
```bash
cd ~/diaas-sec
rm database/diaas.db
node database/seed.js
```

This recreates all default users, labs, questions, alerts, and rubrics. All analyst progress is wiped.

---

## Add Users Without the Admin Panel

```bash
node -e "
const db = require('better-sqlite3')('database/diaas.db');
const bcrypt = require('bcryptjs');
const hash = bcrypt.hashSync('Password@123', 10);
db.prepare('INSERT INTO users (username, password_hash, role) VALUES (?,?,?)').run('analyst_11', hash, 'analyst');
console.log('Done');
"
```

---

## Troubleshooting

### Server won't start

```bash
# Check what's on port 3000
lsof -i :3000

# Kill it
kill $(lsof -ti:3000)

# Check logs
tail -50 logs/server.log
```

Common causes:
- `Cannot find module 'better-sqlite3'` → run `npm install`
- `SQLITE_CANTOPEN` → run `node database/seed.js` first
- Port already in use → kill the existing process

### Database errors after update

If you see `table X has no column named Y`, the DB is out of date. The server runs idempotent `ALTER TABLE` migrations automatically on startup — restart usually fixes it. If not:

```bash
rm database/diaas.db && node database/seed.js
```

### Analyst scores not showing

Check that the `streaks` and `user_achievements` tables exist:
```bash
sqlite3 database/diaas.db ".tables"
```

If missing, the migrations in `db.js` create them on next startup. Just restart the server.

### Performance score shows 0

The DPS requires at least one lab answer or alert closure. It returns 0 if no activity exists — this is correct. Once the student submits their first answer, the score populates.

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Runtime | Node.js 18+, built-in `http` module (no Express) |
| Database | SQLite via `better-sqlite3` (WAL mode, 32MB cache) |
| Auth | bcryptjs hashing, crypto.randomBytes session tokens |
| Frontend | Vanilla HTML/CSS/JS — no frameworks, no build step |
| Concurrency | Node.js `cluster` — (CPUs − 2) workers, min 2, max 6 |
| Service manager | launchd (macOS) / systemd (Linux) |

---

## Changelog

| Commit | What changed |
|--------|--------------|
| `b3e8ef5` | Admin analyst profiling: full profile with 4 tabs (overview, labs per-question, alert triage, activity feed). Category weakness detection. Stuck question tracking. Time-per-lab. |
| `620fa69` | Fixed sequential question locking (all questions now accessible). Streaks now award +5 pts attendance bonus per new day. Streak updates on any attempt (not just correct). |
| `fc53840` | Weighted Performance Score (DPS 0–100). Letter grades. Admin Performance page with breakdown per student. Emojis removed from UI. Learning Paths removed. |
| `69311df` | Fixed lab view left-gap bug. `position:fixed` layout for lab view. Removed `height:100vh` conflict. |
| `b9033f5` | Fixed `ok()` response helper spreading arrays. Fixed 7 missing admin routes (404s). Fixed `/api/me/drafts` stub. |
| `475b1bb` | Achievements page, XP/level system, streak widget, lab notes autosave, achievement popups live in analyst UI. |
| `4a5433d` | Achievements backend (25 badges, 7 categories). Streak service. Lab notes API. Lab reset endpoint. |
| `a8b89e2` | Full modular refactor: server.js 1785 → 41 lines. 8 security headers. Rate limiting all routes. Input validation. Structured logging. Graceful shutdown. Cluster mode. |
| `0bccf04` | Performance: 697 queries → 4 on lab load (174× faster). 13 DB indexes. Leaderboard cache. |
| `8151367` | 100 new questions across 19 Stack 2 labs. |
| `b19ac36` | v2.0.0 — full platform rebuild: Node.js + SQLite, analyst SPA, admin panel, labs, alerts, IR workflow. |
