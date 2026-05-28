# DIAAS-SEC — Security Operations Training Platform

A hands-on SOC analyst training platform. Analysts work through real-world alert scenarios, answer investigation questions, and close alerts using a structured 5-step Incident Response workflow. Every answer is scored against a rubric built from actual alert evidence — writing filler text does not earn points.

**Current commit:** `e2a6ffb`

---

## Quick Start — Run This First

Copy and paste this entire block into your terminal. It checks every dependency, installs anything missing, seeds the database, and starts the server.

```bash
# 1. Check Node.js version (need 18 or higher)
node -v
# If missing or below 18: https://nodejs.org/en/download

# 2. Go into the project folder
cd /var/www/diaas-sec

# 3. Install dependencies
npm install

# 4. Seed the database (creates diaas.db, loads all alerts, labs, rubrics)
node database/seed.js

# 5. Start the server
nohup node server.js > /tmp/diaas.log 2>&1 &

# 6. Confirm it is running
curl -s http://localhost:3000 | head -5
```

The app will be at **http://localhost:3000** (or your server IP).

---

## Deploy to a Live Server (Ubuntu + Apache)

If you are deploying on the `tyrell@system` Ubuntu server with Apache:

```bash
# SSH into the server
ssh tyrell@system

# Pull the latest code
cd /var/www/diaas-sec && git pull origin main

# Install/update dependencies
npm install

# Seed the database (safe to re-run — uses INSERT OR REPLACE)
node database/seed.js

# Stop any running instance and restart
kill $(lsof -ti:3000) 2>/dev/null; sleep 1
nohup node server.js > /tmp/diaas.log 2>&1 &

# Check the log to confirm it started
tail -20 /tmp/diaas.log
```

Apache proxies port 80 → 3000. No Apache config changes needed on redeploy.

**When you MUST reseed** (run `node database/seed.js` again):
- Any time labs, alerts, questions, or rubrics change in seed.js
- First deploy on a new machine
- If you delete diaas.db and want a fresh start

**When you do NOT need to reseed:**
- Bug fixes, styling changes, server-side logic changes
- Just `git pull` and restart the server

---

## Default Login Credentials

| Role | Username | Password |
|---|---|---|
| Admin | `admin` | set during seed |
| Analyst | `analyst_01` through `analyst_10` | set during seed |

Passwords are bcrypt-hashed in the database. To reset a password, use the self-service endpoint or update directly in the DB:

```bash
# Open the SQLite database
sqlite3 /var/www/diaas-sec/database/diaas.db

# Check users
SELECT id, username, role FROM users;

# Exit
.quit
```

---

## Project Structure

```
diaas-sec/
│
├── server.js                  ← The entire backend. One file, no framework.
│                                All routes, auth, DB queries, scoring engine.
│
├── package.json               ← Dependencies: better-sqlite3, bcryptjs
│
├── database/
│   ├── schema.sql             ← All table definitions. Source of truth for DB structure.
│   ├── seed.js                ← Populates the DB: users, alerts, labs, questions, rubrics.
│   └── diaas.db               ← The SQLite database file. Created by seed.js.
│
└── public/
    ├── login.html             ← Login page. Served at /
    ├── analyst/
    │   └── index.html         ← Analyst dashboard. Everything an analyst sees.
    └── admin/
        └── index.html         ← Admin dashboard. User management, progress, stats.
```

**The three files you will edit most often:**
- `database/seed.js` — add alerts, labs, questions, rubrics
- `server.js` — add or fix API routes, scoring logic, auth
- `public/analyst/index.html` — change what analysts see and interact with

---

## How the App Works — Full Workflow

### Analyst workflow

```
Login → Analyst Dashboard
         │
         ├── Labs tab
         │     └── Pick a lab → Read alert(s) → Answer questions
         │           └── Each question is multiple choice, tied to a specific alert
         │
         └── SOC Alerts tab
               └── Browse all alerts → Click an alert → Read raw log
                     │
                     ├── [Mark as Resolved] → 5-step IR modal opens
                     │     Step 1: 5W+H triage (Who/What/When/Where/Why/How)
                     │     Step 2: Containment steps
                     │     Step 3: Eradication steps
                     │     Step 4: Recovery steps
                     │     Step 5: Root cause analysis
                     │     → Submit → scored against rubric → points awarded
                     │
                     └── [False Positive] → Justification modal
                           → Submit → points awarded if correct
```

**Points system:**

| Action | Points |
|---|---|
| Correct alert close (TP), investigation score 90–100% | 5 pts |
| Correct alert close (TP), investigation score 75–89% | 4 pts |
| Correct alert close (TP), investigation score 60–74% | 3 pts |
| Correct alert close (TP), investigation score 40–59% | 2 pts |
| Correct alert close (TP), investigation score 0–39% | 1 pt |
| Correct FP classification with justification | 3 pts |
| Wrong classification (TP closed as FP or vice versa) | 0 pts |
| Correct MCQ answer in a lab | 20 pts (default) |

### Admin workflow

```
Login → Admin Dashboard
         │
         ├── Overview — total users, labs completed, avg score
         ├── Users — create/disable analyst accounts
         ├── Progress — see every analyst's lab completion
         └── Analysts — click any analyst → full profile page
               Shows: total points, classification accuracy,
                      investigation score, per-alert closure history,
                      IR step text submitted, scoring feedback
```

---

## Scoring Engine — How Rubrics Work

The rubric scoring engine is in `server.js` starting at the `scoreIRAnswers()` function (around line 25).

**How a score is calculated:**

1. Each of the 5 IR steps has a max of 10 points
2. Each step has 3–4 "concept buckets" — a set of keywords and a point value
3. If any keyword in a bucket is found in the analyst's answer, those points are awarded
4. A step must have at least **15 words** to score anything — shorter answers get 0 for that step
5. The investigation score = (total points earned / total possible) × 100
6. If no rubric exists for an alert, scoring falls back to total word count depth

**Example — ALT-085 (ransomware, vssadmin):**

| Step | Concept bucket | Keywords that score points |
|---|---|---|
| Triage | Shadow copy deletion | `vssadmin`, `shadow cop` — 3 pts |
| Triage | Suspicious parent process | `svch0st`, `parent` — 3 pts |
| Triage | Ransomware intent | `ransomware`, `precursor` — 2 pts |
| Containment | Network isolation | `isolat`, `network`, `disconnect` — 3 pts |
| Containment | Kill process | `kill`, `svch0st`, `pid` — 3 pts |
| ... | ... | ... |

**Where rubrics are stored:** `database/alert_rubrics` table. Seeded in `database/seed.js` at the bottom of the file in the `rubrics` array.

**Current alerts with rubrics:** ALT-085, ALT-121, ALT-123, ALT-011, ALT-048, ALT-050, ALT-005, ALT-033, ALT-034, ALT-041

**To add a rubric for a new alert**, find the `rubrics` array at the bottom of `database/seed.js` and add a new entry following the same structure, then reseed.

---

## Database Tables

All table definitions are in `database/schema.sql`. The server also creates tables at startup if they are missing (idempotent migrations at the top of `server.js`).

| Table | What it stores |
|---|---|
| `users` | All accounts — analysts and admins. Has `points` and `triage_score` columns. |
| `sessions` | Auth tokens. 24-hour TTL. |
| `labs` | Training lab metadata — title, slug, difficulty, which alerts it references. |
| `questions` | MCQ questions linked to a lab. Each question has a `correct_answer` and `explanation`. |
| `user_progress` | One row per user per lab — tracks started/completed status and score. |
| `user_answers` | Every MCQ answer submitted. Records whether it was correct and points awarded. |
| `leaderboard` | Aggregate score view per user. Rebuilt from `user_answers` on query. |
| `soc_alerts` | All training alerts. Each has `raw_log`, `iocs`, `timeline`, MITRE fields, severity. |
| `escalations` | When an analyst escalates an alert to L2. |
| `incidents` | Full incident record when an alert enters the IR workflow. |
| `alert_closures` | Every alert close decision — stores all 5 IR step answers, classification, `investigation_score`, `step_scores` (JSON), `scoring_feedback` (JSON), points awarded. |
| `alert_rubrics` | Per-alert scoring rubrics. JSON blob per alert, queried by `scoreIRAnswers()`. |

---

## API Routes

All routes are in `server.js`. Every route that is not `/`, `/login`, `/analyst`, or `/admin` requires a valid session token in the `Authorization: Bearer <token>` header.

### Auth
| Method | Route | What it does |
|---|---|---|
| POST | `/api/auth/login` | Login with username + password. Returns session token. |
| POST | `/api/auth/logout` | Invalidates the session token. |

### Analyst
| Method | Route | What it does |
|---|---|---|
| GET | `/api/me` | Current analyst's profile, score, accuracy, rank. |
| GET | `/api/me/closures` | All alert closes this analyst has submitted. |
| GET | `/api/labs` | List all visible labs with progress for current user. |
| GET | `/api/labs/:slug` | Lab detail — questions, alerts linked, current progress. |
| POST | `/api/labs/:slug/submit` | Submit an MCQ answer. Returns correct/incorrect + explanation. |
| GET | `/api/leaderboard` | All analysts ranked by score. |
| GET | `/api/alerts` | All SOC alerts (with filter support). |
| GET | `/api/alerts/:id` | Single alert detail — raw log, IOCs, timeline, etc. |
| POST | `/api/alerts/:id/status` | Close an alert (as TP or FP). Triggers rubric scoring. |
| GET | `/api/alerts/:id/incident` | Fetch the incident record for an alert. |
| POST | `/api/alerts/:id/incident` | Create or update an incident record. |
| POST | `/api/alerts/:id/escalate` | Escalate an alert to L2. |
| GET | `/api/alerts/:id/escalations` | Get escalation history for an alert. |
| POST | `/api/user/password` | Self-service password change. |

### Admin (admin role required)
| Method | Route | What it does |
|---|---|---|
| GET | `/api/admin/stats` | Platform-wide stats — users, labs completed, avg score. |
| GET | `/api/admin/users` | All analyst accounts with score and lab progress. |
| POST | `/api/admin/users` | Create a new analyst account. |
| PUT | `/api/admin/users/:id` | Update account (username, role, active status). |
| DELETE | `/api/admin/users/:id` | Delete an analyst account. |
| GET | `/api/admin/progress` | All user_progress rows — which analyst is in which lab. |
| GET | `/api/admin/labs` | All labs. |
| POST | `/api/admin/labs` | Create a new lab. |
| PUT | `/api/admin/labs/:id` | Update a lab. |
| DELETE | `/api/admin/labs/:id` | Delete a lab. |
| GET | `/api/admin/labs/:id/questions` | Get all questions for a lab. |
| POST | `/api/admin/labs/:id/questions` | Add a question to a lab. |
| PUT | `/api/admin/questions/:id` | Edit a question. |
| DELETE | `/api/admin/questions/:id` | Delete a question. |
| GET | `/api/admin/analysts/:id/activity` | Full closure history for one analyst — all IR steps, scores, feedback. |

---

## Troubleshooting

### Server won't start

```bash
# Check what is on port 3000
lsof -i :3000

# Kill it
kill $(lsof -ti:3000)

# Check the log for errors
tail -50 /tmp/diaas.log
```

Common causes:
- `Cannot find module 'better-sqlite3'` → run `npm install`
- `SQLITE_CANTOPEN` → database path does not exist, run `node database/seed.js` first
- `port already in use` → kill the existing process first

### Database errors after a code update

If you see `table X has no column named Y` in the log, the DB schema is out of date. The server runs idempotent `ALTER TABLE` migrations at startup for all new columns, so a plain restart should fix it. If not:

```bash
# Nuclear option — wipe and reseed (loses all analyst progress)
rm /var/www/diaas-sec/database/diaas.db
node database/seed.js
```

### Analyst scores not updating

Check `alert_closures` has the `investigation_score` column:

```bash
sqlite3 /var/www/diaas-sec/database/diaas.db ".schema alert_closures"
```

If `investigation_score` is missing, restart the server — the migration will add it automatically.

### Alert closes with "investigation_score is not defined"

This was a bug fixed in commit `e2a6ffb`. Pull the latest code and restart.

```bash
cd /var/www/diaas-sec && git pull origin main
kill $(lsof -ti:3000) 2>/dev/null; sleep 1
nohup node server.js > /tmp/diaas.log 2>&1 &
```

### Questions not matching alerts

Every question in `seed.js` has an `alert_refs` field that lists which ALT-XXX alerts it is based on. If a question references an alert that does not exist in `soc_alerts`, the question cannot be answered correctly. Check with:

```bash
sqlite3 /var/www/diaas-sec/database/diaas.db \
  "SELECT id, title FROM soc_alerts WHERE id = 'ALT-085';"
```

---

## Labs — Full List

| Slug | Title | Difficulty |
|---|---|---|
| `alert-triage-basics` | Alert Triage Basics | Beginner |
| `soc-fundamentals` | SOC Fundamentals | Beginner |
| `credential-attacks` | Credential Attacks | Beginner |
| `windows-event-logs` | Windows Event Logs | Beginner |
| `malware-analysis` | Malware Analysis | Intermediate |
| `network-traffic-analysis` | Network Traffic Analysis | Intermediate |
| `lateral-movement` | Lateral Movement | Intermediate |
| `network-forensics` | Network Forensics | Intermediate |
| `threat-hunting` | Threat Hunting | Intermediate |
| `incident-response-playbooks` | Incident Response Playbooks | Intermediate |
| `exfiltration-detection` | Exfiltration Detection | Advanced |
| `advanced-persistent-threats` | Advanced Persistent Threats | Advanced |
| `ransomware-ir` | Ransomware IR | Advanced |
| `cloud-security-incidents` | Cloud Security Incidents | Advanced |
| `red-team-detection` | Red Team Detection | Advanced |
| `incident-response` | Operation Blackout IR | Advanced |

---

## Making Changes

### Add a new alert
Edit `database/seed.js` — find the `soc_alerts` insert block and add your alert following the existing format. Each alert needs: `id` (ALT-XXX format), `severity`, `category`, `title`, `source`, `host`, `raw_log`, `iocs`, `mitre_tactic`, `mitre_technique`.

### Add a new lab or question
Edit `database/seed.js` — find the labs array and questions array. Every question must have an `alert_refs` field pointing to real ALT-XXX ids.

### Add a rubric for an alert
Edit the `rubrics` array at the bottom of `database/seed.js`. Copy an existing entry and update the `alert_id`, `required_keywords`, and `steps` concept buckets. Run `node database/seed.js` to apply.

### Add a new API route
Edit `server.js`. All routes are `if (method === 'GET/POST' && url === '/path')` blocks. Add yours after the existing ones before the final `server.listen()` call. Follow the pattern: check auth with `requireAuth(req, res)`, parse body with `await parseBody(req)`, return with `jsonRes(res, 200, {...})`.

### Change the UI
- Analyst-facing changes → `public/analyst/index.html`
- Admin-facing changes → `public/admin/index.html`
- Login page → `public/login.html`

All three files are self-contained single-page apps. CSS is in `<style>` tags at the top, JavaScript is in `<script>` tags at the bottom. No build step, no bundler.

---

## Changelog

| Commit | What changed |
|---|---|
| `e2a6ffb` | Fixed ReferenceError crash on alert resolve. Step 1 triage now asks for 5W+H (Who/What/When/Where/Why/How). |
| `a10a867` | Rubric-based IR scoring engine. 10 rubrics seeded. Live word counter per IR step (15-word minimum). Tiered 1–5 points based on investigation score. Score feedback panel after close. |
| `76fb934` | Fixed 500 error on alert resolve (missing `users.points` column). Removed activity heatmap. Rebuilt analyst profile as full admin page. |
| `9487878` | Space Grotesk font. 5-step IR modal. FP justification modal. Analyst profile page. |
| `b7b7673` | Full IR workflow. False positive workflow. Fixed 19 broken question-to-alert mappings. 4 Operation Blackout IR labs added. |
