# DIAAS-SEC — Security Operations Training Platform

A self-hosted SOC training platform. Analysts log in, work through labs, answer investigation questions, and close real-world alerts using a structured 5-step Incident Response workflow. Every IR answer is scored against a rubric built from actual alert evidence — filler text does not earn points. Admins manage users, track progress, and view full analyst profiles.

No cloud. No Docker. No external dependencies.

---

## What's inside

- **16 hands-on labs** — Alert Triage, SOC Fundamentals, Credential Attacks, Windows Event Logs, Malware Analysis, Network Traffic Analysis, Lateral Movement, Network Forensics, Threat Hunting, IR Playbooks, Exfiltration Detection, APT Hunting, Ransomware IR, Cloud Security Incidents, Red Team Detection, Operation Blackout IR
- **200+ training alerts** — each with raw log, IOCs, timeline, MITRE ATT&CK mapping
- **5-step IR workflow** — analysts close alerts by walking through Triage (5W+H) → Containment → Eradication → Recovery → Root Cause Analysis
- **Rubric-based scoring** — every IR answer scored against keyword-concept rubrics built from actual alert fields. 15-word minimum per step. 1–5 pts based on investigation score.
- **False Positive workflow** — analysts can classify an alert as FP with a written justification
- **Real auth** — bcrypt-hashed passwords, session tokens, 24h expiry
- **Analyst dashboard** — lab progress, leaderboard, SOC alerts feed, IR modal
- **Admin panel** — create/disable/delete users, track progress, full analyst profile with all IR step text + scores
- **SQLite** — zero config, single file database
- **No Docker, no YAML** — one script installs everything

---

## Requirements

| Requirement | Version |
|------------|---------|
| Node.js | 18 or higher |
| npm | comes with Node |
| git | any recent version |
| OS | macOS, Ubuntu, Debian, RHEL/CentOS |

---

## Install — One Command

```bash
curl -fsSL https://raw.githubusercontent.com/indranilroy99/soc-training-lab/main/install.sh | bash
```

Or clone and run manually:

```bash
git clone https://github.com/indranilroy99/soc-training-lab ~/diaas-sec
cd ~/diaas-sec
npm install
node database/seed.js
node server.js
```

The installer will:
1. Install Node.js if missing
2. Clone the repo to `~/diaas-sec`
3. Install npm dependencies
4. Seed the database (11 users, 16 labs, 200+ alerts, 10 rubrics)
5. Install a background service (launchd on Mac, systemd on Linux)

---

## Default Credentials

| Role | Username | Password |
|------|----------|----------|
| Admin | `admin` | `Admin@2024` |
| Analyst | `analyst_01` through `analyst_10` | `Analyst@2024` |

**Change all passwords before sharing with users.** Use Admin panel → Manage Users → Reset PW.

---

## Access

After install, open a browser and go to:

```
http://<server-ip>:3000          ← login page
http://<server-ip>:3000/admin    ← admin panel
http://<server-ip>:3000/analyst  ← analyst view
```

To find your Mac mini's IP: `System Settings → Wi-Fi → Details` or run `ipconfig getifaddr en0`.

Analysts on the same network open `http://<your-mac-mini-ip>:3000` and log in with the credentials you give them.

---

## Start / Stop / Update

**macOS (launchd)**
```bash
# Start
launchctl load ~/Library/LaunchAgents/com.diaas-sec.plist

# Stop
launchctl unload ~/Library/LaunchAgents/com.diaas-sec.plist

# Check logs
tail -f ~/diaas-sec/logs/server.log
```

**Linux (systemd)**
```bash
sudo systemctl start diaas-sec
sudo systemctl stop diaas-sec
sudo systemctl status diaas-sec
journalctl -u diaas-sec -f
```

**Manual (no service)**
```bash
cd ~/diaas-sec
node server.js
# Ctrl+C to stop
```

**Update to latest**
```bash
cd ~/diaas-sec
git pull origin main
npm install
# Restart service or node server.js
```

---

## Deploy to a Live Server (Ubuntu + Apache)

If you are deploying on a Ubuntu server with Apache proxying port 80 → 3000:

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

**When you MUST reseed** (run `node database/seed.js` again):
- Any time labs, alerts, questions, or rubrics change in seed.js
- First deploy on a new machine
- If you delete diaas.db and want a fresh start

**When you do NOT need to reseed:**
- Bug fixes, styling changes, server-side logic changes
- Just `git pull` and restart the server

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | Port to listen on |

To run on a different port:
```bash
PORT=8080 node server.js
```

---

## Re-seed the Database

If you want to reset all progress and start fresh:

```bash
cd ~/diaas-sec
rm database/diaas.db
node database/seed.js
```

This recreates all 11 default users, 16 labs, 200+ alerts, questions, and rubrics. Any analyst progress will be wiped.

---

## Add Users Without the Admin Panel

```bash
cd ~/diaas-sec
node -e "
const db = require('better-sqlite3')('database/diaas.db');
const bcrypt = require('bcryptjs');
const hash = bcrypt.hashSync('YourPassword@123', 10);
db.prepare('INSERT INTO users (username, password_hash, role) VALUES (?,?,?)').run('analyst_11', hash, 'analyst');
console.log('Done');
"
```

---

## Project Structure

```
diaas-sec/
│
├── server.js                  ← The entire backend. One file, no framework.
│                                All routes, auth, DB queries, rubric scoring engine.
│
├── package.json               ← Dependencies: better-sqlite3, bcryptjs
│
├── install.sh                 ← One-command installer (Node check, clone, seed, service)
│
├── database/
│   ├── schema.sql             ← All table definitions. Source of truth for DB structure.
│   ├── seed.js                ← Populates DB: users, alerts, labs, questions, rubrics.
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
         │     └── Pick a lab → Read the linked alert(s) → Answer MCQ questions
         │           └── Each question is tied to a specific ALT-XXX alert's raw log
         │
         └── SOC Alerts tab
               └── Browse all alerts → Click alert → Read raw log, IOCs, timeline
                     │
                     ├── [Mark as Resolved] → 5-step IR modal opens
                     │     Step 1: 5W+H triage (Who / What / When / Where / Why / How)
                     │     Step 2: Containment steps
                     │     Step 3: Eradication steps
                     │     Step 4: Recovery steps
                     │     Step 5: Root Cause Analysis
                     │     → Submit → scored against rubric → points awarded (1–5)
                     │     → Score feedback panel shows for 15s with improvement tips
                     │
                     └── [False Positive] → Justification modal
                           → Submit → 3 pts if classification is correct
```

### Admin workflow

```
Login → Admin Dashboard
         │
         ├── Overview — total users, labs completed, avg score, alert stats
         ├── Users — create / disable / delete analyst accounts
         ├── Progress — see every analyst's lab completion status
         └── Analysts — click any analyst → full profile page
               Shows: total points, classification accuracy, investigation score,
                      per-alert closure history, all IR step text submitted,
                      scoring feedback per step
```

---

## Points System

| Action | Points |
|---|---|
| Correct alert close (TP), investigation score 90–100% | 5 pts |
| Correct alert close (TP), investigation score 75–89% | 4 pts |
| Correct alert close (TP), investigation score 60–74% | 3 pts |
| Correct alert close (TP), investigation score 40–59% | 2 pts |
| Correct alert close (TP), investigation score 0–39% | 1 pt |
| Correct FP classification with written justification | 3 pts |
| Wrong classification (TP closed as FP or vice versa) | 0 pts |
| Correct MCQ answer — first attempt | full points (default 20) |
| Correct MCQ answer — second attempt | 50% points |
| Correct MCQ answer — third attempt | 50% points + answer revealed |
| 3 failed MCQ attempts | answer + explanation revealed, 0 pts |

---

## Scoring Engine — How Rubrics Work

The rubric scoring engine lives in `server.js` in the `scoreIRAnswers()` function (around line 25).

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

**To add a rubric for a new alert**, find the `rubrics` array at the bottom of `database/seed.js`, copy an existing entry, update the `alert_id`, `required_keywords`, and `steps` concept buckets, then reseed.

---

## Database Tables

All table definitions are in `database/schema.sql`. The server also runs idempotent `ALTER TABLE` migrations at startup for any new columns added since the DB was created.

| Table | What it stores |
|---|---|
| `users` | All accounts — analysts and admins. Has `points` and `triage_score` columns. |
| `sessions` | Auth tokens. 24-hour TTL. |
| `labs` | Training lab metadata — title, slug, difficulty, which alerts it references. |
| `questions` | MCQ questions linked to a lab. Each has `correct_answer` and `explanation`. |
| `user_progress` | One row per user per lab — tracks started/completed status and score. |
| `user_answers` | Every MCQ answer submitted. Records whether it was correct and points awarded. |
| `leaderboard` | Aggregate score view per user. Rebuilt from `user_answers` on query. |
| `soc_alerts` | All training alerts. Each has `raw_log`, `iocs`, `timeline`, MITRE fields, severity. |
| `escalations` | When an analyst escalates an alert to L2. |
| `incidents` | Full incident record when an alert enters the IR workflow. |
| `alert_closures` | Every alert close decision — all 5 IR step answers, classification, `investigation_score`, `step_scores` (JSON), `scoring_feedback` (JSON), points awarded. |
| `alert_rubrics` | Per-alert scoring rubrics. JSON blob per alert, queried by `scoreIRAnswers()`. |

---

## API Routes

All routes are in `server.js`. Every route except `/`, `/login`, `/analyst`, `/admin` requires a valid session token in the `Authorization: Bearer <token>` header.

### Auth
| Method | Route | What it does |
|---|---|---|
| POST | `/api/auth/login` | Login. Returns session token. |
| POST | `/api/auth/logout` | Invalidates session token. |

### Analyst
| Method | Route | What it does |
|---|---|---|
| GET | `/api/me` | Current analyst's profile, score, accuracy, rank. |
| GET | `/api/me/closures` | All alert closes this analyst has submitted. |
| GET | `/api/labs` | All visible labs with progress for current user. |
| GET | `/api/labs/:slug` | Lab detail — questions, linked alerts, current progress. |
| POST | `/api/labs/:slug/submit` | Submit an MCQ answer. Returns correct/incorrect + explanation. |
| GET | `/api/leaderboard` | All analysts ranked by score. |
| GET | `/api/alerts` | All SOC alerts (with filter support). |
| GET | `/api/alerts/:id` | Single alert — raw log, IOCs, timeline, MITRE, etc. |
| POST | `/api/alerts/:id/status` | Close an alert as TP or FP. Triggers rubric scoring. |
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
| GET | `/api/admin/progress` | All user_progress rows. |
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

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Node.js 18+, built-in `http` module (no Express) |
| Database | SQLite via `better-sqlite3` |
| Auth | bcryptjs password hashing, crypto random session tokens |
| Frontend | Vanilla HTML/CSS/JS, no frameworks, no build step |
| Service | launchd (macOS) / systemd (Linux) |

All dependencies are free and open source. Zero paid services.

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
Edit `database/seed.js` — find the `soc_alerts` insert block and add your alert. Each alert needs: `id` (ALT-XXX format), `severity`, `category`, `title`, `source`, `host`, `raw_log`, `iocs`, `mitre_tactic`, `mitre_technique`. Then reseed.

### Add a new lab or question
Edit `database/seed.js` — find the labs array and questions array. Every question must have an `alert_refs` field pointing to real ALT-XXX ids that actually exist in `soc_alerts`.

### Add a rubric for an alert
Edit the `rubrics` array at the bottom of `database/seed.js`. Copy an existing entry, update `alert_id`, `required_keywords`, and `steps` concept buckets. Run `node database/seed.js` to apply.

### Add a new API route
Edit `server.js`. All routes follow this pattern:
```javascript
if (method === 'POST' && url === '/api/your-route') {
  const user = requireAuth(req, res); if (!user) return;
  const body = await parseBody(req);
  // your logic
  return jsonRes(res, 200, { ok: true });
}
```
Add yours before the final `server.listen()` call.

### Change the UI
- Analyst-facing → `public/analyst/index.html`
- Admin-facing → `public/admin/index.html`
- Login page → `public/login.html`

All three are self-contained single-page apps. CSS in `<style>` at the top, JavaScript in `<script>` at the bottom. No build step, no bundler — edit and reload.

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
- `SQLITE_CANTOPEN` → run `node database/seed.js` first to create the DB
- `port already in use` → kill the existing process first

### Database errors after a code update

If you see `table X has no column named Y`, the DB schema is out of date. The server runs idempotent `ALTER TABLE` migrations on startup — a plain restart usually fixes it. If not:

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

If missing, restart the server — the migration adds it automatically.

### Alert closes with "investigation_score is not defined"

Fixed in commit `e2a6ffb`. Pull and restart:

```bash
cd /var/www/diaas-sec && git pull origin main
kill $(lsof -ti:3000) 2>/dev/null; sleep 1
nohup node server.js > /tmp/diaas.log 2>&1 &
```

### Questions not matching alerts

Every question in `seed.js` has an `alert_refs` field. If it references an ALT-XXX that doesn't exist in `soc_alerts`, answers won't work. Check with:

```bash
sqlite3 /var/www/diaas-sec/database/diaas.db \
  "SELECT id, title FROM soc_alerts WHERE id = 'ALT-085';"
```

---

## Changelog

| Commit | What changed |
|---|---|
| `e6de6e6` | Full README rewrite — merged old install commands + new architecture docs. |
| `e2a6ffb` | Fixed ReferenceError crash on alert resolve (`investigation_score` scope bug). Step 1 triage now asks for 5W+H. |
| `a10a867` | Rubric-based IR scoring engine. 10 rubrics seeded. Live 15-word counter per step. Tiered 1–5 pts. Score feedback panel after close. |
| `76fb934` | Fixed 500 on alert resolve (missing `users.points` column). Removed heatmap. Rebuilt analyst profile as full page. |
| `9487878` | Space Grotesk font. 5-step IR modal. FP justification modal. Analyst profile page. |
| `b7b7673` | Full IR workflow. False positive workflow. Fixed 19 broken question-to-alert mappings. 4 Operation Blackout IR labs. |
| `b19ac36` | v2.0.0 — full stack rebuild: Node.js + SQLite auth, analyst SPA, admin panel, 6 labs, 30 questions. |
