# DIAAS-SEC — Security Operations Training Platform

A self-hosted SOC training platform. Analysts log in, work through labs, and earn points. Admins manage users, track progress, and view the leaderboard. No cloud, no Docker, no external dependencies.

---

## What's inside

- **6 hands-on labs** — Alert Triage, Phishing Analysis, Lateral Movement, SIEM Hunting, Ransomware IR, APT Threat Hunting
- **Real auth** — bcrypt-hashed passwords, session tokens, 24h expiry
- **Analyst dashboard** — lab progress, leaderboard, profile, score tracking
- **Admin panel** — create/disable/delete users, reset passwords, progress matrix, full leaderboard
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

## Install (Mac mini / Linux server)

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
4. Seed the database (11 users, 6 labs, 30 questions)
5. Install a background service (launchd on Mac, systemd on Linux)

---

## Default credentials

| Role | Username | Password |
|------|----------|----------|
| Admin | `admin` | `Admin@2024` |
| Analyst | `analyst_01` through `analyst_10` | `Analyst@2024` |

**Change all passwords before sharing with users.** Use the Admin panel → Manage Users → Reset PW.

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

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | Port to listen on |

To run on a different port:
```bash
PORT=8080 node server.js
```

---

## Re-seed the database

If you want to reset all progress and start fresh:

```bash
cd ~/diaas-sec
rm database/diaas.db
node database/seed.js
```

This recreates all 11 default users, 6 labs, and 30 questions. Any custom users or analyst progress will be wiped.

---

## Add users without the admin panel

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

## File structure

```
diaas-sec/
├── server.js              — Node.js backend (no Express)
├── package.json
├── database/
│   ├── schema.sql         — SQLite schema
│   ├── seed.js            — Seeds users, labs, questions
│   └── diaas.db           — Database file (created on first seed)
├── public/
│   ├── login.html         — Login page
│   ├── analyst/
│   │   └── index.html     — Analyst SPA
│   └── admin/
│       └── index.html     — Admin SPA
└── logs/
    ├── server.log
    └── error.log
```

---

## Labs

| # | Lab | Category | Difficulty | Points |
|---|-----|----------|------------|--------|
| 1 | Alert Triage Fundamentals | Alert Triage | Easy | 100 |
| 2 | Phishing Email Analysis | Threat Intel | Easy | 100 |
| 3 | Lateral Movement Detection | Alert Triage | Medium | 150 |
| 4 | SIEM Log Hunting | SIEM | Medium | 150 |
| 5 | Ransomware Incident Response | Incident Response | Hard | 200 |
| 6 | APT Threat Hunting | Threat Hunting | Hard | 200 |

Total available: **900 pts**

---

## Scoring

- **First correct attempt** — full points
- **Second correct attempt** — 50% points
- **Third correct attempt** — 50% points + answer revealed
- **3 failed attempts** — answer and explanation revealed, 0 pts
- Text questions use keyword matching (case-insensitive, partial credit)

---

## Tech stack

| Layer | Technology |
|-------|-----------|
| Backend | Node.js 20, built-in `http` module (no Express) |
| Database | SQLite via `better-sqlite3` |
| Auth | bcryptjs password hashing, crypto random session tokens |
| Frontend | Vanilla HTML/CSS/JS, no frameworks |
| Service | launchd (macOS) / systemd (Linux) |

All dependencies are free and open source. Zero paid services.
