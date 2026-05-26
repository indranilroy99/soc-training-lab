# NEXUS — Security Operations Training Platform

**Stack 3 · SOC Specialist Training · vo1dLabs**

A browser-based SOC training simulation platform. Trainees work through real incident scenarios across all core SOC disciplines — alert triage, SIEM log analysis, incident case management, and threat intelligence enrichment.

---

## What's Inside

```
index.html          → Full platform (single page app, no dependencies)
css/style.css       → Design system (Bloomberg + Linear.app aesthetic)
js/app.js           → Platform engine — routing, scoring, modules
data/scenarios.js   → 18 alerts, 18 SIEM events, 10 IOCs, 2 cases
```

## Platform Features

| Module | What Trainees Do |
|---|---|
| **Dashboard** | Live attack timeline, severity breakdown, MITRE heatmap, agent health |
| **Alert Triage** | Classify 18 alerts as TP/FP, map MITRE technique, earn points |
| **SIEM Logs** | Search 18 raw Windows event logs with key:value syntax |
| **Incident Cases** | Manage 2 active cases, complete tasks, add observables |
| **Threat Intel** | Enrich 10 IOCs, lookup by IP/domain/hash/URL |
| **Leaderboard** | Live class ranking, personal score, accuracy stats |

## Scenarios Covered

1. Port Scan / Nmap Recon
2. RDP Brute Force + Successful Login
3. Phishing → Macro → PowerShell → C2
4. Lateral Movement via PsExec + Pass-the-Hash
5. LSASS Credential Dump
6. C2 Beaconing (Cobalt Strike pattern)
7. Kerberoasting + DCSync (AD attack)
8. Ransomware + VSS Deletion

Plus 2 False Positive scenarios for TP/FP discrimination training.

## Deploy (Apache — 3 commands)

```bash
# 1. Clone
git clone https://github.com/indranilroy99/soc-training-lab.git /var/www/nexus

# 2. Set permissions
sudo chown -R www-data:www-data /var/www/nexus

# 3. Configure Apache virtual host
sudo bash -c 'cat > /etc/apache2/sites-available/nexus.conf << EOF
<VirtualHost *:80>
    ServerName nexus.local
    DocumentRoot /var/www/nexus
    <Directory /var/www/nexus>
        Options -Indexes
        AllowOverride None
        Require all granted
    </Directory>
</VirtualHost>
EOF'
sudo a2ensite nexus.conf && sudo systemctl reload apache2
```

Access: `http://<server-ip>` from any browser on the network.

No Node.js, no npm, no Docker. Pure static files.

## Trainee Setup

Each trainee opens `http://<server-ip>` in their browser. No install required.
Change analyst name in `js/app.js` → `state.analystId` or let trainees type their own name.

## Scoring

- Correct TP/FP verdict: 10–35 pts (scales with alert severity)
- Correct MITRE technique: +30% bonus
- Case task completion: +10 pts each
- IOC enrichment: +5 pts per lookup
- Speed bonus on critical alerts: +15 pts

## Stack 3 Curriculum

Full 14-day curriculum is in the Slack channel. Platform covers:
- Days 1–5: Daily web app labs (this platform)
- Days 7–12: VM labs (Wazuh + Kali + Windows Server)
- Days 13–14: Operation Blackout capstone (this platform + all VMs)

---

*Built for vo1dLabs SOC Training — Stack 3: Niche Cybersecurity Skills*
