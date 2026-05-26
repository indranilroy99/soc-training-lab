# DIASS-SEC — Security Operations Platform

A browser-based security operations platform for alert triage, SIEM log analysis, incident case management, and threat intelligence enrichment. Built around real-world incident scenarios with accurate Windows Event IDs, MITRE ATT&CK mappings, and attack chain telemetry.

---

## Platform Modules

| Module | Description |
|---|---|
| **Dashboard** | Live attack timeline, severity breakdown, MITRE heatmap, agent health |
| **Alert Triage** | 18 alerts across 8 incident scenarios — TP/FP classification with MITRE mapping |
| **SIEM Logs** | 18 raw Windows event logs with key:value search syntax |
| **Incident Cases** | Case management with task checklists, observable tracking, and pivot to threat intel |
| **Threat Intel** | IOC enrichment with threat scoring — IPs, domains, hashes, URLs, email |
| **Analyst Board** | Per-analyst activity tracking, triage counts, and accuracy metrics |

---

## Incident Scenarios

| # | Scenario | Key Event IDs | MITRE |
|---|---|---|---|
| S1 | Port Scan / Recon | 5156 | T1046 |
| S2 | RDP Brute Force → Account Compromise | 4625, 4624 | T1110.001, T1078 |
| S3 | Phishing → Macro → PowerShell → C2 | Sysmon 1, 3 | T1059.001, T1071.001 |
| S4 | Lateral Movement via PsExec + Pass-the-Hash | 7045, 4624 | T1021.002, T1550.002 |
| S5 | LSASS Credential Dump | Sysmon 10 | T1003.001 |
| S6 | C2 Beaconing (Cobalt Strike profile) | Sysmon 3, 22 | T1071.001, T1071.004 |
| S7 | Kerberoasting + DCSync | 4769, 4662 | T1558.003, T1003.006 |
| S8 | Ransomware + VSS Deletion | Sysmon 11, 4688 | T1486, T1490 |
| FP | False Positive set (2 scenarios) | 4688, 4720 | — |

---

## Stack

```
index.html        — Single-page application shell
css/style.css     — Design system
js/app.js         — Platform engine: routing, modules, analyst state
data/scenarios.js — Alert data, SIEM logs, IOCs, cases
```

No build step. No framework. No package manager. Pure HTML, CSS, and JavaScript.

---

## Deploy

```bash
# Clone
git clone https://github.com/indranilroy99/soc-training-lab.git /var/www/diass-sec

# Permissions
sudo chown -R www-data:www-data /var/www/diass-sec

# Apache virtual host
sudo bash -c 'cat > /etc/apache2/sites-available/diass-sec.conf << EOF
<VirtualHost *:80>
    DocumentRoot /var/www/diass-sec
    <Directory /var/www/diass-sec>
        Options -Indexes
        AllowOverride None
        Require all granted
    </Directory>
</VirtualHost>
EOF'
sudo a2ensite diass-sec.conf && sudo systemctl reload apache2
```

Access at `http://<server-ip>` — no client setup required.

---

## Update

```bash
cd /var/www/diass-sec && git pull origin main && sudo systemctl reload apache2
```

---

## Analyst Configuration

Analyst identity is set in `js/app.js` under `state.analystId`. Update the `analysts` array in `data/scenarios.js` to reflect your team roster.

---

## IOC Coverage

10 indicators pre-loaded: known C2 IPs (Cobalt Strike infrastructure), phishing domains, ransomware hashes, dropper hashes, and C2 URLs — all mapped to real-world threat campaigns.
