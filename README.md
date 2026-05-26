# DIASS-SEC — Security Operations Platform

A browser-based security operations platform for alert triage, SIEM log analysis, incident case management, and threat intelligence enrichment. Built around real-world incident scenarios with accurate Windows Event IDs, MITRE ATT&CK mappings, and full attack chain telemetry.

No build step. No framework. No package manager. Pure HTML, CSS, and JavaScript — Apache serves static files.

---

## Platform Modules

| Module | Description |
|---|---|
| **Dashboard** | Live attack timeline, severity breakdown, MITRE heatmap, agent health |
| **Alert Triage** | 18 alerts across 8 incident scenarios — TP/FP classification with MITRE mapping |
| **SIEM Logs** | 18 raw Windows event logs with key:value search syntax |
| **Incident Cases** | Case management with task checklists, observable tracking, pivot to threat intel |
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

## File Structure

```
diass-sec/
├── index.html          # Single-page application shell
├── css/
│   └── style.css       # Design system (dark navy, Bloomberg/Linear aesthetic)
├── js/
│   └── app.js          # Platform engine: routing, modules, analyst state
└── data/
    └── scenarios.js    # Alert data, SIEM logs, IOCs, incident cases
```

---

## Requirements

### Server

| Requirement | Version |
|---|---|
| Linux (Ubuntu 20.04+ recommended) | any recent LTS |
| Apache2 | 2.4+ |
| Git | 2.x |

No Python, Node.js, database, or runtime dependency. Apache serves the static files directly.

> **Non-Ubuntu Linux:** Works on any distro with Apache2. Replace `apt` commands with your package manager:
> - Debian: `apt` (same as Ubuntu)
> - RHEL / Rocky / AlmaLinux: `dnf install httpd git` — service name is `httpd` not `apache2`, config path is `/etc/httpd/conf.d/`
> - Arch: `pacman -S apache git` — service name is `httpd`
> - openSUSE: `zypper install apache2 git`

### Client

Any modern browser (Chrome 90+, Firefox 88+, Edge 90+, Safari 14+). No install required on the client side.

---

## Install

### Option 1 — Automated (recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/indranilroy99/soc-training-lab/main/install.sh | sudo bash
```

### Option 2 — Manual (Ubuntu / Debian)

**Step 1 — Install dependencies**

```bash
sudo apt update && sudo apt install -y apache2 git
```

**Step 2 — Enable Apache and verify it's running**

```bash
sudo systemctl enable apache2
sudo systemctl start apache2
sudo systemctl status apache2
```

**Step 3 — Clone the repo**

```bash
sudo git clone https://github.com/indranilroy99/soc-training-lab.git /var/www/diass-sec
```

**Step 4 — Set permissions**

```bash
sudo chown -R www-data:www-data /var/www/diass-sec
sudo chmod -R 755 /var/www/diass-sec
```

**Step 5 — Create virtual host**

```bash
sudo tee /etc/apache2/sites-available/diass-sec.conf > /dev/null << 'EOF'
<VirtualHost *:80>
    DocumentRoot /var/www/diass-sec
    <Directory /var/www/diass-sec>
        Options -Indexes
        AllowOverride None
        Require all granted
    </Directory>
</VirtualHost>
EOF
```

**Step 6 — Enable site and reload Apache**

```bash
sudo a2ensite diass-sec.conf
sudo a2dissite 000-default.conf
sudo systemctl reload apache2
```

**Step 7 — Verify**

```bash
curl -s -o /dev/null -w "%{http_code}" http://localhost
# Expected: 200
```

Access at `http://<server-ip>` from any browser on the same network.

---

## Update

```bash
cd /var/www/diass-sec && sudo git pull origin main && sudo systemctl reload apache2
```

---

## Analyst Configuration

Analyst identities are defined in `data/scenarios.js` under the `analysts` array. Update `name` fields to match your team roster. The active analyst is set in `js/app.js` under `state.analystId` — change `analyst_01` to the relevant ID.

---

## IOC Coverage

10 indicators pre-loaded: known C2 IPs (Cobalt Strike infrastructure), phishing domains, ransomware hashes, dropper hashes, and C2 URLs — all mapped to real-world threat campaigns against financial sector targets.
