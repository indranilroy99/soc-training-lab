# DIASS-SEC

Browser-based security operations platform. Alert triage, SIEM log analysis, incident case management, and threat intelligence enrichment — built around real incident scenarios with accurate Windows Event IDs and MITRE ATT&CK mappings.

No build step. No framework. No runtime. Apache serves static files.

---

## Requirements

- Linux server (Ubuntu 20.04+ recommended)
- `apache2` and `git` — installed in Step 1 below
- Any modern browser on the client side (Chrome, Firefox, Edge, Safari)

---

## Install

### Quick install (recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/indranilroy99/soc-training-lab/main/install.sh | sudo bash
```

Done. Access at `http://<your-server-ip>`.

---

### Manual install (Ubuntu / Debian)

**1. Install dependencies**

```bash
sudo apt update && sudo apt install -y apache2 git
```

**2. Start Apache**

```bash
sudo systemctl enable apache2
sudo systemctl start apache2
```

**3. Clone the repo**

> `/var/www` is root-owned — you must use `sudo` here.

```bash
sudo git clone https://github.com/indranilroy99/soc-training-lab.git /var/www/diass-sec
```

**4. Set permissions**

```bash
sudo chown -R www-data:www-data /var/www/diass-sec
sudo chown -R root:root /var/www/diass-sec/.git
sudo chmod -R 755 /var/www/diass-sec
```

> Apache needs to own the app files (`www-data`). `.git` stays owned by root so `sudo git pull` works later without errors.

**5. Create the Apache site config**

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

**6. Enable the site and reload Apache**

```bash
sudo a2ensite diass-sec.conf
sudo a2dissite 000-default.conf
sudo systemctl reload apache2
```

**7. Verify it's up**

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://localhost
# 200 = good to go
```

Open `http://<your-server-ip>` in a browser.

---

## Update

Pull the latest and reload Apache:

```bash
sudo git -C /var/www/diass-sec pull origin main
sudo systemctl reload apache2
```

---

## Stop

Stop Apache (platform goes offline, nothing is deleted):

```bash
sudo systemctl stop apache2
```

Start it again:

```bash
sudo systemctl start apache2
```

Disable Apache from starting on boot:

```bash
sudo systemctl disable apache2
```

---

## Uninstall

Remove the app and site config:

```bash
sudo rm -rf /var/www/diass-sec
sudo rm -f /etc/apache2/sites-available/diass-sec.conf
sudo rm -f /etc/apache2/sites-enabled/diass-sec.conf
sudo systemctl reload apache2
```

---

## Other Linux Distros

Works on any distro with Apache. Replace the `apt` commands:

| Distro | Install command | Apache service name |
|---|---|---|
| Debian | `apt install apache2 git` | `apache2` |
| RHEL / Rocky / AlmaLinux | `dnf install httpd git` | `httpd` |
| Arch | `pacman -S apache git` | `httpd` |
| openSUSE | `zypper install apache2 git` | `apache2` |

On RHEL-based systems the vhost config goes in `/etc/httpd/conf.d/diass-sec.conf` instead of `/etc/apache2/sites-available/`.

---

## File Structure

```
diass-sec/
├── index.html          # App shell
├── install.sh          # Automated install script
├── css/
│   └── style.css       # Design system
├── js/
│   └── app.js          # Platform engine
└── data/
    └── scenarios.js    # Alert data, SIEM logs, IOCs, cases
```

---

## Modules

| Module | Description |
|---|---|
| Dashboard | Attack timeline, severity breakdown, MITRE heatmap |
| Alert Triage | 18 alerts — TP/FP classification with MITRE mapping |
| SIEM Logs | 18 raw Windows event logs with search |
| Incident Cases | Case management, task checklists, observable tracking |
| Threat Intel | IOC enrichment — IPs, domains, hashes, URLs, email |
| Analyst Board | Per-analyst triage counts and accuracy metrics |

---

## Scenarios

| ID | Scenario | Event IDs | MITRE |
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
