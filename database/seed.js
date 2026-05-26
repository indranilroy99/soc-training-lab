// DIAAS-SEC — Database Seed Script
// Run: node database/seed.js
// Idempotent — safe to run multiple times

const path = require('path');
const fs   = require('fs');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');

const DB_PATH     = path.join(__dirname, 'diaas.db');
const SCHEMA_PATH = path.join(__dirname, 'schema.sql');

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// Run schema
const schema = fs.readFileSync(SCHEMA_PATH, 'utf8');
db.exec(schema);

// ── Helpers ──────────────────────────────────────────────
function upsertUser(username, password, role) {
  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  const hash = bcrypt.hashSync(password, 10);
  if (existing) {
    db.prepare('UPDATE users SET password_hash=?, role=?, active=1 WHERE username=?')
      .run(hash, role, username);
    return existing.id;
  }
  const info = db.prepare(
    'INSERT INTO users (username, password_hash, role) VALUES (?,?,?)'
  ).run(username, hash, role);
  return info.lastInsertRowid;
}

function upsertLab(slug, title, category, difficulty, description, points, order_num) {
  const existing = db.prepare('SELECT id FROM labs WHERE slug = ?').get(slug);
  if (existing) {
    db.prepare(`UPDATE labs SET title=?,category=?,difficulty=?,description=?,points=?,order_num=?,active=1 WHERE slug=?`)
      .run(title, category, difficulty, description, points, order_num, slug);
    return existing.id;
  }
  const info = db.prepare(
    `INSERT INTO labs (slug,title,category,difficulty,description,points,order_num) VALUES (?,?,?,?,?,?,?)`
  ).run(slug, title, category, difficulty, description, points, order_num);
  return info.lastInsertRowid;
}

function upsertQuestion(lab_id, order_num, question_text, answer_type, correct_answer, options, explanation, points, hint) {
  const existing = db.prepare('SELECT id FROM questions WHERE lab_id=? AND order_num=?').get(lab_id, order_num);
  if (existing) {
    db.prepare(`UPDATE questions SET question_text=?,answer_type=?,correct_answer=?,options=?,explanation=?,points=?,hint=? WHERE id=?`)
      .run(question_text, answer_type, correct_answer, options ? JSON.stringify(options) : null, explanation, points, hint || null, existing.id);
    return existing.id;
  }
  const info = db.prepare(
    `INSERT INTO questions (lab_id,order_num,question_text,answer_type,correct_answer,options,explanation,points,hint) VALUES (?,?,?,?,?,?,?,?,?)`
  ).run(lab_id, order_num, question_text, answer_type, correct_answer, options ? JSON.stringify(options) : null, explanation, points, hint || null);
  return info.lastInsertRowid;
}

// ── Users ─────────────────────────────────────────────────
console.log('Seeding users...');
upsertUser('admin',       'Admin@2024',   'admin');
for (let i = 1; i <= 10; i++) {
  const pad = String(i).padStart(2, '0');
  upsertUser(`analyst_${pad}`, 'Analyst@2024', 'analyst');
}
console.log('  ✓ 1 admin + 10 analysts');

// ── Labs & Questions ──────────────────────────────────────
console.log('Seeding labs...');

// ── LAB 1: Alert Triage Fundamentals ─────────────────────
const lab1 = upsertLab(
  'alert-triage-basics',
  'Alert Triage Fundamentals',
  'Alert Triage',
  'Easy',
  `You are an L1 SOC analyst reviewing Windows Security Event logs. A batch of alerts has just come in from the SIEM. Your job is to identify the correct event, classify it, and determine whether each alert is a True Positive (TP) or False Positive (FP). This lab covers the most critical Windows Event IDs every SOC analyst must know by memory.`,
  100, 1
);
upsertQuestion(lab1, 1,
  'A user reports being unable to log in. You pull the Windows Security log and find repeated occurrences of a specific Event ID on the domain controller. Which Windows Event ID indicates a failed logon attempt?',
  'choice', '4625',
  ['4624', '4625', '4634', '4648'],
  'Event ID 4625 is "An account failed to log on." It is one of the most important events for detecting brute force and credential stuffing attacks. 4624 is successful logon, 4634 is logoff, and 4648 is logon using explicit credentials.',
  20, 'Look for the event that records a FAILED authentication attempt, not a successful one.'
);
upsertQuestion(lab1, 2,
  'You see Event ID 4688 on a workstation. The New Process Name field shows: C:\\Windows\\System32\\cmd.exe. The Creator Process Name shows: WINWORD.EXE. Why is this alert suspicious?',
  'text', 'word spawning cmd',
  null,
  'Microsoft Word (WINWORD.EXE) should never spawn cmd.exe under normal operation. This parent-child process relationship is a classic indicator of a malicious macro executing a command shell — a common initial access technique (MITRE T1566.001). Any Office application spawning cmd.exe, powershell.exe, or wscript.exe is a high-fidelity TP.',
  20, 'Think about what process is the parent and whether that relationship is normal.'
);
upsertQuestion(lab1, 3,
  'You receive an alert for Event ID 4698. What activity does this event record, and why do attackers use it?',
  'choice', 'A scheduled task was created',
  ['A user account was created', 'A scheduled task was created', 'A service was installed', 'An audit log was cleared'],
  'Event ID 4698 records "A scheduled task was created." Attackers use scheduled tasks for persistence (MITRE T1053.005) — they create tasks that execute malware on reboot, at set intervals, or when a specific user logs on. Always check the Task Content field for encoded PowerShell or suspicious executables.',
  20, 'This event is used by attackers to survive a reboot.'
);
upsertQuestion(lab1, 4,
  'Event ID 4720 fires on your domain controller. The Subject (who performed the action) is a standard user account, not an admin. Is this a True Positive (TP) or False Positive (FP)? Explain why.',
  'text', 'true positive',
  null,
  'TRUE POSITIVE. Event ID 4720 is "A user account was created." Standard users should never have permission to create domain accounts. If a non-admin account is the Subject on this event, it means either privilege escalation has already occurred, or an attacker has found a misconfigured delegation. This warrants immediate investigation — pull the user\'s recent logon history and check for 4672 (special privileges assigned) events.',
  20, 'Ask yourself: should a normal user be able to perform this action?'
);
upsertQuestion(lab1, 5,
  'You see 847 occurrences of Event ID 4776 against the same username ("svc_sql") from the same source IP (10.10.5.22) over 3 minutes. What attack is most likely occurring and what is your recommended immediate action?',
  'text', 'credential stuffing brute force password spray block ip disable account',
  null,
  '847 authentication attempts in 3 minutes against a service account is a credential stuffing or password spray attack (MITRE T1110.003). Recommended immediate actions: (1) Block source IP 10.10.5.22 at perimeter firewall, (2) Temporarily lock/disable the svc_sql account, (3) Check if any 4624 (successful logon) events exist for this account from that IP — if yes, assume compromise and begin IR, (4) Notify the account owner, (5) Escalate to L2 if successful logon found.',
  20, 'Volume + speed + single target = a specific attack type. What is it called?'
);
console.log('  ✓ Lab 1: Alert Triage Fundamentals');

// ── LAB 2: Phishing Email Analysis ───────────────────────
const lab2 = upsertLab(
  'phishing-analysis',
  'Phishing Email Analysis',
  'Threat Intel',
  'Easy',
  `A suspicious email has been reported by an employee in the Finance department. The user says they received an email claiming to be from "IT Support" asking them to verify their credentials. You have been handed the raw email headers and body for analysis. Your job is to examine the artifacts and determine if this is a phishing attempt, extract IOCs, and recommend actions.`,
  100, 2
);
upsertQuestion(lab2, 1,
  'The email "From" field shows: IT Support <it-support@razorpay-helpdesk.com>. Your company domain is razorpay.com. What social engineering technique is being used here?',
  'choice', 'Domain spoofing / lookalike domain',
  ['Email header injection', 'Domain spoofing / lookalike domain', 'SMTP relay hijacking', 'Reply-to poisoning'],
  'This is a lookalike domain attack (typosquatting). "razorpay-helpdesk.com" is not the legitimate "razorpay.com" domain. Attackers register domains that look visually similar to trusted brands and use them to send phishing emails that pass basic visual inspection. Always verify the full sending domain, not just the display name.',
  20, 'Compare the sender domain character by character against the legitimate domain.'
);
upsertQuestion(lab2, 2,
  'You examine the email headers and find: "Received-SPF: fail (domain of razorpay-helpdesk.com does not designate 185.220.101.15 as permitted sender)". What does this tell you?',
  'text', 'spf fail sender not authorized ip not permitted',
  null,
  'An SPF FAIL means the sending IP (185.220.101.15) is NOT listed in the SPF record for razorpay-helpdesk.com as an authorised mail sender. This confirms the email was sent from an unauthorized server — a strong indicator of a phishing or spoofing attack. Note: SPF alone is not sufficient; also check DKIM and DMARC. 185.220.101.15 is a known Tor exit node — elevate this to high severity immediately.',
  20, 'SPF checks whether the sending server is allowed to send email on behalf of that domain.'
);
upsertQuestion(lab2, 3,
  'The email body contains a link: "https://razorpay-helpdesk.com/secure-login?token=aHR0cHM6Ly9yYXpvcnBheS5jb20=". Decode the token parameter and identify what technique is being used.',
  'text', 'base64 redirect open redirect',
  null,
  'The token "aHR0cHM6Ly9yYXpvcnBheS5jb20=" is Base64-encoded. Decoded it is "https://razorpay.com" — this is an open redirect technique. The attacker hosts a redirect page on their phishing domain, which then bounces the victim to the real site after capturing credentials. The victim sees the real razorpay.com URL at the end, reducing suspicion. Always decode suspicious URL parameters during phishing analysis.',
  20, 'Try decoding the token parameter — it looks like it may be encoded.'
);
upsertQuestion(lab2, 4,
  'You extract the following IOCs from the email. Which ONE of these is the highest-priority IOC to submit to your threat intel platform and block at the perimeter first?',
  'choice', 'Source IP: 185.220.101.15 (Tor exit node)',
  ['Sender email: it-support@razorpay-helpdesk.com', 'Source IP: 185.220.101.15 (Tor exit node)', 'Domain: razorpay-helpdesk.com', 'Subject line: Urgent: Verify Your Account'],
  'While all IOCs should be actioned, the Tor exit node IP (185.220.101.15) is the highest priority for immediate perimeter block. Blocking a Tor exit node prevents the attacker from using that C2 channel for any current or future attacks. The domain should be blocked at DNS/proxy simultaneously. The email address is useful for mail gateway rules. Subject lines are too easily changed to be reliable long-term IOCs.',
  20, 'Think about which IOC, if blocked, immediately disrupts the attacker\'s infrastructure.'
);
upsertQuestion(lab2, 5,
  'The targeted user says they clicked the link but "nothing happened." What is your immediate response procedure? List the steps in order.',
  'text', 'isolate contain forensics password reset',
  null,
  'Correct response order: (1) ISOLATE — disconnect the user\'s machine from the network immediately (do not shut it down — preserve volatile memory), (2) CONTAIN — reset the user\'s Active Directory password and revoke all active sessions/tokens, (3) COLLECT — image the machine memory (Volatility) and disk if possible, pull browser history and credential store, (4) ANALYSE — check for persistence (new scheduled tasks, registry run keys, new services), check for lateral movement from that machine, (5) NOTIFY — inform user, HR, and management per IR policy, (6) REMEDIATE — re-image if compromise confirmed, restore from known-good backup.',
  20, 'The user clicked the link. Assume the worst. What do you do first?'
);
console.log('  ✓ Lab 2: Phishing Email Analysis');

// ── LAB 3: Lateral Movement Detection ────────────────────
const lab3 = upsertLab(
  'lateral-movement',
  'Lateral Movement Detection',
  'Alert Triage',
  'Medium',
  `An attacker has gained initial access to WIN-FIN01 via a phishing macro. Intelligence suggests they are now moving laterally through the network toward the domain controller. You are monitoring Windows Security logs, Sysmon events, and network flow data. Your task is to identify the lateral movement techniques being used and map them to MITRE ATT&CK.`,
  150, 3
);
upsertQuestion(lab3, 1,
  'Sysmon Event ID 3 (Network Connection) shows: Source=WIN-FIN01, Destination=WIN-DC01, DestPort=445, Process=cmd.exe. Which lateral movement technique does this most likely indicate?',
  'choice', 'Pass-the-Hash / SMB lateral movement (T1550.002)',
  ['RDP Hijacking (T1563.002)', 'Pass-the-Hash / SMB lateral movement (T1550.002)', 'SSH tunneling (T1572)', 'WMI execution (T1047)'],
  'cmd.exe connecting to a remote host on port 445 (SMB) is a classic Pass-the-Hash or SMB lateral movement indicator. Attackers use harvested NTLM hashes to authenticate to remote systems over SMB without knowing the plaintext password (MITRE T1550.002). Correlate with Event ID 4624 on WIN-DC01 to confirm — look for Logon Type 3 (Network) with NTLM authentication.',
  30, 'Port 445 is SMB. What authentication technique abuses SMB without a plaintext password?'
);
upsertQuestion(lab3, 2,
  'On WIN-DC01, you find Event ID 4624 with Logon Type 3, Authentication Package: NTLM, and the workstation name WIN-FIN01. At the same time, Sysmon shows PSEXESVC.exe created as a new service. Which MITRE technique is this?',
  'text', 'T1569.002 psexec service execution',
  null,
  'This is PsExec lateral movement (MITRE T1569.002 — System Services: Service Execution). The attacker used PsExec (or a PsExec-like tool) over SMB to create a remote service (PSEXESVC.exe) on the domain controller and execute commands. Indicators: (1) PSEXESVC.exe appearing in Event ID 7045 (service installed), (2) Logon Type 3 NTLM from the source host, (3) Pipes named \\PSEXESVC in network traffic. Remediation: block ADMIN$ share access from non-admin workstations.',
  30, 'PSEXESVC.exe is the server-side component of a very well-known sysadmin tool used for remote execution.'
);
upsertQuestion(lab3, 3,
  'You see Windows Event ID 4648 (Logon using explicit credentials) on WIN-FIN01, where the user "svc_backup" is authenticating to multiple hosts in rapid succession — WIN-APP01, WIN-HR01, WIN-FILE01 — all within 90 seconds. What is this behaviour called and what MITRE technique does it map to?',
  'choice', 'Pass-the-Ticket / Credential-based lateral movement (T1550.003)',
  ['Kerberoasting (T1558.003)', 'Pass-the-Ticket / Credential-based lateral movement (T1550.003)', 'DCShadow (T1207)', 'Token Impersonation (T1134)'],
  'Rapid sequential authentication to multiple hosts using a single service account credential is Pass-the-Ticket (T1550.003) or credential-based lateral movement. The attacker has extracted the Kerberos TGT or NTLM hash for svc_backup and is using it to move to multiple targets quickly. The speed (3 hosts in 90 seconds) rules out legitimate admin activity. Escalate immediately — service accounts typically have elevated privileges across multiple systems.',
  30, 'The key indicator is SPEED and BREADTH — one account hitting many systems in seconds.'
);
upsertQuestion(lab3, 4,
  'Sysmon Event ID 1 on WIN-APP01 shows: ParentImage=wmiprvse.exe, Image=powershell.exe, CommandLine="powershell -nop -w hidden -enc JABjAGwAaQBlAG4AdA..." What technique is being used and why is "-enc" significant?',
  'text', 'wmi remote execution encoded powershell obfuscation T1047',
  null,
  'wmiprvse.exe (WMI Provider Host) spawning PowerShell is WMI-based remote execution (MITRE T1047). The "-enc" flag indicates Base64-encoded PowerShell — this is obfuscation (T1027) to hide the actual command from basic string-based detections. Decode the Base64 payload immediately to understand what is executing. WMI lateral movement leaves fewer traces than PsExec (no service installation) and uses legitimate Windows infrastructure, making it harder to detect without Sysmon or WMI activity logging enabled.',
  30, 'What process is wmiprvse.exe and why would it be spawning PowerShell?'
);
upsertQuestion(lab3, 5,
  'You want to detect all four lateral movement techniques covered in this lab using a single SIEM rule logic. Write the core detection condition in plain English (not SPL/KQL) that would catch PsExec, WMI, Pass-the-Hash, and Pass-the-Ticket.',
  'text', 'logon type 3 ntlm non-dc source unusual service creation wmiprvse powershell',
  null,
  'Effective combined detection logic: Alert when ANY of the following occur from a non-domain-controller workstation: (1) Event ID 4624 Logon Type 3 with NTLM auth from a workstation-class machine to another workstation-class machine, (2) PSEXESVC.exe or new service creation (Event 7045) within 60s of a remote logon, (3) wmiprvse.exe spawning any scripting host (powershell.exe, cmd.exe, wscript.exe, cscript.exe), (4) Event ID 4648 from a single source account to 3+ distinct hosts within 5 minutes. Whitelist: domain admin workstations performing known maintenance during approved windows.',
  30, 'Think about what ALL these techniques have in common at the authentication and process level.'
);
console.log('  ✓ Lab 3: Lateral Movement Detection');

// ── LAB 4: SIEM Log Hunting ───────────────────────────────
const lab4 = upsertLab(
  'siem-log-hunting',
  'SIEM Log Hunting',
  'SIEM',
  'Medium',
  `You have access to a Splunk-like SIEM with 72 hours of Windows event logs, proxy logs, and DNS query logs from a suspected compromised environment. An automated alert fired for "Unusual outbound traffic from WIN-APP01." Your job is to write queries, interpret results, and build a timeline of the attack.`,
  150, 4
);
upsertQuestion(lab4, 1,
  'You want to find all failed logon attempts (Event ID 4625) in the last 24 hours, grouped by username, showing only accounts with more than 10 failures. Write this as a Splunk SPL query.',
  'text', 'index sourcetype EventCode=4625 stats count by',
  null,
  'Correct SPL: index=windows sourcetype="WinEventLog:Security" EventCode=4625 earliest=-24h | stats count by Account_Name | where count > 10 | sort -count\n\nKey elements: (1) index and sourcetype scoping, (2) EventCode filter, (3) time range with earliest=, (4) stats count by Account_Name to group, (5) where clause to threshold, (6) sort descending. Common mistake: forgetting the time constraint — always scope queries to avoid scanning all historical data and impacting SIEM performance.',
  30, 'The key SPL commands here are: stats, where, and sort.'
);
upsertQuestion(lab4, 2,
  'Your proxy logs show this entry: 2024-01-15 10:23:41, src=192.168.1.45, dst=185.220.101.15, method=POST, url=/api/update, bytes_out=142, bytes_in=8421, duration=30001ms. What is suspicious about this log entry and what MITRE technique does it suggest?',
  'text', 'c2 beaconing long duration large download small upload T1071',
  null,
  'Multiple red flags: (1) Destination 185.220.101.15 is a known Tor exit node / malicious IP, (2) POST to /api/update — suspicious exfiltration or C2 check-in disguised as an API call, (3) bytes_out=142 (small beacon) but bytes_in=8421 (large response — likely tasking or payload download), (4) duration=30001ms — exactly 30 seconds suggests automated/scripted beaconing rather than human activity. This maps to MITRE T1071.001 (Web Protocols C2) and T1041 (Exfiltration over C2 channel). Add this IP and URI pattern to your blocklist immediately.',
  30, 'Look at every field: direction of data transfer, timing, destination reputation.'
);
upsertQuestion(lab4, 3,
  'You run a DNS query log search and find WIN-APP01 resolving the domain "update.meridian-security-patch.com" every 300 seconds, exactly, for the last 6 hours. What technique is this and what makes the 300-second interval significant?',
  'choice', 'C2 beaconing with fixed interval (T1071) — regularity reveals automation',
  ['DNS tunneling (T1071.004) — data encoded in DNS queries', 'C2 beaconing with fixed interval (T1071) — regularity reveals automation', 'Domain Generation Algorithm (T1568.002) — random domains per connection', 'Fast flux DNS (T1568.001) — rapidly changing IP resolutions'],
  'Fixed-interval DNS resolution (exactly every 300 seconds for 6 hours = 72 queries) is C2 beaconing (MITRE T1071). The regularity is the giveaway — humans do not access resources at perfectly timed intervals. Malware sleep timers produce this pattern. Detection approach: calculate the standard deviation of inter-request intervals. Legitimate browsing has high variance; beacons have near-zero variance. "meridian-security-patch.com" is also a DGA-style lookalike domain designed to appear legitimate.',
  30, 'What does "exactly 300 seconds, every time, for 6 hours" tell you about who or what is making these requests?'
);
upsertQuestion(lab4, 4,
  'You need to correlate the DNS beacon with process activity. Write a Splunk SPL query that joins DNS logs and Sysmon process creation logs to find which process on WIN-APP01 is making DNS requests to domains containing "meridian".',
  'text', 'join lookup dns sysmon process dns query',
  null,
  'Approach using join or lookup:\n\nindex=dns src_host=WIN-APP01 query="*meridian*" | table _time, src_host, query, src_pid\n| join src_pid [search index=sysmon EventCode=1 host=WIN-APP01 | table ProcessId, Image, CommandLine, ParentImage]\n\nAlternatively with stats:\nindex=sysmon OR index=dns host=WIN-APP01 | eval pid=coalesce(src_pid, ProcessId) | stats values(query) as dns_queries values(Image) as process by pid | where isnotnull(dns_queries) AND isnotnull(process)\n\nThe key insight: correlate by process ID (PID) and timestamp proximity. Sysmon Event ID 22 (DNS Query) directly logs which process made each DNS request — always enable this.',
  30, 'Sysmon Event ID 22 directly records DNS queries with the originating process. Use that.'
);
upsertQuestion(lab4, 5,
  'Based on all findings in this lab (failed logons, C2 beacon, proxy POST, DNS beaconing), assign a MITRE ATT&CK kill chain stage to this attack. What stage are you most likely observing, and what stage likely comes next?',
  'text', 'command and control C2 exfiltration lateral movement',
  null,
  'Current stage: Command & Control (TA0011). The evidence — regular beaconing to a known-bad IP, POST requests with large inbound data, DNS queries to suspicious domains — all indicate an active C2 channel is established. The attacker has persistence and is receiving tasking. What comes next depends on attacker objective: (1) Collection (TA0009) — staging data for exfiltration, (2) Lateral Movement (TA0008) — using WIN-APP01 as a pivot to reach higher-value targets, (3) Exfiltration (TA0010) — the large bytes_in from the proxy log may already be inbound tools for exfiltration. Priority: sever the C2 channel first (block IP/domain at firewall and DNS resolver), then investigate what data may already be staged.',
  30, 'You have C2. What are the logical next steps an attacker would take from here?'
);
console.log('  ✓ Lab 4: SIEM Log Hunting');

// ── LAB 5: Ransomware Incident Response ──────────────────
const lab5 = upsertLab(
  'ransomware-ir',
  'Ransomware Incident Response',
  'Incident Response',
  'Hard',
  `CRITICAL INCIDENT — P1. It is 02:47 AM. The NOC has received automated alerts: mass file rename events on WIN-FILE01, CPU spike to 98%, and users are reporting their files show a ".locked" extension. A ransom note "README_DECRYPT.txt" has been found on the desktop of multiple users. You are the on-call L2 analyst. This lab walks you through the full IR lifecycle for a ransomware event.`,
  200, 5
);
upsertQuestion(lab5, 1,
  'The first alert you receive is at 02:47 AM. Your first action is to check the blast radius. Which SIEM query logic tells you how many hosts have been affected by the .locked extension rename activity?',
  'choice', 'Search Sysmon Event ID 11 (FileCreate) where TargetFilename ends in .locked, group by host',
  ['Search Event ID 4663 (file access) for .locked across all hosts', 'Search Sysmon Event ID 11 (FileCreate) where TargetFilename ends in .locked, group by host', 'Search Event ID 4698 (scheduled task) for ransom-related task names', 'Search proxy logs for outbound POST requests from all hosts'],
  'Sysmon Event ID 11 (FileCreate) captures file creation and rename events including the target filename. Filtering for filenames ending in ".locked" and grouping by host gives you the blast radius instantly. Event ID 4663 (Object Access) requires file system auditing to be enabled (often it is not). This query should be your first action — knowing how many hosts are affected determines whether you isolate individually or segment the entire VLAN.',
  40, 'You need to find file rename/create events. Which Sysmon event captures new file creation including renames?'
);
upsertQuestion(lab5, 2,
  'You confirm 3 hosts are actively encrypting: WIN-FILE01, WIN-HR01, WIN-APP01. What is the correct CONTAINMENT order and why does the sequence matter?',
  'text', 'file server first network isolation vlan segment preserve evidence',
  null,
  'Correct containment order and rationale: (1) WIN-FILE01 FIRST — it is the file server. Isolating it stops the most data loss per second. Pull the network cable or disable the NIC via remote tool — do NOT shut down (loses volatile memory with encryption keys potentially in RAM). (2) Network segment isolation — disable the VLAN or ACL-block inter-VLAN routing to prevent spread to other segments while you handle individual hosts. (3) WIN-HR01 and WIN-APP01 — isolate in parallel once file server is contained. Sequence matters because ransomware spreads via network shares. WIN-FILE01 has the most mapped drives — containing it stops the encryption cascade even before you reach the other hosts.',
  40, 'Think about which host, if isolated first, stops the most damage per second.'
);
upsertQuestion(lab5, 3,
  'You find the ransomware process: "svchost.exe" running from C:\\Users\\svc_backup\\AppData\\Local\\Temp\\svchost.exe (note: NOT the real svchost.exe in System32). What are the two MITRE techniques being used here simultaneously?',
  'text', 'T1036 masquerading T1074 data staged user writeable directory',
  null,
  'Two techniques: (1) T1036.005 — Masquerading: Match Legitimate Name or Location. The malware is named "svchost.exe" to blend in with the legitimate Windows process. The key detection: legitimate svchost.exe ALWAYS runs from C:\\Windows\\System32\\. Any svchost.exe outside of System32 is malicious. (2) T1074.001 — Data Staged: Local Data Staging / execution from user-writable temp directory. AppData\\Local\\Temp is user-writable without admin rights — attackers drop payloads here to avoid UAC and to persist under user context. Detection rule: alert on ANY executable running from %TEMP%, %APPDATA%, or Downloads that matches the name of a known Windows system process.',
  40, 'Look at both the filename AND the path. What is abnormal about each?'
);
upsertQuestion(lab5, 4,
  'Memory forensics on WIN-FILE01 shows the encryption key in process memory. What Volatility 3 command extracts the memory of the malicious svchost.exe process (PID 3847) to a file for analysis?',
  'choice', 'python vol.py -f memory.dmp windows.memmap --pid 3847 --dump',
  ['python vol.py -f memory.dmp windows.strings --pid 3847', 'python vol.py -f memory.dmp windows.memmap --pid 3847 --dump', 'python vol.py -f memory.dmp windows.procdump --pid 3847', 'python vol.py -f memory.dmp windows.dlllist --pid 3847'],
  'windows.memmap --pid <PID> --dump extracts the full virtual memory map of a specific process to disk, giving you the raw memory pages where the encryption key material lives. windows.procdump dumps the PE executable itself (useful for malware analysis) but not the runtime memory contents. windows.strings extracts printable strings but does not dump raw memory. For key recovery, you need the full memory pages — use memmap --dump, then grep or use specialized tools like photorec or custom scripts to locate key material patterns.',
  40, 'You need the PROCESS MEMORY CONTENTS, not just the executable. Which command dumps live process memory pages?'
);
upsertQuestion(lab5, 5,
  'The incident is contained. Write the five mandatory sections of a P1 Incident Report for this ransomware event. Just name the five section headings and one sentence describing what goes in each.',
  'text', 'executive summary timeline technical findings impact remediation',
  null,
  'Five mandatory P1 Incident Report sections: (1) Executive Summary — one paragraph, non-technical, for CISO/management: what happened, when, business impact, current status. (2) Incident Timeline — chronological table: time, event, actor, evidence source. From first IOC to full containment. (3) Technical Findings — attack chain mapped to MITRE ATT&CK: initial access vector, persistence, lateral movement, impact. Include all IOCs (IPs, hashes, domains, file paths). (4) Impact Assessment — systems affected, data potentially exfiltrated, business functions disrupted, regulatory/compliance implications (GDPR notification required within 72h if PII affected). (5) Remediation & Lessons Learned — immediate actions taken, long-term hardening recommendations, detection gaps identified, what controls would have caught this earlier.',
  40, 'Think about what a CISO, a technical investigator, and a compliance officer each need to read in that report.'
);
console.log('  ✓ Lab 5: Ransomware Incident Response');

// ── LAB 6: APT Threat Hunting ────────────────────────────
const lab6 = upsertLab(
  'threat-hunting-apt',
  'APT Threat Hunting',
  'Threat Hunting',
  'Hard',
  `No alerts have fired. But threat intelligence reports that APT group "IRON TWILIGHT" — known for targeting financial sector organisations in South Asia — has been observed using a new toolset. You have a TTP profile and must proactively hunt for signs of compromise in your environment. This lab teaches hypothesis-driven threat hunting: you start from TTPs, not alerts.`,
  200, 6
);
upsertQuestion(lab6, 1,
  'IRON TWILIGHT is known to use LOLBins (Living Off the Land Binaries) for execution. Which of the following is NOT a LOLBin?',
  'choice', 'mimikatz.exe',
  ['certutil.exe', 'mshta.exe', 'mimikatz.exe', 'regsvr32.exe'],
  'mimikatz.exe is NOT a LOLBin — it is a standalone offensive tool that must be dropped onto the system. LOLBins are legitimate Windows binaries that come pre-installed and can be abused for malicious purposes. certutil.exe (T1140 — can decode Base64, download files), mshta.exe (T1218.005 — executes HTA files / VBScript), and regsvr32.exe (T1218.010 — executes DLLs/COM scripts, "Squiblydoo" technique) are all LOLBins. Hunting for LOLBins: focus on unusual parent processes, unusual arguments, and network connections made by these binaries.',
  40, 'LOLBins are binaries that are ALREADY on Windows. Which of these options had to be downloaded by an attacker?'
);
upsertQuestion(lab6, 2,
  'Your hunt hypothesis: "IRON TWILIGHT uses certutil.exe to download secondary payloads." Write the Sysmon-based hunt query logic (in plain English) to find this activity.',
  'text', 'sysmon event id 1 certutil urlcache split http network connection',
  null,
  'Hunt query logic: Search Sysmon Event ID 1 (Process Create) where Image ends with "certutil.exe" AND CommandLine contains any of: "-urlcache", "-split", "-decode", "http://", "https://", "-f". Additionally correlate with Sysmon Event ID 3 (Network Connection) where Image=certutil.exe — certutil should NEVER make outbound network connections in a normal environment. False positive baseline: certutil legitimately runs for certificate operations but should NOT have -urlcache or outbound network activity. Any hit on this query should be treated as high confidence TP.',
  40, 'certutil has a specific flag used for downloading files from the internet. What is it?'
);
upsertQuestion(lab6, 3,
  'IRON TWILIGHT is known to use Registry Run Keys for persistence. You are writing a hunt across 500 endpoints. What Sysmon Event ID captures Registry modifications, and what specific run key paths should you hunt?',
  'choice', 'Event ID 13 — HKCU/HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run and RunOnce',
  ['Event ID 12 — HKLM\\SYSTEM\\CurrentControlSet\\Services', 'Event ID 13 — HKCU/HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run and RunOnce', 'Event ID 14 — HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'Event ID 11 — any .reg file creation in temp directories'],
  'Sysmon Event ID 13 (RegistryEvent — Value Set) captures registry value writes. The canonical persistence run key paths to hunt: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run, HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run, HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce, HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce. Also hunt: HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon (Userinit, Shell values) and HKCU\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Load. Filter out known-good software update entries using a whitelist of legitimate publisher paths.',
  40, 'There are multiple Sysmon registry event IDs. Which one specifically captures when a value is WRITTEN/SET?'
);
upsertQuestion(lab6, 4,
  'You find a suspicious DLL: C:\\ProgramData\\Intel\\telemetry.dll — it was written 3 days ago, has no digital signature, and is loaded by svchost.exe. What technique is this and how do you confirm it?',
  'text', 'DLL search order hijacking T1574 side loading unsigned dll verify hash vt',
  null,
  'This is DLL Search Order Hijacking or DLL Side-Loading (MITRE T1574.001/T1574.002). Attackers place a malicious DLL with a name that a legitimate process will load, in a directory that appears before the legitimate DLL in the search order. Confirmation steps: (1) Hash the DLL (Get-FileHash in PowerShell) and check against VirusTotal — any detections confirm malicious, (2) Use Sysinternals Sigcheck to verify digital signature — legitimate Windows/Intel DLLs are signed, (3) Use Process Monitor to confirm svchost.exe is actually loading this specific file, (4) Check DLL exports with tools like CFF Explorer — compare against the legitimate DLL, (5) Check the DLL\'s import table for suspicious functions (CreateRemoteThread, VirtualAllocEx, WSAConnect).',
  40, 'The DLL is in ProgramData (not System32) and is unsigned. What persistence technique places malicious DLLs where legitimate programs will load them?'
);
upsertQuestion(lab6, 5,
  'You have confirmed IRON TWILIGHT has been present in the network for approximately 72 hours without triggering any alerts. What are the THREE most critical gaps in your detection coverage that allowed this, and what is the single most impactful control you would implement first?',
  'text', 'sysmon not deployed lolbin whitelist registry monitoring gap detection',
  null,
  'The three critical detection gaps revealed by this scenario: (1) No Sysmon deployment or incomplete deployment — LOLBin abuse, registry modifications, and DLL loads would all be invisible without Sysmon. Deploy Sysmon with the SwiftOnSecurity config immediately across all endpoints. (2) No application whitelisting — certutil, mshta, regsvr32 should be blocked from making network connections or executing scripts via AppLocker or Windows Defender Application Control (WDAC). (3) No DLL integrity monitoring — unsigned DLLs loaded by system processes should trigger alerts. Implement a baseline of all DLLs loaded by svchost.exe and alert on deviations. Most impactful single control: deploy Sysmon organisation-wide with a hardened configuration. It costs nothing, requires no infrastructure, and immediately gives you visibility into process creation, network connections, registry changes, and file writes — the four pillars of endpoint detection.',
  40, 'Think about what telemetry was MISSING that allowed each technique to go undetected.'
);
console.log('  ✓ Lab 6: APT Threat Hunting');

console.log('\nSeed complete. Database ready at:', DB_PATH);
db.close();
