'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const DB_FILE = path.join(__dirname, '..', 'database', 'diaas.db');
const BACKUP_FILE = path.join(__dirname, '..', 'database', 'diaas.db.test-backup');

let serverModule;
let server;
let baseUrl;

function resetSeededDb() {
  execFileSync('node', ['database/seed.js'], {
    cwd: path.join(__dirname, '..'),
    stdio: 'ignore'
  });
}

async function api(url, { method = 'GET', token, body, headers = {} } = {}) {
  const finalHeaders = { ...headers };
  if (token) finalHeaders.Authorization = `Bearer ${token}`;
  if (body !== undefined) finalHeaders['Content-Type'] = 'application/json';
  const res = await fetch(`${baseUrl}${url}`, {
    method,
    headers: finalHeaders,
    body: body !== undefined ? JSON.stringify(body) : undefined
  });
  const text = await res.text();
  let data = null;
  if (text) {
    try { data = JSON.parse(text); } catch { data = text; }
  }
  return { status: res.status, data };
}

async function login(username, password) {
  const res = await api('/api/auth/login', {
    method: 'POST',
    body: { username, password }
  });
  assert.equal(res.status, 200, JSON.stringify(res.data));
  assert.ok(res.data.token);
  return res.data.token;
}

test.before(async () => {
  if (fs.existsSync(BACKUP_FILE)) fs.rmSync(BACKUP_FILE, { force: true });
  if (fs.existsSync(DB_FILE)) fs.copyFileSync(DB_FILE, BACKUP_FILE);
  resetSeededDb();
  serverModule = require('../server');
  server = await serverModule.startServer(0, '127.0.0.1');
  const address = server.address();
  baseUrl = `http://127.0.0.1:${address.port}`;
});

test.after(async () => {
  if (serverModule?.stopServer) await serverModule.stopServer();
  if (serverModule?.sessionCleanupTimer) clearInterval(serverModule.sessionCleanupTimer);
  if (fs.existsSync(BACKUP_FILE)) {
    fs.copyFileSync(BACKUP_FILE, DB_FILE);
    fs.rmSync(BACKUP_FILE, { force: true });
  }
});

test('labs API exposes mapped lab IDs, session tags, and all 19 curriculum additions', async () => {
  const token = await login('analyst_01', 'Analyst@2024');
  const res = await api('/api/labs', { token });
  assert.equal(res.status, 200, JSON.stringify(res.data));
  assert.ok(Array.isArray(res.data));
  assert.equal(res.data.length, 101, `expected 101 labs after adding 19 missing labs, got ${res.data.length}`);

  const mappedExpectations = [
    ['Network Traffic Analysis', 'S2-D1-L8', 'Stack 2 · Day 1 · Networking Fundamentals'],
    ['SOC Fundamentals & Alert Workflow', 'S3-D1-L1', 'Stack 3 · Day 6 · SOC Foundations'],
    ['Alert Triage Fundamentals', 'S3-D1-L2', 'Stack 3 · Day 6 · SOC Foundations'],
    ['Supply Chain Attacks — SolarWinds, 3CX, XZ Utils', 'ADV-33', 'Additional Labs · Real-World CVEs'],
    ['CVE Exploitation in the Wild — MOVEit, Citrix Bleed, PaperCut', 'ADV-34', 'Additional Labs · Real-World CVEs'],
    ['SOC Capstone — Full Incident from Alert to IR Report', 'S3-CAP-B', 'Stack 3 · Day 10 · Capstone: Operation Flashpoint']
  ];

  for (const [title, labId, sessionTag] of mappedExpectations) {
    const lab = res.data.find(l => l.title === title);
    assert.ok(lab, `${title} lab missing`);
    assert.equal(lab.lab_id, labId, `${title} lab_id mismatch`);
    assert.equal(lab.session_tag, sessionTag, `${title} session_tag mismatch`);
  }

  const expectedNewLabs = [
    ['S2-D1-L1', 'Network Concepts — OSI and TCP/IP Layer Classification', 'Network Security'],
    ['S2-D1-L3', 'IP Addressing — Subnet Calculation and NAT Analysis', 'Network Security'],
    ['S2-D1-L4', 'Port and Protocol Speed Round — 20 Ports Every Analyst Must Know', 'Network Security'],
    ['S2-D1-L6', 'HTTP Request Analysis — Methods, Status Codes, Anomaly Detection', 'Network Security'],
    ['S2-D1-L7', 'Firewall Rule Analysis — Permitted vs Blocked Traffic', 'Network Security'],
    ['S2-D2-L1', 'Windows Architecture — Kernel vs Userland Process Classification', 'Windows Security'],
    ['S2-D2-L6', 'Autoruns Persistence — Before and After Snapshot Diff', 'Windows Security'],
    ['S2-D2-L7', 'Netstat Analysis — Identifying the Attacker C2 Session', 'Windows Security'],
    ['S2-D2-L8', 'PowerShell Analyst Challenge — Suspicious Process Identification', 'Windows Security'],
    ['S2-D3-L1', 'Linux Filesystem Forensics — Suspicious /tmp Artefacts', 'Linux Security'],
    ['S2-D3-L3', 'Linux Process Tree — Reverse Shell Detection', 'Linux Security'],
    ['S2-D3-L4-B', 'Linux Log Anatomy — Multi-Source Field Extraction', 'Linux Security'],
    ['S2-D3-L5', 'Linux Command Challenge — grep, awk, sort, uniq Pipelines', 'Linux Security'],
    ['S2-D4-L1', 'AWS Service Identification — CloudTrail EventSource Mapping', 'Cloud Security'],
    ['S2-D4-L2', 'IAM Policy Review — Over-Privileged Permission Detection', 'Cloud Security'],
    ['S2-D4-L3', 'CloudTrail JSON Anatomy — Field Extraction and Event Analysis', 'Cloud Security'],
    ['S2-D5-L1', 'Python Script Reading — IOC Extraction Script Comprehension', 'Log Analysis'],
    ['S2-D5-L2', 'Bash Pipeline Builder — Analyst Command Construction', 'Log Analysis'],
    ['S2-D5-L3', 'Log Format Recognition — Syslog, JSON, CEF, XML, CSV', 'Log Analysis']
  ];

  for (const [labId, title, category] of expectedNewLabs) {
    const lab = res.data.find(l => l.lab_id === labId);
    assert.ok(lab, `${labId} missing`);
    assert.equal(lab.title, title, `${labId} title mismatch`);
    assert.equal(lab.category, category, `${labId} category mismatch`);
    assert.equal(lab.difficulty, 'beginner', `${labId} difficulty mismatch`);
    assert.equal(lab.points, 100, `${labId} points mismatch`);
  }
});

test('analyst labs page renders lab ID above title and session tag below badges', async () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'analyst', 'index.html'), 'utf8');
  assert.match(html, /class="lab-card-labid"/, 'expected lab id block in lab card');
  assert.match(html, /class="lab-card-session-tag"/, 'expected session tag block in lab card');
  assert.match(html, /\$\{l\.lab_id \? `<div class="lab-card-labid">\[\$\{escapeHtml\(l\.lab_id\)\}\]<\/div>` : ''\}/, 'expected lab id renderer above title');
  assert.match(html, /\$\{l\.session_tag \? `<div class="lab-card-session-tag">\$\{escapeHtml\(l\.session_tag\)\}<\/div>` : ''\}/, 'expected session tag renderer');
});
