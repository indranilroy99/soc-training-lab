'use strict';

// ── Learning paths ─────────────────────────────────────────────────────────
// Structured learning paths that guide trainees through the curriculum.
// Each path is a curated sequence of labs from easiest to hardest.

const { db } = require('../db');

// ── Path definitions ──────────────────────────────────────────────────────
const LEARNING_PATHS = [
  {
    id: 'soc-foundations',
    title: 'SOC Analyst Foundations',
    description: 'Master the core skills every SOC analyst needs: alert triage, network fundamentals, Windows and Linux security basics, and cloud awareness. Ideal starting point for all trainees.',
    icon: '🛡️',
    difficulty: 'Beginner',
    estimated_hours: 8,
    tags: ['beginner', 'essential', 'stack2'],
    lab_slugs: [
      'soc-fundamentals', 'alert-triage-basics',
      's2-d1-l1-network-concepts', 's2-d1-l3-ip-addressing',
      's2-d1-l4-port-protocol-speed-round', 's2-d1-l6-http-request-analysis',
      's2-d1-l7-firewall-rule-analysis', 'network-traffic-analysis',
      's2-d2-l1-windows-architecture', 'windows-event-logs',
      's2-d2-l6-autoruns-persistence', 's2-d2-l7-netstat-analysis',
      's2-d3-l1-linux-filesystem-forensics', 's2-d3-l3-linux-process-tree',
    ],
    order_index: 1,
  },
  {
    id: 'threat-detection',
    title: 'Threat Detection & Log Analysis',
    description: 'Deep-dive into threat detection: read Wazuh, Suricata, and Zeek logs, identify attack patterns, detect credential attacks, and analyse malware indicators.',
    icon: '🔍',
    difficulty: 'Intermediate',
    estimated_hours: 10,
    tags: ['intermediate', 'logs', 'detection'],
    lab_slugs: [
      'lab-s2-01', 'lab-s2-02', 'lab-s2-03', 'lab-s2-04', 'lab-s2-05',
      'lab-s2-06', 'lab-s2-07', 'lab-s2-08', 'lab-s2-09',
      'credential-attacks', 'malware-analysis',
      's2-d3-l4-b-linux-log-anatomy', 's2-d3-l5-linux-command-challenge',
      's2-d5-l1-python-script-reading', 's2-d5-l2-bash-pipeline-builder',
      's2-d5-l3-log-format-recognition',
    ],
    order_index: 2,
  },
  {
    id: 'cloud-security',
    title: 'Cloud Security Operations',
    description: 'Investigate AWS-native attacks: CloudTrail forensics, IAM abuse, GuardDuty findings, S3 data exposure, and multi-stage cloud attack chains.',
    icon: '☁️',
    difficulty: 'Intermediate',
    estimated_hours: 6,
    tags: ['cloud', 'aws', 'intermediate'],
    lab_slugs: [
      's2-d4-l1-aws-service-identification', 's2-d4-l2-iam-policy-review',
      's2-d4-l3-cloudtrail-json-anatomy', 'lab-s2-10', 'lab-s2-11',
      'lab-s2-16', 'lab-s3c-07', 'lab-sp-04', 'lab-sp-05',
      'cloud-security-incidents',
    ],
    order_index: 3,
  },
  {
    id: 'incident-response',
    title: 'Incident Response Practitioner',
    description: 'Apply the full NIST 800-61 IR lifecycle to real incidents: triage correlated alerts, execute containment and eradication, and write post-incident RCA reports.',
    icon: '🚨',
    difficulty: 'Advanced',
    estimated_hours: 12,
    tags: ['incident-response', 'advanced'],
    lab_slugs: [
      'incident-response-playbooks', 'lab-s2-20',
      'lab-s3c-14', 'lab-s3c-15', 'lab-s3c-08',
      'ransomware-ir', 'operation-blackout-containment',
      'operation-blackout-eradication', 'operation-blackout-recovery',
      'operation-blackout-rca', 'lab-sp-08', 'lab-sp-13',
    ],
    order_index: 4,
  },
  {
    id: 'threat-hunting',
    title: 'Advanced Threat Hunting',
    description: 'Hunt for hidden adversaries using MITRE ATT&CK, detect APTs, Cobalt Strike beacons, memory-resident malware, and sophisticated lateral movement.',
    icon: '🎯',
    difficulty: 'Advanced',
    estimated_hours: 14,
    tags: ['threat-hunting', 'advanced', 'mitre'],
    lab_slugs: [
      'threat-hunting', 'exfiltration-detection',
      'lateral-movement', 'lab-s3c-05',
      'advanced-persistent-threats', 'lab-sp-02',
      'lab-s3c-11', 'lab-sp-12',
      'red-team-detection', 'lab-sp-20',
    ],
    order_index: 5,
  },
  {
    id: 'active-directory',
    title: 'Active Directory Attack & Defence',
    description: 'Master AD-focused attacks and defences: Kerberoasting, Golden Tickets, DCSync, Pass-the-Hash, privilege escalation chains, and domain compromise response.',
    icon: '🏰',
    difficulty: 'Expert',
    estimated_hours: 10,
    tags: ['active-directory', 'expert', 'windows'],
    lab_slugs: [
      'lab-s3c-01', 'lab-s3c-02', 'lab-s3c-06',
      'lab-sp-01', 'lab-sp-06', 'lab-sp-07',
      'lab-sp-21',
    ],
    order_index: 6,
  },
];

// ── Seed learning paths ───────────────────────────────────────────────────
function seedLearningPaths() {
  const insert = db.prepare(
    `INSERT OR IGNORE INTO learning_paths
       (id, title, description, icon, difficulty, estimated_hours, tags, lab_slugs, order_index)
     VALUES (?,?,?,?,?,?,?,?,?)`
  );
  const tx = db.transaction(() => {
    for (const p of LEARNING_PATHS) {
      insert.run(
        p.id, p.title, p.description, p.icon, p.difficulty,
        p.estimated_hours,
        JSON.stringify(p.tags),
        JSON.stringify(p.lab_slugs),
        p.order_index
      );
    }
  });
  tx();
}

// ── Get all paths with user progress ─────────────────────────────────────
function getPathsWithProgress(userId) {
  const paths = db.prepare(
    `SELECT * FROM learning_paths ORDER BY order_index`
  ).all();

  // Batch: get all completed labs for this user
  const completedSlugs = new Set(
    db.prepare(
      `SELECT l.slug FROM user_progress up JOIN labs l ON l.id=up.lab_id
       WHERE up.user_id=? AND up.status='completed'`
    ).all(userId).map(r => r.slug)
  );

  return paths.map(p => {
    const slugs = JSON.parse(p.lab_slugs || '[]');
    const tags  = JSON.parse(p.tags || '[]');
    const done  = slugs.filter(s => completedSlugs.has(s)).length;
    return {
      id:              p.id,
      title:           p.title,
      description:     p.description,
      icon:            p.icon,
      difficulty:      p.difficulty,
      estimated_hours: p.estimated_hours,
      tags,
      lab_slugs:       slugs,
      total_labs:      slugs.length,
      completed_labs:  done,
      pct:             slugs.length ? Math.round((done / slugs.length) * 100) : 0,
      completed:       done >= slugs.length && slugs.length > 0,
    };
  });
}

module.exports = { LEARNING_PATHS, seedLearningPaths, getPathsWithProgress };
