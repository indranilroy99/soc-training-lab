'use strict';

const { db }                 = require('../db');
const { requireAuth }        = require('../middleware/auth');
const { parseBody }          = require('../middleware/security');
const { ok, notFound, badRequest } = require('../middleware/response');
const { getUserAlertStatus, setUserAlertStatus } = require('../services/users');
const { scoreIRAnswers, pointsFromScore }         = require('../services/scoring');

const TP_BLACKLIST = ['[benign]', 'false positive'];
function isTruePositive(alert) {
  const title = String(alert.title || '').toLowerCase();
  const cat   = String(alert.category || '').toLowerCase();
  return !TP_BLACKLIST.some(t => title.includes(t)) && !cat.includes('test');
}

// GET /api/alerts
function listAlerts(req, res) {
  const user   = requireAuth(req, res); if (!user) return;
  const url    = req.url;
  const qs     = url.includes('?') ? new URLSearchParams(url.split('?')[1]) : new URLSearchParams();

  const severity = qs.get('severity');
  const category = qs.get('category');
  const search   = qs.get('q');
  const status   = qs.get('status');
  const limit    = Math.min(parseInt(qs.get('limit') || '100', 10), 200);
  const offset   = Math.max(0, parseInt(qs.get('offset') || '0', 10));

  const where = []; const args = [];
  if (severity) { where.push('severity=?'); args.push(severity); }
  if (category) { where.push('category=?'); args.push(category); }
  if (search) {
    where.push('(title LIKE ? OR description LIKE ? OR host LIKE ? OR src_ip LIKE ? OR mitre_technique LIKE ?)');
    const q = `%${search}%`; args.push(q, q, q, q, q);
  }
  const whereStr = where.length ? `WHERE ${where.join(' AND ')}` : '';

  let alerts = db.prepare(
    `SELECT id, severity, category, title, source, host, src_ip, dst_ip, username,
            process, event_id, mitre_tactic, mitre_technique, status, timestamp
     FROM soc_alerts ${whereStr}
     ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,
              timestamp DESC
     LIMIT ? OFFSET ?`
  ).all(...args, limit, offset).map(a => ({
    ...a,
    status: user.role === 'admin' ? a.status : getUserAlertStatus(user.id, a.id, a.status),
  }));

  if (status) alerts = alerts.filter(a => a.status === status);

  const total = status
    ? alerts.length
    : db.prepare(`SELECT COUNT(*) as c FROM soc_alerts ${whereStr}`).get(...args).c;

  const counts = db.prepare(`SELECT severity, COUNT(*) as n FROM soc_alerts GROUP BY severity`)
    .all().reduce((acc, r) => { acc[r.severity] = r.n; return acc; }, {});

  return ok(res, { alerts, total, counts });
}

// GET /api/alerts/:id
function getAlert(req, res, alertId) {
  const user  = requireAuth(req, res); if (!user) return;
  const alert = db.prepare(`SELECT * FROM soc_alerts WHERE id=?`).get(alertId);
  if (!alert) return notFound(res, 'Alert not found');

  ['iocs','timeline','network_flow'].forEach(f => {
    try { alert[f] = JSON.parse(alert[f] || 'null'); } catch { alert[f] = null; }
  });

  if (user.role !== 'admin') {
    alert.status = getUserAlertStatus(user.id, alert.id, alert.status);
  }
  return ok(res, alert);
}

// POST /api/alerts/:id/status
async function updateAlertStatus(req, res, alertId) {
  const user = requireAuth(req, res); if (!user) return;
  const body = await parseBody(req);
  const { status, triage_reason, containment_steps, eradication_steps,
          recovery_steps, rca_notes, fp_reason } = body;

  const ALLOWED = ['open', 'investigating', 'false_positive', 'closed'];
  if (!ALLOWED.includes(status)) return badRequest(res, `status must be one of: ${ALLOWED.join(', ')}`);

  const alert = db.prepare('SELECT id, category, title, severity FROM soc_alerts WHERE id=?').get(alertId);
  if (!alert) return notFound(res, 'Alert not found');

  if (status === 'false_positive' && !fp_reason?.trim()) {
    return badRequest(res, 'Justification required to close as false positive');
  }
  if (status === 'closed') {
    const required = { triage_reason, containment_steps, eradication_steps, recovery_steps, rca_notes };
    const missing  = Object.entries(required).filter(([, v]) => !v?.trim()).map(([k]) => k);
    if (missing.length) return badRequest(res, `All IR steps are required. Missing: ${missing.join(', ')}`);
  }

  let points_awarded = 0, is_correct = 0, investigation_score = 0;
  let step_scores = {}, scoring_feedback = [];

  if (status === 'closed' || status === 'false_positive') {
    const isTP = isTruePositive(alert);

    if (status === 'closed' && isTP) {
      is_correct = 1;
      const result = scoreIRAnswers(alertId, { triage_reason, containment_steps, eradication_steps, recovery_steps, rca_notes });
      investigation_score = result.investigation_score;
      step_scores         = result.step_scores;
      scoring_feedback    = result.feedback;
      points_awarded      = pointsFromScore(investigation_score);
    } else if (status === 'false_positive' && !isTP) {
      is_correct = 1; points_awarded = 3;
    }

    db.prepare(
      `INSERT INTO alert_closures
         (alert_id, user_id, classification, triage_reason, containment_steps,
          eradication_steps, recovery_steps, rca_notes, fp_reason,
          is_correct, points_awarded, investigation_score, step_scores, scoring_feedback)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
    ).run(alertId, user.id, status,
          triage_reason || null, containment_steps || null,
          eradication_steps || null, recovery_steps || null,
          rca_notes || null, fp_reason || null,
          is_correct, points_awarded, investigation_score || 0,
          JSON.stringify(step_scores || {}), JSON.stringify(scoring_feedback || []));

    if (points_awarded > 0) {
      db.prepare('UPDATE users SET points=COALESCE(points,0)+? WHERE id=?').run(points_awarded, user.id);
    }
  }

  setUserAlertStatus(user.id, alertId, status);

  return ok(res, {
    alertId, status, is_correct, points_awarded,
    investigation_score: investigation_score || 0,
    step_scores:         step_scores || {},
    scoring_feedback:    scoring_feedback || [],
  });
}

// GET/POST /api/alerts/:id/incident
function getIncident(req, res, alertId) {
  const user = requireAuth(req, res); if (!user) return;
  const inc  = db.prepare('SELECT * FROM incidents WHERE alert_id=? AND user_id=?').get(alertId, user.id);
  return ok(res, inc || null);
}

async function upsertIncident(req, res, alertId) {
  const user = requireAuth(req, res); if (!user) return;
  const { stage, notes, title } = await parseBody(req);
  const VALID_STAGES = ['identification','containment','eradication','recovery','rca','closed'];
  if (!VALID_STAGES.includes(stage)) return badRequest(res, 'Invalid stage');

  const existing = db.prepare('SELECT * FROM incidents WHERE alert_id=? AND user_id=?').get(alertId, user.id);
  const now      = new Date().toISOString();
  const stageCol = { containment:'containment_at', eradication:'eradication_at', recovery:'recovery_at', rca:'rca_at', closed:'closed_at' }[stage];

  if (!existing) {
    db.prepare(`INSERT INTO incidents (alert_id, user_id, title, stage, notes, created_at, updated_at) VALUES (?,?,?,?,?,?,?)`)
      .run(alertId, user.id, title || null, stage, JSON.stringify({ identification: notes || '' }), now, now);
  } else {
    let parsedNotes = {};
    try { parsedNotes = JSON.parse(existing.notes || '{}'); } catch {}
    if (notes) parsedNotes[stage] = notes;
    const updates = ['stage=?', 'notes=?', 'updated_at=?'];
    const vals    = [stage, JSON.stringify(parsedNotes), now];
    if (stageCol && !existing[stageCol]) { updates.push(`${stageCol}=?`); vals.push(now); }
    vals.push(alertId, user.id);
    db.prepare(`UPDATE incidents SET ${updates.join(', ')} WHERE alert_id=? AND user_id=?`).run(...vals);
  }

  setUserAlertStatus(user.id, alertId, stage === 'closed' ? 'closed' : 'investigating');
  const result = db.prepare('SELECT * FROM incidents WHERE alert_id=? AND user_id=?').get(alertId, user.id);
  return ok(res, { incident: result });
}

// POST /api/alerts/:id/escalate
async function escalateAlert(req, res, alertId) {
  const user  = requireAuth(req, res); if (!user) return;
  const alert = db.prepare(`SELECT id FROM soc_alerts WHERE id=?`).get(alertId);
  if (!alert) return notFound(res, 'Alert not found');
  const { level, justification } = await parseBody(req);
  const validLevel = ['L2','L3'].includes(level) ? level : 'L2';
  const info = db.prepare(`INSERT INTO escalations (alert_id, user_id, level, justification) VALUES (?,?,?,?)`)
    .run(alertId, user.id, validLevel, justification || null);
  setUserAlertStatus(user.id, alertId, 'investigating');
  return ok(res, { escalation_id: info.lastInsertRowid });
}

// GET /api/alerts/:id/escalations
function getEscalations(req, res, alertId) {
  const user = requireAuth(req, res); if (!user) return;
  const rows = db.prepare(
    `SELECT e.id, e.alert_id, e.level, e.justification, e.status, e.created_at, u.username
     FROM escalations e JOIN users u ON u.id = e.user_id
     WHERE e.alert_id=? ORDER BY e.created_at ASC`
  ).all(alertId);
  return ok(res, rows);
}

module.exports = { listAlerts, getAlert, updateAlertStatus, getIncident, upsertIncident, escalateAlert, getEscalations };
