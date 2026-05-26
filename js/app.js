// DIAAS-SEC — Platform Engine
// Handles routing, state, scoring, toasts, clock, sidebar

const App = (function() {
  'use strict';

  // ---- STATE ----
  const state = {
    currentPage: 'dashboard',
    analystId: 'analyst_01',
    score: 0,
    solvedAlerts: new Set(),
    openedCases: new Set(),
    alertTimers: {},
    liveAlertInterval: null,
    clockInterval: null,
    scoreCallbacks: []
  };

  // ---- ROUTING ----
  const pages = ['dashboard','alerts','siem','cases','intel','leaderboard'];

  function navigate(page) {
    if (!pages.includes(page)) return;
    document.querySelectorAll('.page').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
    const pageEl = document.getElementById('page-' + page);
    const navEl  = document.querySelector('[data-page="' + page + '"]');
    if (pageEl) pageEl.classList.add('active');
    if (navEl)  navEl.classList.add('active');
    state.currentPage = page;
    // Update breadcrumb
    const labels = { dashboard:'Dashboard', alerts:'Alert Triage', siem:'SIEM Logs', cases:'Incident Cases', intel:'Threat Intel', leaderboard:'Leaderboard' };
    const bc = document.getElementById('breadcrumb-current');
    if (bc) bc.textContent = labels[page] || page;
    // Lifecycle hooks
    if (page === 'dashboard') Dashboard.refresh();
    if (page === 'alerts')    Alerts.init();
    if (page === 'siem')      SIEM.init();
    if (page === 'cases')     Cases.init();
    if (page === 'intel')     Intel.init();
    if (page === 'leaderboard') Leaderboard.init();
  }

  // ---- SCORE ----
  function addScore(pts, label) {
    state.score += pts;
    document.querySelectorAll('.my-score').forEach(el => el.textContent = state.score);
    toast('+' + pts + ' pts — ' + label, 'success');
    // Update board
    const me = DIAAS_DATA.analysts.find(a => a.id === state.analystId);
    if (me) me.score = state.score;
    _sortLeaderboard();
  }

  function _sortLeaderboard() {
    DIAAS_DATA.analysts.sort((a,b) => b.score - a.score);
    DIAAS_DATA.analysts.forEach((a,i) => a.rank = i+1);
  }

  // ---- TOAST ----
  function toast(msg, type='info', duration=3500) {
    const icons = { success:'✓', error:'✕', warning:'⚠', info:'ℹ' };
    const t = document.createElement('div');
    t.className = 'toast ' + type;
    t.innerHTML = '<span>' + icons[type] + '</span><span>' + msg + '</span>';
    const container = document.getElementById('toast-container');
    if (container) {
      container.appendChild(t);
      setTimeout(() => { t.style.opacity='0'; t.style.transition='opacity 0.3s'; setTimeout(()=>t.remove(), 300); }, duration);
    }
  }

  // ---- CLOCK ----
  function startClock() {
    const el = document.getElementById('topbar-clock');
    if (!el) return;
    const tick = () => {
      const now = new Date();
      el.textContent = now.toLocaleTimeString('en-IN', { hour12:false, timeZone:'Asia/Kolkata' }) + ' IST';
    };
    tick();
    state.clockInterval = setInterval(tick, 1000);
  }

  // ---- SIDEBAR TOGGLE ----
  function initSidebar() {
    const sb = document.getElementById('sidebar');
    const toggle = document.getElementById('sidebar-toggle');
    if (toggle && sb) {
      toggle.addEventListener('click', () => sb.classList.toggle('collapsed'));
    }
    document.querySelectorAll('.nav-item').forEach(item => {
      item.addEventListener('click', () => {
        const page = item.dataset.page;
        if (page) navigate(page);
      });
    });
  }

  // ---- MODAL HELPERS ----
  function openModal(id) {
    const el = document.getElementById(id);
    if (el) { el.classList.add('open'); document.body.style.overflow='hidden'; }
  }
  function closeModal(id) {
    const el = document.getElementById(id);
    if (el) { el.classList.remove('open'); document.body.style.overflow=''; }
  }
  function initModals() {
    document.querySelectorAll('.modal-close, [data-modal-close]').forEach(btn => {
      btn.addEventListener('click', () => {
        const overlay = btn.closest('.modal-overlay');
        if (overlay) { overlay.classList.remove('open'); document.body.style.overflow=''; }
      });
    });
    document.querySelectorAll('.modal-overlay').forEach(overlay => {
      overlay.addEventListener('click', e => {
        if (e.target === overlay) { overlay.classList.remove('open'); document.body.style.overflow=''; }
      });
    });
  }

  // ---- LIVE ALERT TICKER ----
  function startLiveTicker() {
    let i = 0;
    const ticker = document.getElementById('live-ticker');
    if (!ticker) return;
    const items = DIAAS_DATA.alerts.filter(a => a.severity === 'critical' || a.severity === 'high');
    state.liveAlertInterval = setInterval(() => {
      if (items.length === 0) return;
      const alert = items[i % items.length];
      ticker.textContent = '[' + new Date().toLocaleTimeString('en-IN',{hour12:false}) + '] ' + alert.rule_name + ' — ' + alert.agent;
      i++;
    }, 4000);
  }

  // ---- LIVE ALERT COUNT IN NAV ----
  function updateNavBadges() {
    const unreviewedCount = DIAAS_DATA.alerts.filter(a => !state.solvedAlerts.has(a.id)).length;
    document.querySelectorAll('.badge-alerts').forEach(el => el.textContent = unreviewedCount);
    const openCases = DIAAS_DATA.cases.filter(c => c.status === 'open').length;
    document.querySelectorAll('.badge-cases').forEach(el => el.textContent = openCases);
  }

  // ---- SEVERITY HELPERS ----
  const SEV_ORDER = { critical:0, high:1, medium:2, low:3, info:4 };
  function chipHtml(sev, label) {
    const l = (label || sev).toUpperCase();
    return '<span class="chip chip-' + sev + '">' + l + '</span>';
  }
  function dotHtml(sev) { return '<span class="live-dot ' + sev + '"></span>'; }
  function mitreHtml(id) {
    const t = DIAAS_DATA.mitre_techniques[id];
    const name = t ? t.name : id;
    return '<span class="mitre-tag" data-tip="' + name + '">' + id + '</span>';
  }
  function fmtTs(iso) {
    const d = new Date(iso);
    return d.toISOString().replace('T',' ').slice(0,19);
  }
  function relTime(iso) {
    const diff = Date.now() - new Date(iso).getTime();
    const m = Math.floor(diff/60000);
    if (m < 1) return 'just now';
    if (m < 60) return m + 'm ago';
    const h = Math.floor(m/60);
    if (h < 24) return h + 'h ago';
    return Math.floor(h/24) + 'd ago';
  }

  // ---- INIT ----
  function init() {
    initSidebar();
    initModals();
    startClock();
    startLiveTicker();
    updateNavBadges();
    navigate('dashboard');
  }

  return { state, navigate, addScore, toast, openModal, closeModal, chipHtml, dotHtml, mitreHtml, fmtTs, relTime, updateNavBadges };
})();

// ============================================================
//  DASHBOARD MODULE
// ============================================================
const Dashboard = (function() {

  function refresh() {
    renderStats();
    renderSeverityChart();
    renderMitreBars();
    renderRecentAlerts();
    renderAgentStatus();
    renderTimeline();
  }

  function renderStats() {
    const total    = DIAAS_DATA.alerts.length;
    const critical = DIAAS_DATA.alerts.filter(a=>a.severity==='critical').length;
    const high     = DIAAS_DATA.alerts.filter(a=>a.severity==='high').length;
    const openCases = DIAAS_DATA.cases.filter(c=>c.status==='open').length;
    const solved    = App.state.solvedAlerts.size;
    const tp        = DIAAS_DATA.alerts.filter(a=>App.state.solvedAlerts.has(a.id) && a.answer==='TP').length;

    _set('stat-total',    total);
    _set('stat-critical', critical);
    _set('stat-high',     high);
    _set('stat-cases',    openCases);
    _set('stat-solved',   solved);
    _set('stat-tp',       tp);
  }

  function renderSeverityChart() {
    const el = document.getElementById('chart-severity');
    if (!el) return;
    const counts = { critical:0, high:0, medium:0, low:0 };
    DIAAS_DATA.alerts.forEach(a => { if (counts[a.severity]!==undefined) counts[a.severity]++; });
    const max = Math.max(...Object.values(counts), 1);
    const colors = { critical:'var(--critical)', high:'var(--high)', medium:'var(--medium)', low:'var(--low)' };
    el.innerHTML = Object.entries(counts).map(([sev,count]) => `
      <div class="bar-row">
        <span class="bar-label">${sev.toUpperCase()}</span>
        <div class="bar-track"><div class="bar-fill" style="width:${(count/max*100).toFixed(1)}%;background:${colors[sev]}"></div></div>
        <span class="bar-val">${count}</span>
      </div>`).join('');
  }

  function renderMitreBars() {
    const el = document.getElementById('chart-mitre');
    if (!el) return;
    const counts = {};
    DIAAS_DATA.alerts.forEach(a => { counts[a.mitre] = (counts[a.mitre]||0)+1; });
    const sorted = Object.entries(counts).sort((a,b)=>b[1]-a[1]).slice(0,6);
    const max = sorted[0] ? sorted[0][1] : 1;
    el.innerHTML = sorted.map(([tid,count]) => {
      const t = DIAAS_DATA.mitre_techniques[tid];
      const name = t ? t.name : tid;
      return `<div class="bar-row">
        <span class="bar-label" data-tip="${tid}">${name}</span>
        <div class="bar-track"><div class="bar-fill" style="width:${(count/max*100).toFixed(1)}%;background:var(--accent)"></div></div>
        <span class="bar-val">${count}</span>
      </div>`;
    }).join('');
  }

  function renderRecentAlerts() {
    const el = document.getElementById('recent-alerts-body');
    if (!el) return;
    const recent = DIAAS_DATA.alerts.slice(0,8);
    el.innerHTML = recent.map(a => {
      const solved = App.state.solvedAlerts.has(a.id);
      const statusHtml = solved
        ? '<span class="chip chip-success">TRIAGED</span>'
        : App.dotHtml(a.severity) + '&nbsp;OPEN';
      return `<tr onclick="App.navigate('alerts')">
        <td class="td-mono text-muted">${a.id}</td>
        <td class="td-primary">${a.rule_name}</td>
        <td>${App.chipHtml(a.severity)}</td>
        <td class="td-mono text-muted">${a.agent}</td>
        <td>${App.mitreHtml(a.mitre)}</td>
        <td class="text-muted text-sm">${App.relTime(a.timestamp)}</td>
        <td>${statusHtml}</td>
      </tr>`;
    }).join('');
  }

  function renderAgentStatus() {
    const el = document.getElementById('agent-status-list');
    if (!el) return;
    const agents = [
      { name:'WIN-DC01',   os:'Windows Server 2019', status:'active',  alerts:3 },
      { name:'WIN-FIN01',  os:'Windows 10 Pro',      status:'critical', alerts:5 },
      { name:'WIN-APP01',  os:'Windows Server 2016', status:'critical', alerts:4 },
      { name:'WIN-HR01',   os:'Windows 10 Pro',      status:'warning',  alerts:2 },
      { name:'WIN-RDP01',  os:'Windows Server 2019', status:'warning',  alerts:2 },
      { name:'WIN-FILE01', os:'Windows Server 2016', status:'critical', alerts:2 },
      { name:'WIN-IT01',   os:'Windows 10 Pro',      status:'active',   alerts:1 },
      { name:'WIN-DEV01',  os:'Windows 11',          status:'active',   alerts:1 },
    ];
    const statusColor = { active:'success', warning:'medium', critical:'critical' };
    el.innerHTML = agents.map(ag => `
      <div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--border);">
        ${App.dotHtml(statusColor[ag.status]||'low')}
        <div style="flex:1;min-width:0;">
          <div style="font-size:12px;font-weight:500;color:var(--text-primary)">${ag.name}</div>
          <div style="font-size:10px;color:var(--text-muted)">${ag.os}</div>
        </div>
        ${ag.alerts > 0 ? `<span class="chip chip-${ag.alerts>=3?'critical':ag.alerts>=2?'high':'medium'}">${ag.alerts} ALERTS</span>` : '<span class="chip chip-success">CLEAN</span>'}
      </div>`).join('');
  }

  function renderTimeline() {
    const el = document.getElementById('attack-timeline');
    if (!el) return;
    const events = [
      { ts:'08:14', title:'Reconnaissance', desc:'Port scan from internal host 192.168.10.55', sev:'medium' },
      { ts:'09:02', title:'Brute Force RDP', desc:'47 failed logins from 203.0.113.42', sev:'high' },
      { ts:'09:08', title:'RDP Access Gained', desc:'svc_backup account compromised', sev:'critical' },
      { ts:'10:14', title:'Phishing Macro', desc:'WINWORD.EXE spawned PowerShell on WIN-FIN01', sev:'high' },
      { ts:'10:15', title:'C2 Established', desc:'PowerShell beaconing to 185.220.101.15', sev:'critical' },
      { ts:'11:33', title:'Lateral Movement', desc:'PSEXESVC deployed on WIN-APP01', sev:'high' },
      { ts:'12:02', title:'Credential Dump', desc:'LSASS accessed by rundll32.exe', sev:'critical' },
      { ts:'14:00', title:'Kerberoasting', desc:'RC4 TGS request for SQL service account', sev:'high' },
      { ts:'14:08', title:'DCSync', desc:'Domain replication from non-DC host', sev:'critical' },
      { ts:'15:01', title:'Ransomware', desc:'3,847 files encrypted on WIN-FILE01', sev:'critical' },
    ];
    const sevCol = { critical:'var(--critical)', high:'var(--high)', medium:'var(--medium)', low:'var(--low)' };
    el.innerHTML = events.map((ev,i) => `
      <div class="timeline-item">
        <div class="timeline-line">
          <div class="timeline-dot" style="background:${sevCol[ev.sev]};border-color:${sevCol[ev.sev]}"></div>
          ${i<events.length-1?'<div class="timeline-connector"></div>':''}
        </div>
        <div class="timeline-content">
          <div class="timeline-ts">${ev.ts} IST</div>
          <div class="timeline-title">${ev.title} ${App.chipHtml(ev.sev)}</div>
          <div class="timeline-desc">${ev.desc}</div>
        </div>
      </div>`).join('');
  }

  function _set(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
  }

  return { refresh };
})();

// ============================================================
//  ALERTS MODULE
// ============================================================
const Alerts = (function() {
  let filtered = [];
  let selected = null;

  function init() {
    filtered = [...DIAAS_DATA.alerts];
    renderTable();
    bindFilters();
  }

  function renderTable() {
    const tbody = document.getElementById('alerts-tbody');
    if (!tbody) return;
    if (filtered.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8"><div class="empty-state"><div class="empty-state-title">No alerts match filters</div></div></td></tr>';
      return;
    }
    tbody.innerHTML = filtered.map(a => {
      const solved = App.state.solvedAlerts.has(a.id);
      const rowClass = solved ? 'style="opacity:0.55"' : '';
      return `<tr ${rowClass} onclick="Alerts.openDetail('${a.id}')">
        <td>${App.dotHtml(a.severity)}</td>
        <td class="td-mono text-muted">${a.id}</td>
        <td class="td-primary">${a.rule_name}</td>
        <td>${App.chipHtml(a.severity)}</td>
        <td class="td-mono text-sm">${a.agent}</td>
        <td class="td-mono text-sm text-muted">${a.source_ip}</td>
        <td>${App.mitreHtml(a.mitre)}</td>
        <td>${solved
          ? '<span class="chip chip-success">TRIAGED</span>'
          : '<span class="chip chip-neutral">OPEN</span>'
        }</td>
        <td class="text-muted text-sm">${App.relTime(a.timestamp)}</td>
      </tr>`;
    }).join('');
  }

  function bindFilters() {
    const search = document.getElementById('alert-search');
    const sevFilter = document.getElementById('alert-sev-filter');
    const statusFilter = document.getElementById('alert-status-filter');
    if (search) search.oninput = applyFilters;
    if (sevFilter) sevFilter.onchange = applyFilters;
    if (statusFilter) statusFilter.onchange = applyFilters;
  }

  function applyFilters() {
    const q     = (document.getElementById('alert-search')?.value || '').toLowerCase();
    const sev   = document.getElementById('alert-sev-filter')?.value || 'all';
    const status = document.getElementById('alert-status-filter')?.value || 'all';
    filtered = DIAAS_DATA.alerts.filter(a => {
      if (sev !== 'all' && a.severity !== sev) return false;
      if (status === 'open' && App.state.solvedAlerts.has(a.id)) return false;
      if (status === 'triaged' && !App.state.solvedAlerts.has(a.id)) return false;
      if (q && !(a.rule_name.toLowerCase().includes(q) ||
                 a.agent.toLowerCase().includes(q) ||
                 a.source_ip.includes(q) ||
                 a.id.toLowerCase().includes(q))) return false;
      return true;
    });
    renderTable();
  }

  function openDetail(id) {
    const alert = DIAAS_DATA.alerts.find(a => a.id === id);
    if (!alert) return;
    selected = alert;
    const modal = document.getElementById('modal-alert-detail');
    if (!modal) return;

    modal.querySelector('#detail-id').textContent = alert.id;
    modal.querySelector('#detail-rule').textContent = alert.rule_name;
    modal.querySelector('#detail-sev').innerHTML = App.chipHtml(alert.severity);
    modal.querySelector('#detail-agent').textContent = alert.agent;
    modal.querySelector('#detail-src-ip').textContent = alert.source_ip;
    modal.querySelector('#detail-dest-ip').textContent = alert.dest_ip;
    modal.querySelector('#detail-dest-port').textContent = alert.dest_port;
    modal.querySelector('#detail-event-id').textContent = alert.event_id;
    modal.querySelector('#detail-process').textContent = alert.process;
    modal.querySelector('#detail-ts').textContent = App.fmtTs(alert.timestamp);
    modal.querySelector('#detail-mitre').innerHTML = App.mitreHtml(alert.mitre);
    const t = DIAAS_DATA.mitre_techniques[alert.mitre];
    modal.querySelector('#detail-tactic').textContent = t ? t.tactic : 'Unknown';
    modal.querySelector('#detail-desc').textContent = alert.description;
    modal.querySelector('#detail-raw-log').textContent = alert.raw_log;
    modal.querySelector('#detail-points').textContent = alert.points;

    // Reset triage form
    const form = modal.querySelector('#triage-form');
    if (form) {
      form.querySelectorAll('.radio-option').forEach(el => el.classList.remove('selected'));
      form.querySelectorAll('input[type=radio]').forEach(el => el.checked = false);
      const mitreSel = form.querySelector('#triage-mitre');
      if (mitreSel) mitreSel.value = alert.mitre;
      const notes = form.querySelector('#triage-notes');
      if (notes) notes.value = '';
    }
    const fb = modal.querySelector('#triage-feedback');
    if (fb) { fb.className = 'feedback-panel'; fb.innerHTML = ''; }

    const solved = App.state.solvedAlerts.has(id);
    const submitBtn = modal.querySelector('#btn-submit-triage');
    if (submitBtn) submitBtn.disabled = solved;
    if (solved) {
      const fb = modal.querySelector('#triage-feedback');
      if (fb) {
        fb.className = 'feedback-panel correct visible';
        fb.innerHTML = '<div class="feedback-title">✓ Already triaged</div><div class="feedback-text">You already answered this alert correctly.</div>';
      }
    }

    App.openModal('modal-alert-detail');
  }

  function submitTriage() {
    if (!selected) return;
    const form = document.getElementById('triage-form');
    if (!form) return;
    const checked = form.querySelector('input[name="verdict"]:checked');
    if (!checked) { App.toast('Select TP or FP first', 'error'); return; }
    const verdict = checked.value;
    const mitreSel = form.querySelector('#triage-mitre');
    const mitreVal = mitreSel ? mitreSel.value : '';
    const fb = document.getElementById('triage-feedback');

    const correct = verdict === selected.answer;
    const mitrePts = (mitreVal === selected.answer_mitre) ? Math.floor(selected.points * 0.3) : 0;
    const totalPts = correct ? (selected.points + mitrePts) : 0;

    if (correct) {
      App.state.solvedAlerts.add(selected.id);
      if (totalPts > 0) App.addScore(totalPts, 'Alert ' + selected.id);
      if (fb) {
        fb.className = 'feedback-panel correct visible';
        fb.innerHTML = `<div class="feedback-title">✓ Correct — ${verdict}</div><div class="feedback-text">${selected.explanation}</div>`;
      }
    } else {
      if (fb) {
        fb.className = 'feedback-panel incorrect visible';
        fb.innerHTML = `<div class="feedback-title">✕ Incorrect — the answer is ${selected.answer}</div><div class="feedback-text">${selected.explanation}</div>`;
      }
    }
    document.getElementById('btn-submit-triage').disabled = true;
    App.updateNavBadges();
    renderTable();
  }

  return { init, openDetail, submitTriage, applyFilters };
})();

// ============================================================
//  SIEM MODULE
// ============================================================
const SIEM = (function() {
  let results = [];
  let currentLog = null;

  function init() {
    results = [...DIAAS_DATA.siem_logs];
    renderResults();
    bindSearch();
  }

  function renderResults() {
    const el = document.getElementById('siem-results-body');
    if (!el) return;
    if (results.length === 0) {
      el.innerHTML = '<tr><td colspan="7"><div class="empty-state"><div class="empty-state-title">No logs match your query</div></div></td></tr>';
      return;
    }
    el.innerHTML = results.map(log => {
      const levColor = { Critical:'critical', Warning:'high', Information:'low', Error:'critical' };
      const sev = levColor[log.level] || 'low';
      return `<tr onclick="SIEM.showLog('${log.id}')">
        <td class="td-mono text-muted">${App.fmtTs(log.timestamp)}</td>
        <td class="td-primary">${log.host}</td>
        <td class="td-mono text-sm">${log.source}</td>
        <td class="td-mono text-sm">${log.event_id}</td>
        <td>${App.chipHtml(sev, log.level)}</td>
        <td class="td-code">${log.message}</td>
        <td>${log.tags.slice(0,2).map(t=>`<span class="chip chip-neutral" style="margin-right:2px">${t}</span>`).join('')}</td>
      </tr>`;
    }).join('');
    document.getElementById('siem-count').textContent = results.length + ' events';
  }

  function bindSearch() {
    const input = document.getElementById('siem-search');
    const runBtn = document.getElementById('siem-run');
    if (runBtn) runBtn.onclick = () => runQuery(input?.value || '');
    if (input) {
      input.onkeydown = e => { if (e.key === 'Enter') runQuery(input.value); };
      // Add sample queries on focus
      input.onfocus = () => { if (!input.value) input.placeholder = 'e.g. event_id:4625  or  host:WIN-DC01  or  lsass'; };
    }
    document.querySelectorAll('.siem-quick-query').forEach(btn => {
      btn.onclick = () => {
        if (input) { input.value = btn.dataset.query; }
        runQuery(btn.dataset.query);
      };
    });
    const timeFilter = document.getElementById('siem-time-filter');
    if (timeFilter) timeFilter.onchange = () => runQuery(input?.value || '');
    const hostFilter = document.getElementById('siem-host-filter');
    if (hostFilter) hostFilter.onchange = () => runQuery(input?.value || '');
  }

  function runQuery(q) {
    q = (q || '').trim().toLowerCase();
    const hostF = (document.getElementById('siem-host-filter')?.value || 'all').toLowerCase();
    results = DIAAS_DATA.siem_logs.filter(log => {
      if (hostF !== 'all' && log.host.toLowerCase() !== hostF) return false;
      if (!q) return true;
      // Support key:value syntax
      if (q.includes(':')) {
        const [key, val] = q.split(':').map(s=>s.trim());
        const map = { event_id:'event_id', host:'host', source:'source', level:'level', tag:'tags' };
        if (map[key] === 'tags') return log.tags.some(t=>t.includes(val));
        if (map[key]) return String(log[map[key]]).toLowerCase().includes(val);
      }
      // Full text search
      return log.message.toLowerCase().includes(q) ||
             log.host.toLowerCase().includes(q) ||
             log.source.toLowerCase().includes(q) ||
             String(log.event_id).includes(q) ||
             log.tags.some(t=>t.includes(q));
    });
    renderResults();
    App.toast('Query returned ' + results.length + ' events', 'info', 2000);
  }

  function showLog(id) {
    const log = DIAAS_DATA.siem_logs.find(l => l.id === id);
    if (!log) return;
    currentLog = log;
    const panel = document.getElementById('siem-detail-panel');
    if (!panel) return;
    panel.innerHTML = `
      <div class="card-header"><span class="card-title">Event Detail — ${log.id}</span>
        <button class="btn btn-xs btn-secondary" onclick="SIEM.createAlertFromLog('${log.id}')">Open Alert</button>
      </div>
      <div class="card-body">
        <div class="detail-grid mb-3">
          <div class="detail-row"><span class="detail-key">Timestamp</span><span class="detail-val">${App.fmtTs(log.timestamp)}</span></div>
          <div class="detail-row"><span class="detail-key">Host</span><span class="detail-val">${log.host}</span></div>
          <div class="detail-row"><span class="detail-key">Source</span><span class="detail-val">${log.source}</span></div>
          <div class="detail-row"><span class="detail-key">Event ID</span><span class="detail-val">${log.event_id}</span></div>
          <div class="detail-row"><span class="detail-key">Level</span><span class="detail-val">${log.level}</span></div>
          <div class="detail-row"><span class="detail-key">Tags</span><span class="detail-val">${log.tags.join(', ')}</span></div>
        </div>
        <div class="form-label mb-2">Raw Message</div>
        <div class="log-block">${escHtml(log.message)}</div>
        <div class="mt-3 flex gap-2">
          ${log.tags.map(t=>`<span class="chip chip-neutral">${t}</span>`).join('')}
        </div>
      </div>`;
    panel.style.display='block';
  }

  function createAlertFromLog(id) {
    App.toast('Pivoting to alert queue...', 'info');
    setTimeout(()=>App.navigate('alerts'), 600);
  }

  function escHtml(s) { return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

  return { init, showLog, createAlertFromLog, runQuery };
})();

// ============================================================
//  CASES MODULE
// ============================================================
const Cases = (function() {
  let selectedCase = null;

  function init() { renderList(); }

  function renderList() {
    const el = document.getElementById('cases-list');
    if (!el) return;
    el.innerHTML = DIAAS_DATA.cases.map(c => {
      const done = c.tasks.filter(t=>t.status==='closed').length;
      const pct  = c.tasks.length ? Math.round(done/c.tasks.length*100) : 0;
      return `<div class="card mb-3 cursor-pointer" onclick="Cases.openCase('${c.id}')" style="cursor:pointer">
        <div class="card-header">
          <div>
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
              ${App.chipHtml(c.severity)}
              <span class="text-mono text-sm text-muted">${c.id}</span>
              <span class="chip chip-${c.status==='open'?'neutral':'success'}">${c.status.toUpperCase()}</span>
            </div>
            <div class="card-title" style="font-size:14px">${c.title}</div>
          </div>
          <div style="text-align:right;flex-shrink:0">
            <div class="text-muted text-xs mb-2">${App.relTime(c.updated)}</div>
            <div class="chip chip-${c.tlp==='RED'?'critical':c.tlp==='AMBER'?'high':'info'}">TLP:${c.tlp}</div>
          </div>
        </div>
        <div class="card-body">
          <p style="font-size:12px;color:var(--text-secondary);margin-bottom:12px">${c.description}</p>
          <div style="display:flex;align-items:center;gap:12px">
            <div style="flex:1">
              <div style="display:flex;justify-content:space-between;margin-bottom:4px">
                <span class="text-xs text-muted">Task Progress</span>
                <span class="text-mono text-xs text-muted">${done}/${c.tasks.length}</span>
              </div>
              <div class="progress-bar-wrap">
                <div class="progress-bar-fill" style="width:${pct}%;background:${pct===100?'var(--success)':'var(--accent)'}"></div>
              </div>
            </div>
            <div style="display:flex;gap:6px;flex-wrap:wrap">
              ${c.mitre_tags.slice(0,3).map(t=>App.mitreHtml(t)).join('')}
            </div>
          </div>
        </div>
      </div>`;
    }).join('');
  }

  function openCase(id) {
    const c = DIAAS_DATA.cases.find(x=>x.id===id);
    if (!c) return;
    selectedCase = c;
    const modal = document.getElementById('modal-case-detail');
    if (!modal) return;

    modal.querySelector('#case-modal-title').textContent = c.title;
    modal.querySelector('#case-modal-id').textContent = c.id;
    modal.querySelector('#case-modal-sev').innerHTML = App.chipHtml(c.severity);
    modal.querySelector('#case-modal-status').textContent = c.status.toUpperCase();
    modal.querySelector('#case-modal-desc').textContent = c.description;
    modal.querySelector('#case-modal-created').textContent = App.fmtTs(c.created);
    modal.querySelector('#case-modal-mitre').innerHTML = c.mitre_tags.map(t=>App.mitreHtml(t)).join(' ');

    // Render tasks
    const taskEl = modal.querySelector('#case-tasks-list');
    if (taskEl) {
      taskEl.innerHTML = c.tasks.map((t,i) => `
        <div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--border)">
          <input type="checkbox" ${t.status==='closed'?'checked':''} 
            onchange="Cases.toggleTask('${c.id}','${t.id}')" 
            style="accent-color:var(--accent);width:14px;height:14px;cursor:pointer">
          <span style="flex:1;font-size:12px;color:${t.status==='closed'?'var(--text-muted)':'var(--text-primary)'};${t.status==='closed'?'text-decoration:line-through':''}">${t.title}</span>
          <span class="chip chip-${t.status==='closed'?'success':'neutral'}">${t.status.toUpperCase()}</span>
        </div>`).join('');
    }

    // Render observables
    renderObservables(c, modal);

    App.openModal('modal-case-detail');
  }

  function renderObservables(c, modal) {
    const el = modal.querySelector('#case-observables');
    if (!el) return;
    const defaultObs = [
      { type:'ip', value:'185.220.101.15' },
      { type:'ip', value:'203.0.113.42' },
      { type:'hash', value:'e3b0c44298fc1c149afb' },
      { type:'domain', value:'update.meridian-security-patch.com' }
    ].concat(c.observables || []);
    el.innerHTML = defaultObs.map(obs => `
      <span class="obs-tag" onclick="Intel.lookupIoc('${obs.value}')">
        <span class="ioc-type ioc-${obs.type}">${obs.type}</span>
        ${obs.value}
      </span>`).join('');
  }

  function toggleTask(caseId, taskId) {
    const c = DIAAS_DATA.cases.find(x=>x.id===caseId);
    if (!c) return;
    const t = c.tasks.find(x=>x.id===taskId);
    if (!t) return;
    t.status = t.status === 'closed' ? 'open' : 'closed';
    if (t.status === 'closed') App.addScore(10, 'Task completed: ' + t.title.slice(0,30));
    renderList();
    openCase(caseId);
  }

  function addObservable() {
    if (!selectedCase) return;
    const type = document.getElementById('obs-type')?.value;
    const val  = document.getElementById('obs-val')?.value?.trim();
    if (!type || !val) { App.toast('Enter an observable value', 'error'); return; }
    selectedCase.observables = selectedCase.observables || [];
    selectedCase.observables.push({ type, value: val });
    const modal = document.getElementById('modal-case-detail');
    if (modal) renderObservables(selectedCase, modal);
    document.getElementById('obs-val').value = '';
    App.toast('Observable added', 'success', 2000);
    App.addScore(5, 'Observable added');
  }

  return { init, openCase, toggleTask, addObservable };
})();

// ============================================================
//  THREAT INTEL MODULE
// ============================================================
const Intel = (function() {
  function init() { renderIocTable(); }

  function renderIocTable() {
    const el = document.getElementById('intel-tbody');
    if (!el) return;
    el.innerHTML = DIAAS_DATA.iocs.map(ioc => {
      const pct = ioc.score;
      const barColor = pct >= 80 ? 'var(--critical)' : pct >= 50 ? 'var(--high)' : pct >= 20 ? 'var(--medium)' : 'var(--success)';
      return `<tr onclick="Intel.lookupIoc('${ioc.value}')">
        <td><span class="ioc-type ioc-${ioc.type}">${ioc.type}</span></td>
        <td class="td-primary td-mono">${ioc.value}</td>
        <td>
          <div class="vt-score">
            <div class="vt-bar-wrap"><div class="vt-bar-fill" style="width:${pct}%;background:${barColor}"></div></div>
            <span class="vt-num" style="color:${barColor}">${pct}</span>
          </div>
        </td>
        <td class="td-mono text-sm">${ioc.engine_hits}</td>
        <td>${ioc.malicious
          ? '<span class="chip chip-critical">MALICIOUS</span>'
          : '<span class="chip chip-success">CLEAN</span>'}</td>
        <td class="text-sm text-muted">${ioc.description.slice(0,60)}...</td>
        <td>${ioc.tags.map(t=>`<span class="chip chip-neutral" style="margin-right:2px">${t}</span>`).join('')}</td>
      </tr>`;
    }).join('');
  }

  function lookupIoc(value) {
    const ioc = DIAAS_DATA.iocs.find(i => i.value === value);
    if (!ioc) { App.toast('IOC not found in threat database', 'warning'); return; }
    const modal = document.getElementById('modal-ioc-detail');
    if (!modal) return;
    const pct = ioc.score;
    const barColor = pct >= 80 ? 'var(--critical)' : pct >= 50 ? 'var(--high)' : pct >= 20 ? 'var(--medium)' : 'var(--success)';
    const verdict = ioc.malicious
      ? `<div class="banner banner-critical" style="margin-top:0">⚠ MALICIOUS — DIAAS-SEC Threat Score: ${pct}/100</div>`
      : `<div class="banner banner-success" style="margin-top:0">✓ CLEAN — No detections</div>`;
    modal.querySelector('#ioc-modal-body').innerHTML = `
      ${verdict}
      <div class="detail-grid mb-3">
        <div class="detail-row"><span class="detail-key">Type</span><span class="detail-val">${ioc.type.toUpperCase()}</span></div>
        <div class="detail-row"><span class="detail-key">Value</span><span class="detail-val">${ioc.value}</span></div>
        <div class="detail-row"><span class="detail-key">Engine Hits</span><span class="detail-val">${ioc.engine_hits}</span></div>
        <div class="detail-row"><span class="detail-key">Threat Score</span>
          <span class="detail-val" style="color:${barColor}">${pct}/100</span></div>
      </div>
      <div class="log-block">${ioc.description}</div>
      <div class="mt-3 flex gap-2 flex-wrap">${ioc.tags.map(t=>`<span class="chip chip-neutral">${t}</span>`).join('')}</div>`;
    modal.querySelector('#ioc-modal-title').textContent = 'IOC Lookup — ' + ioc.value.slice(0,40);
    App.openModal('modal-ioc-detail');
    App.addScore(5, 'IOC enriched: ' + value.slice(0,20));
  }

  function runLookup() {
    const val = document.getElementById('intel-search')?.value?.trim();
    if (!val) return;
    lookupIoc(val);
  }

  return { init, renderIocTable, lookupIoc, runLookup };
})();

// ============================================================
//  ANALYST BOARD MODULE
// ============================================================
const Leaderboard = (function() {
  function init() {
    // Seed demo scores so the board isn't all zeros
    const demo = [312, 285, 274, 248, 231, 198, 175, 142, 118, 0];
    DIAAS_DATA.analysts.forEach((a,i) => {
      if (a.id === App.state.analystId) a.score = App.state.score;
      else if (a.score === 0) a.score = demo[i] || 0;
    });
    DIAAS_DATA.analysts.sort((a,b)=>b.score-a.score);
    DIAAS_DATA.analysts.forEach((a,i)=>a.rank=i+1);
    renderBoard();
    renderMyStats();
  }

  function renderBoard() {
    const el = document.getElementById('leaderboard-tbody');
    if (!el) return;
    const badges = ['👑','🥈','🥉'];
    el.innerHTML = DIAAS_DATA.analysts.map((a,i) => {
      const isMe = a.id === App.state.analystId;
      const solved = isMe ? App.state.solvedAlerts.size : Math.floor(a.score/20);
      const acc = solved > 0 ? Math.round((solved/(solved+1))*100)+'%' : 'N/A';
      return `<tr class="${isMe?'selected':''} rank-${i+1}">
        <td><span class="rank-num">${badges[i]||('#'+(i+1))}</span></td>
        <td>
          <div style="display:flex;align-items:center;gap:8px">
            <div class="analyst-avatar" style="background:${isMe?'var(--accent)':'var(--bg-raised)'}">
              ${a.name.split(' ').map(w=>w[0]).join('').slice(0,2)}
            </div>
            <div>
              <div style="font-size:12.5px;font-weight:500;color:${isMe?'var(--accent)':'var(--text-primary)'}">${a.name}${isMe?' (you)':''}</div>
              <div style="font-size:10px;color:var(--text-muted)">${a.badge}</div>
            </div>
          </div>
        </td>
        <td class="td-mono" style="font-size:16px;font-weight:700;color:${isMe?'var(--accent)':'var(--text-primary)'}">${a.score}</td>
        <td class="td-mono text-sm">${solved}</td>
        <td class="text-sm text-muted">${acc}</td>
        <td>${App.chipHtml(i<3?'success':i<7?'medium':'low', i<3?'TOP':i<7?'MID':'—')}</td>
      </tr>`;
    }).join('');
  }

  function renderMyStats() {
    const el = document.getElementById('my-stats-body');
    if (!el) return;
    const tp = DIAAS_DATA.alerts.filter(a=>App.state.solvedAlerts.has(a.id)&&a.answer==='TP').length;
    const fp = DIAAS_DATA.alerts.filter(a=>App.state.solvedAlerts.has(a.id)&&a.answer==='FP').length;
    const tasks = DIAAS_DATA.cases.flatMap(c=>c.tasks).filter(t=>t.status==='closed').length;
    const iocs  = 0; // enrichments tracked via score
    el.innerHTML = `
      <div class="stat-card success">
        <div class="stat-label">Total Score</div>
        <div class="stat-value my-score">${App.state.score}</div>
        <div class="stat-delta">pts this shift</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Alerts Triaged</div>
        <div class="stat-value">${App.state.solvedAlerts.size}</div>
        <div class="stat-delta">${tp} TP &nbsp;·&nbsp; ${fp} FP</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Case Tasks Done</div>
        <div class="stat-value">${tasks}</div>
        <div class="stat-delta">10 pts each</div>
      </div>
      <div class="stat-card accent">
        <div class="stat-label">Team Rank</div>
        <div class="stat-value">${(DIAAS_DATA.analysts.find(a=>a.id===App.state.analystId)?.rank) || '—'}</div>
        <div class="stat-delta">of ${DIAAS_DATA.analysts.length} analysts</div>
      </div>`;
  }

  return { init };
})();

// ---- BOOT ----
document.addEventListener('DOMContentLoaded', App.init);
