/* auth_lab.js — Auth Lab frontend logic */

const API = 'http://localhost:8001';
let currentTargetId = null;
let allTrafficLogs = [];

// ─────────────────────────────────────────────────────────────────────────────
// Boot
// ─────────────────────────────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', async () => {
  await loadTargets();
  await loadStats();
  await loadTraffic();
  await loadPayloads();
  // Auto-refresh traffic every 8s
  setInterval(loadTraffic, 8000);
  setInterval(loadStats,   10000);
});

// ─────────────────────────────────────────────────────────────────────────────
// Targets
// ─────────────────────────────────────────────────────────────────────────────
async function loadTargets() {
  const res  = await fetch(`${API}/api/targets`).catch(() => null);
  if (!res) return;
  const data = await res.json();
  const sel  = document.getElementById('targetSelect');
  sel.innerHTML = '<option value="">— select target —</option>';
  data.forEach(t => {
    const opt = document.createElement('option');
    opt.value = t.id;
    opt.textContent = `#${t.id} ${t.url}`;
    sel.appendChild(opt);
  });
}

function onTargetChange() {
  const val = document.getElementById('targetSelect').value;
  currentTargetId = val ? parseInt(val) : null;
  refreshAll();
}

// ─────────────────────────────────────────────────────────────────────────────
// Stats
// ─────────────────────────────────────────────────────────────────────────────
async function loadStats() {
  const res = await fetch(`${API}/api/stats`).catch(() => null);
  if (!res) return;
  const global = await res.json();
  let surfaces = 0;
  let traffic  = 0;
  let payloads = global.payload_library || 0;
  let tests    = 0; 
  let leaks    = 0;

  if (currentTargetId) {
    // Fetch counts specifically for this target
    const sRes = await fetch(`${API}/api/targets/${currentTargetId}/auth_surfaces`).catch(() => null);
    if (sRes) { const data = await sRes.json(); surfaces = data.length; }

    // For traffic, we fetch flagged logs to get the count of OTP Flags
    const tRes = await fetch(`${API}/api/traffic_logs?target_id=${currentTargetId}&limit=1000`).catch(() => null);
    if (tRes) { 
      const data = await tRes.json(); 
      // Count only logs that have sensitive flags (OTPs, tokens, etc)
      traffic = data.filter(l => {
        try { return JSON.parse(l.sensitive_flags || '[]').length > 0; } catch { return false; }
      }).length;
    }

    const trRes = await fetch(`${API}/api/targets/${currentTargetId}/auth_test_results`).catch(() => null);
    if (trRes) {
      const data = await trRes.json();
      tests = data.length;
      data.forEach(r => {
        try { 
          const l = JSON.parse(r.sensitive_data_detected || '[]'); 
          if (Array.isArray(l)) leaks += l.length; 
        } catch {}
      });
    }
  }

  setText('stSurfaces', currentTargetId ? surfaces : '—');
  setText('stTraffic',  currentTargetId ? traffic  : '—');
  setText('stPayloads', currentTargetId ? payloads : '—'); // Or keep global payloads
  setText('stTests',    currentTargetId ? tests    : '—');
  setText('stLeaks',    currentTargetId ? leaks    : '—');
}

function onStatPillClick(type) {
  const tabs = {
    'surfaces': 'surfaces',
    'tests':    'tests',
    'leaks':    'tests',
    'traffic':  'traffic',
    'payloads': 'payloads'
  };

  const targetTab = tabs[type];
  if (!targetTab) return;

  // 1. Switch Tab UI
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  
  const tabBtn = document.querySelector(`.tab-btn[onclick*="'${targetTab}'"]`);
  if (tabBtn) tabBtn.classList.add('active');
  document.getElementById('tab-' + targetTab).classList.add('active');

  // 2. Set filters BEFORE loading data
  if (type === 'leaks') {
    const filter = document.getElementById('testLeakFilter');
    if (filter) filter.value = 'leaks_only';
  } else if (type === 'tests') {
    const filter = document.getElementById('testLeakFilter');
    if (filter) filter.value = '';
  }

  // 3. Load data for the tab
  if (targetTab === 'surfaces') loadSurfaces();
  if (targetTab === 'tests')    loadTestResults();
  if (targetTab === 'traffic')  loadTraffic();
  if (targetTab === 'payloads') loadPayloads();
}

// ─────────────────────────────────────────────────────────────────────────────
// Auth Surfaces
// ─────────────────────────────────────────────────────────────────────────────
async function loadSurfaces() {
  if (!currentTargetId) {
    document.getElementById('surfacesTbody').innerHTML = `<tr><td colspan="6"><div class="empty"><div class="icon">🔍</div>Select a target and run Page Classification</div></td></tr>`;
    return;
  }
  const res = await fetch(`${API}/api/targets/${currentTargetId}/auth_surfaces`).catch(() => null);
  if (!res) return;
  const allData = await res.json();
  renderSurfaces(allData);
}

function applySurfaceFilter() {
  const type = document.getElementById('surfaceTypeFilter').value;
  const method = document.getElementById('surfaceMethodFilter').value;
  const conf = document.getElementById('surfaceConfFilter').value;

  // Since we don't have all data cached in a global var, we'll re-fetch or filter current table
  // Better to fetch all once and filter locally
  loadSurfaces(); // Simplified: just reload for now, or improve caching
}

function renderSurfaces(data) {
  const tbody = document.getElementById('surfacesTbody');
  if (!data.length) {
    tbody.innerHTML = `<tr><td colspan="6"><div class="empty"><div class="icon">🔍</div>No auth surfaces detected yet</div></td></tr>`;
    return;
  }

  tbody.innerHTML = data.map(s => {
    const conf = (s.confidence_score * 100).toFixed(0);
    const confColor = conf >= 80 ? '#34d399' : conf >= 50 ? '#fbbf24' : '#f87171';
    return `
    <tr onclick="showSurfaceDetail(${JSON.stringify(s).replace(/"/g,'&quot;')})">
      <td class="mono" style="color:#a5b4fc">${truncate(s.url, 55)}</td>
      <td>${typeBadge(s.page_type)}</td>
      <td>${methodBadge(s.detection_method)}</td>
      <td>
        <div class="conf-bar">
          <div class="conf-track">
            <div class="conf-fill" style="width:${conf}%;background:${confColor}"></div>
          </div>
          <span style="font-size:.8rem;color:${confColor}">${conf}%</span>
        </div>
      </td>
      <td style="color:#94a3b8">${truncate(s.page_title || '—', 30)}</td>
      <td><span class="badge" style="${statusStyle(s.response_code)}">${s.response_code || '?'}</span></td>
    </tr>`;
  }).join('');
}

function showSurfaceDetail(s) {
  let forms = [];
  try { forms = JSON.parse(s.form_structure || '[]'); } catch {}

  document.getElementById('panelTitle').textContent = `🔐 ${s.page_type.toUpperCase()} — Surface`;
  document.getElementById('panelBody').innerHTML = `
    <div class="panel-section">
      <div class="panel-section-label">URL</div>
      <div class="panel-value mono" style="color:#a5b4fc">${s.url}</div>
    </div>
    <div class="panel-section">
      <div class="panel-section-label">Classification</div>
      <div style="display:flex;gap:.5rem;align-items:center">
        ${typeBadge(s.page_type)} ${methodBadge(s.detection_method)}
        <span style="color:#94a3b8;font-size:.85rem">Confidence: ${(s.confidence_score*100).toFixed(0)}%</span>
      </div>
    </div>
    ${s.page_title ? `<div class="panel-section"><div class="panel-section-label">Page Title</div><div class="panel-value">${s.page_title}</div></div>` : ''}
    <div class="panel-section">
      <div class="panel-section-label">Form Structure</div>
      <div class="panel-code">${JSON.stringify(forms, null, 2) || 'No forms detected'}</div>
    </div>
    <div class="panel-section">
      <div class="panel-section-label">HTTP Response Code</div>
      <div class="panel-value">${s.response_code || 'N/A'}</div>
    </div>
    <div class="panel-section">
      <div class="panel-section-label">Detected</div>
      <div class="panel-value" style="color:#64748b">${new Date(s.created_at).toLocaleString()}</div>
    </div>
    <button class="replay-btn" onclick="triggerLoginTestUrl('${s.url}')">🧪 Test This Surface</button>
  `;
  openPanel();
}

// ─────────────────────────────────────────────────────────────────────────────
// Test Results
// ─────────────────────────────────────────────────────────────────────────────
async function loadTestResults() {
  if (!currentTargetId) {
    document.getElementById('testsTbody').innerHTML = `<tr><td colspan="6"><div class="empty"><div class="icon">🧪</div>Run Login Test Engine first</div></td></tr>`;
    return;
  }
  const res = await fetch(`${API}/api/targets/${currentTargetId}/auth_test_results`).catch(() => null);
  if (!res) return;
  const data = await res.json();
  renderTests(data);
}

function applyTestFilter() {
  const vuln = document.getElementById('testVulnFilter').value;
  const leak = document.getElementById('testLeakFilter').value;
  
  // For simplicity, we re-fetch and filter (or filter cached if we add cache)
  loadTestResults(); 
}

function renderTests(data) {
  const tbody = document.getElementById('testsTbody');
  const vulnFilter = document.getElementById('testVulnFilter')?.value;
  const leakFilter = document.getElementById('testLeakFilter')?.value;

  let filtered = data;
  if (vulnFilter) filtered = filtered.filter(r => r.vulnerability_type === vulnFilter);
  if (leakFilter === 'leaks_only') {
    filtered = filtered.filter(r => {
      try { return JSON.parse(r.sensitive_data_detected || '[]').length > 0; } catch { return false; }
    });
  } else if (leakFilter === 'no_leaks') {
    filtered = filtered.filter(r => {
      try { return JSON.parse(r.sensitive_data_detected || '[]').length === 0; } catch { return true; }
    });
  }

  if (!filtered.length) {
    tbody.innerHTML = `<tr><td colspan="6"><div class="empty"><div class="icon">🧪</div>No results matching filters</div></td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map(r => {
    let leaks = [];
    try { leaks = JSON.parse(r.sensitive_data_detected || '[]'); } catch {}
    const conf = (r.confidence * 100).toFixed(0);
    const confColor = conf >= 60 ? '#f87171' : conf >= 40 ? '#fbbf24' : '#34d399';
    return `
    <tr onclick="showTestDetail(${JSON.stringify(r).replace(/"/g,'&quot;')})">
      <td class="mono" style="color:#94a3b8">${truncate(r.url, 45)}</td>
      <td>${payloadTypeBadge(r.payload_type)}</td>
      <td><span style="${statusStyle(r.response_code)}">${r.response_code || '?'}</span></td>
      <td>${r.vulnerability_type ? vulnBadge(r.vulnerability_type) : '<span style="color:#475569">—</span>'}</td>
      <td>
        <div class="conf-bar">
          <div class="conf-track">
            <div class="conf-fill" style="width:${conf}%;background:${confColor}"></div>
          </div>
          <span style="font-size:.8rem;color:${confColor}">${conf}%</span>
        </div>
      </td>
      <td>${leaks.slice(0,3).map(l => `<span class="leak-tag">🚨 ${l.type}</span>`).join('')}${leaks.length > 3 ? `<span class="leak-tag">+${leaks.length-3}</span>` : ''}</td>
    </tr>`;
  }).join('');
}

function showTestDetail(r) {
  let leaks = [];
  try { leaks = JSON.parse(r.sensitive_data_detected || '[]'); } catch {}

  document.getElementById('panelTitle').textContent = `🧪 Test Result — ${r.payload_type || 'unknown'}`;
  document.getElementById('panelBody').innerHTML = `
    <div class="panel-section">
      <div class="panel-section-label">Target URL</div>
      <div class="panel-value mono" style="color:#a5b4fc">${r.url}</div>
    </div>
    <div class="panel-section">
      <div class="panel-section-label">Payload Sent</div>
      <div class="panel-code">${escHtml(r.payload || 'N/A')}</div>
    </div>
    <div class="panel-section">
      <div class="panel-section-label">Vulnerability Type</div>
      <div>${r.vulnerability_type ? vulnBadge(r.vulnerability_type) : '<span style="color:#475569">None detected</span>'}</div>
    </div>
    <div class="panel-section">
      <div class="panel-section-label">Response Code</div>
      <div class="panel-value">${r.response_code || 'N/A'}</div>
    </div>
    ${leaks.length ? `
    <div class="panel-section">
      <div class="panel-section-label">🚨 Sensitive Data Detected</div>
      ${leaks.map(l => `
        <div style="background:rgba(248,113,113,0.08);border:1px solid rgba(248,113,113,0.2);border-radius:8px;padding:.6rem .8rem;margin-bottom:.4rem">
          <span class="badge badge-${l.severity || 'high'}" style="margin-bottom:.3rem">${l.severity?.toUpperCase() || 'HIGH'}</span>
          <div style="font-size:.75rem;color:#94a3b8;margin-top:.2rem">${l.type}</div>
          <div class="mono" style="color:#f87171;font-size:.8rem;margin-top:.3rem">${escHtml((l.value || '').substring(0,120))}</div>
        </div>`).join('')}
    </div>` : ''}
    ${r.response_diff ? `
    <div class="panel-section">
      <div class="panel-section-label">Response Diff</div>
      <div class="panel-code" style="color:#fbbf24">${escHtml(r.response_diff.substring(0,800))}</div>
    </div>` : ''}
    ${r.raw_response_snippet ? `
    <div class="panel-section">
      <div class="panel-section-label">Raw Response</div>
      <div class="panel-code">${escHtml(r.raw_response_snippet.substring(0,800))}</div>
    </div>` : ''}
  `;
  openPanel();
}

// ─────────────────────────────────────────────────────────────────────────────
// Traffic Viewer
// ─────────────────────────────────────────────────────────────────────────────
async function loadTraffic() {
  const keyword = document.getElementById('trafficKeyword')?.value || '';
  const tag     = document.getElementById('trafficTagFilter')?.value || '';
  const status  = document.getElementById('trafficStatusFilter')?.value || '';

  let url = `${API}/api/traffic_logs?limit=150`;
  if (currentTargetId) url += `&target_id=${currentTargetId}`;
  if (keyword) url += `&keyword=${encodeURIComponent(keyword)}`;
  if (tag)     url += `&tag=${tag}`;
  if (status)  url += `&status=${status}`;

  const res = await fetch(url).catch(() => null);
  if (!res) return;
  allTrafficLogs = await res.json();
  renderTraffic(allTrafficLogs);
}

function filterTraffic() { loadTraffic(); }

function renderTraffic(logs) {
  const tbody = document.getElementById('trafficTbody');
  if (!logs.length) {
    tbody.innerHTML = `<tr><td colspan="8"><div class="empty"><div class="icon">📡</div>No traffic captured yet. Run a scan to populate.</div></td></tr>`;
    return;
  }

  tbody.innerHTML = logs.map((l, i) => {
    const lat = l.latency_ms || 0;
    const latClass = lat < 300 ? 'latency-good' : lat < 1000 ? 'latency-med' : 'latency-bad';
    const time = new Date(l.timestamp).toLocaleTimeString();
    let flags = [];
    try { flags = JSON.parse(l.sensitive_flags || '[]'); } catch {}
    const methodColor = { GET:'#34d399', POST:'#fbbf24', PUT:'#60a5fa', DELETE:'#f87171', PATCH:'#a78bfa' }[l.method] || '#94a3b8';

    return `
    <tr class="traffic-row" onclick="showTrafficDetail(${JSON.stringify(l).replace(/"/g,'&quot;')})" 
        style="${flags.length ? 'background:rgba(248,113,113,0.05);' : ''}">
      <td style="color:#475569;font-size:.75rem">${l.id}</td>
      <td style="color:#64748b;font-size:.75rem">${time}</td>
      <td><span class="badge" style="color:${methodColor};background:${methodColor}22">${l.method}</span></td>
      <td class="mono" style="color:#94a3b8">${truncate(l.url, 52)}</td>
      <td><span style="${statusStyle(l.response_status)}">${l.response_status || '?'}</span></td>
      <td class="${latClass}" style="font-size:.8rem">${lat.toFixed(0)}ms</td>
      <td><span class="badge badge-${l.tag || 'general'}">${l.tag || 'general'}</span></td>
      <td>${flags.slice(0,2).map(f => `<span class="leak-tag" style="${f.type==='otp_code' ? 'background:var(--auth-danger);color:#fff;' : ''}">${f.type}</span>`).join('')}${flags.length > 2 ? `<span class="leak-tag">+${flags.length-2}</span>` : ''}</td>
    </tr>`;
  }).join('');
}

function showTrafficDetail(l) {
  let reqH = {}, respH = {}, flags = [];
  try { reqH  = JSON.parse(l.request_headers  || '{}'); } catch {}
  try { respH = JSON.parse(l.response_headers || '{}'); } catch {}
  try { flags = JSON.parse(l.sensitive_flags  || '[]'); } catch {}

  document.getElementById('panelTitle').textContent = `📡 ${l.method} ${truncate(l.url, 35)}`;
  document.getElementById('panelBody').innerHTML = `
    <div class="panel-section">
      <div class="panel-section-label">Request</div>
      <div class="panel-value mono" style="color:#a5b4fc">${l.method} ${escHtml(l.url)}</div>
    </div>
    <div class="panel-section">
      <div class="panel-section-label">Status / Latency</div>
      <div class="panel-value"><span style="${statusStyle(l.response_status)}">${l.response_status}</span>  &nbsp; ${l.latency_ms?.toFixed(0)}ms</div>
    </div>
    <div class="panel-section">
      <div class="panel-section-label">Request Headers</div>
      <div class="panel-code">${escHtml(JSON.stringify(reqH, null, 2))}</div>
    </div>
    ${l.request_body ? `<div class="panel-section"><div class="panel-section-label">Request Body</div><div class="panel-code">${escHtml(l.request_body)}</div></div>` : ''}
    <div class="panel-section">
      <div class="panel-section-label">Response Headers</div>
      <div class="panel-code">${escHtml(JSON.stringify(respH, null, 2))}</div>
    </div>
    ${l.response_body ? `<div class="panel-section"><div class="panel-section-label">Response Body</div><div class="panel-code">${escHtml(l.response_body)}</div></div>` : ''}
    ${flags.length ? `<div class="panel-section">
      <div class="panel-section-label">🚨 Detected Flags</div>
      ${flags.map(f => `<div style="background:rgba(248,113,113,0.08);border:1px solid rgba(248,113,113,0.2);border-radius:6px;padding:.5rem .7rem;margin-bottom:.3rem"><span class="leak-tag">${f.type}</span> <span class="mono" style="font-size:.75rem;color:#f87171">${escHtml((f.value||'').substring(0,80))}</span></div>`).join('')}
    </div>` : ''}
    <button class="replay-btn" onclick="replayRequest(${JSON.stringify(l).replace(/"/g,'&quot;')})">↩ Replay Request</button>
  `;
  openPanel();
}

async function clearTraffic() {
  if (!confirm('Clear all traffic logs?')) return;
  await fetch(`${API}/api/traffic_logs`, { method: 'DELETE' });
  loadTraffic();
  loadStats();
}

// Replay: send same request from browser (GET only for safety)
async function replayRequest(log) {
  showToast(`Replaying: ${log.method} ${truncate(log.url, 40)}`);
  try {
    const resp = await fetch(log.url, { method: log.method });
    showToast(`Replay response: ${resp.status}`);
  } catch (e) {
    showToast(`Replay failed: ${e.message}`, true);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Payload Library
// ─────────────────────────────────────────────────────────────────────────────
async function loadPayloads() {
  const type = document.getElementById('plTypeFilter')?.value || '';
  let url = `${API}/api/payload_library?limit=60`;
  if (type) url += `&vuln_type=${type}`;
  const res = await fetch(url).catch(() => null);
  if (!res) return;
  const data = await res.json();
  const tbody = document.getElementById('payloadsTbody');

  if (!data.length) {
    tbody.innerHTML = `<tr><td colspan="5"><div class="empty"><div class="icon">💾</div>Library empty — click Seed Library</div></td></tr>`;
    return;
  }

  tbody.innerHTML = data.map(p => {
    const sr  = (p.success_rate * 100).toFixed(0);
    const clr = sr >= 60 ? '#f87171' : sr >= 40 ? '#fbbf24' : '#34d399';
    return `<tr>
      <td class="mono" style="color:#e2e8f0">${escHtml(p.payload)}</td>
      <td>${payloadTypeBadge(p.vuln_type)}</td>
      <td>
        <div class="conf-bar">
          <div class="conf-track"><div class="conf-fill" style="width:${sr}%;background:${clr}"></div></div>
          <span style="color:${clr};font-size:.8rem">${sr}%</span>
        </div>
      </td>
      <td style="color:#64748b">${p.used_count}×</td>
      <td><span class="badge badge-${p.source === 'gemma' ? 'llm' : 'heuristic'}">${p.source}</span></td>
    </tr>`;
  }).join('');
}

async function seedPayloads() {
  const res = await fetch(`${API}/api/payload_library/seed`, { method: 'POST' });
  const d = await res.json();
  showToast(d.message);
  loadPayloads();
  loadStats();
}

// ─────────────────────────────────────────────────────────────────────────────
// Scan Triggers
// ─────────────────────────────────────────────────────────────────────────────
async function runClassify() {
  if (!currentTargetId) return alert('Select a target first');
  const btn = document.getElementById('btnClassify');
  btn.innerHTML = '<span class="spinner"></span> Running…';
  btn.disabled = true;
  const res = await fetch(`${API}/api/targets/${currentTargetId}/classify_pages`, { method: 'POST' });
  const d = await res.json();
  showToast(d.message);
  setTimeout(() => { btn.innerHTML = '🔍 Classify Pages'; btn.disabled = false; loadSurfaces(); loadStats(); }, 3000);
}

async function runLoginTest() {
  if (!currentTargetId) return alert('Select a target first');
  const btn = document.getElementById('btnLogin');
  btn.innerHTML = '<span class="spinner"></span> Testing…';
  btn.disabled = true;
  const res = await fetch(`${API}/api/targets/${currentTargetId}/login_test`, { method: 'POST' });
  const d = await res.json();
  showToast(d.message);
  setTimeout(() => { btn.innerHTML = '🧪 Run Login Test'; btn.disabled = false; loadTestResults(); loadStats(); }, 3000);
}

async function runRiskScore() {
  if (!currentTargetId) return alert('Select a target first');
  const btn = document.getElementById('btnRisk');
  btn.innerHTML = '<span class="spinner"></span> Scoring…';
  btn.disabled = true;
  const res = await fetch(`${API}/api/targets/${currentTargetId}/risk_score`, { method: 'POST' });
  const d = await res.json();
  showToast(d.message);
  setTimeout(() => { btn.innerHTML = '📊 Risk Score'; btn.disabled = false; }, 2000);
}

async function runAdvancedTest() {
  if (!currentTargetId) return alert('Select a target first');
  const btn = document.getElementById('btnAdvanced');
  btn.innerHTML = '<span class="spinner"></span> Testing…';
  btn.disabled = true;
  const res = await fetch(`${API}/api/targets/${currentTargetId}/advanced_test`, { method: 'POST' });
  const d = await res.json();
  showToast(d.message);
  setTimeout(() => { btn.innerHTML = '🚀 Advanced Test'; btn.disabled = false; loadTestResults(); loadStats(); }, 5000);
}

async function triggerLoginTestUrl(url) {
  showToast(`Running login test on: ${truncate(url, 40)}`);
  await runLoginTest();
}

async function refreshAll() {
  await loadStats();
  await loadSurfaces();
  await loadTestResults();
  await loadTraffic();
  await loadPayloads();
}

// ─────────────────────────────────────────────────────────────────────────────
// Panel
// ─────────────────────────────────────────────────────────────────────────────
function openPanel() { document.getElementById('detailOverlay').classList.add('open'); }
function closePanel(e) {
  if (!e || e.target === document.getElementById('detailOverlay')) {
    document.getElementById('detailOverlay').classList.remove('open');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tabs
// ─────────────────────────────────────────────────────────────────────────────
function switchTab(id, btn) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('tab-' + id).classList.add('active');
  if (id === 'traffic')  loadTraffic();
  if (id === 'payloads') loadPayloads();
  if (id === 'surfaces') loadSurfaces();
  if (id === 'tests')    loadTestResults();
}

// ─────────────────────────────────────────────────────────────────────────────
// Toast
// ─────────────────────────────────────────────────────────────────────────────
function showToast(msg, isErr = false) {
  const t = document.createElement('div');
  t.style.cssText = `position:fixed;bottom:1.5rem;right:1.5rem;
    background:${isErr ? '#7f1d1d' : '#1e1b4b'};
    border:1px solid ${isErr ? '#f87171' : '#a78bfa'};
    color:#e2e8f0;padding:.7rem 1.2rem;border-radius:10px;
    font-size:.85rem;z-index:999;animation:fadeUp .3s ease;
    box-shadow:0 4px 20px rgba(0,0,0,0.5)`;
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 3500);
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────
function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function truncate(s, n) {
  if (!s) return '';
  return s.length > n ? s.substring(0, n) + '…' : s;
}

function escHtml(s) {
  return (s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function typeBadge(t) {
  const map = { login:'badge-login', admin:'badge-admin', dashboard:'badge-dashboard', public:'badge-public' };
  const icons = { login:'🔑', admin:'⚙️', dashboard:'📊', public:'🌐' };
  return `<span class="badge ${map[t]||'badge-public'}">${icons[t]||'📄'} ${t}</span>`;
}

function methodBadge(m) {
  return `<span class="badge ${m==='llm'?'badge-llm':'badge-heuristic'}">${m==='llm'?'🤖 LLM':'⚡ Heuristic'}</span>`;
}

function payloadTypeBadge(t) {
  const map = { sqli:'badge-sqli', auth_bypass:'badge-bypass', xss:'badge-admin', fuzz:'badge-general', error_probe:'badge-leak' };
  return `<span class="badge ${map[t]||'badge-general'}">${t||'unknown'}</span>`;
}

function vulnBadge(t) {
  const map = { sqli:'badge-sqli', auth_bypass:'badge-bypass', info_leak:'badge-leak', verbose_error:'badge-auth' };
  const icons = { sqli:'💉', auth_bypass:'🚪', info_leak:'📤', verbose_error:'🗣' };
  return `<span class="badge ${map[t]||'badge-general'}">${icons[t]||'⚠️'} ${t}</span>`;
}

function statusStyle(code) {
  if (!code) return 'color:#475569';
  if (code < 300) return 'color:#34d399';
  if (code < 400) return 'color:#60a5fa';
  if (code < 500) return 'color:#fbbf24';
  return 'color:#f87171';
}
