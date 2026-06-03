const API_BASE = "/api";
let allVulns = [];
let activeDetailVulnId = null;
let activeTargetFilter = "";
let activeStatusFilter = "";

document.addEventListener('DOMContentLoaded', () => {
    loadTargets();
    loadAllVulns();
    setInterval(loadAllVulns, 8000); // refresh

    document.getElementById('target-filter').addEventListener('change', (e) => {
        activeTargetFilter = e.target.value;
        renderGrid();
    });

    document.querySelectorAll('input[name="status-filter"]').forEach(radio => {
        radio.addEventListener('change', (e) => {
            activeStatusFilter = e.target.value;
            renderGrid();
        });
    });
});

async function loadTargets() {
    const resp = await fetch(`${API_BASE}/targets`);
    const targets = await resp.json();
    const sel = document.getElementById('target-filter');
    targets.forEach(t => {
        const opt = document.createElement('option');
        opt.value = t.id;
        opt.textContent = t.url;
        sel.appendChild(opt);
    });
}

async function loadAllVulns() {
    try {
        // Get all targets first, then load vulns per target
        const tResp = await fetch(`${API_BASE}/targets`);
        const targets = await tResp.json();

        const all = [];
        for (const t of targets) {
            const rResp = await fetch(`${API_BASE}/targets/${t.id}/report`);
            if (!rResp.ok) continue;
            const data = await rResp.json();
            const vulns = (data.vulnerabilities || []).map(v => ({ ...v, target_url: t.url }));
            all.push(...vulns);
        }

        // Global deduplication across targets for the grid view
        const seenVulns = new Set();
        allVulns = all.filter(v => {
            const key = `${v.vuln_type}-${v.severity}-${v.evidence}`;
            if (seenVulns.has(key)) return false;
            seenVulns.add(key);
            return true;
        });
        renderGrid();
    } catch(e) {
        console.error("Failed to load vulns", e);
    }
}

function renderGrid() {
    const grid = document.getElementById('reports-grid');
    const statsEl = document.getElementById('report-stats');

    let filtered = allVulns;
    if (activeTargetFilter) filtered = filtered.filter(v => String(v.target_id) === activeTargetFilter);
    if (activeStatusFilter) filtered = filtered.filter(v => v.ai_report_status === activeStatusFilter);

    const completed = allVulns.filter(v => v.ai_report_status === 'completed').length;
    const pending = allVulns.filter(v => v.ai_report_status === 'none').length;
    const generating = allVulns.filter(v => v.ai_report_status === 'generating').length;
    statsEl.textContent = `${completed} Reports | ${pending} Pending | ${generating} Generating`;

    if (filtered.length === 0) {
        grid.innerHTML = `<div class="empty-state" style="grid-column:1/-1;text-align:center;padding:60px;color:var(--text-secondary);">No vulnerabilities match the selected filter.</div>`;
        return;
    }

    grid.innerHTML = filtered.map(v => {
        const statusConfig = {
            'completed': { color: 'var(--accent-success)', icon: '✅', label: 'Report Ready' },
            'generating': { color: 'var(--accent-warning)', icon: '⏳', label: 'Generating...' },
            'failed':     { color: 'var(--accent-danger)', icon: '❌', label: 'Failed' },
            'none':       { color: 'var(--text-secondary)', icon: '—', label: 'No Report' }
        };
        const sc = statusConfig[v.ai_report_status] || statusConfig['none'];
        const severityColors = { critical: 'var(--accent-danger)', high: 'var(--accent-warning)', medium: '#ffaa00', low: 'var(--accent-success)' };
        const sevColor = severityColors[v.severity?.toLowerCase()] || '#aaa';

        return `
            <div class="glass-panel" style="padding:20px; border-radius:12px; display:flex; flex-direction:column; gap:12px; border-left:3px solid ${sevColor};">
                <div style="display:flex; justify-content:space-between; align-items:flex-start;">
                    <div>
                        <div style="font-weight:700; font-size:1rem;">${v.vuln_type}</div>
                        <div style="font-size:0.75rem; color:var(--text-secondary); margin-top:3px;">${v.target_url || 'Unknown Target'}</div>
                    </div>
                    <span style="font-size:0.72rem; padding:3px 8px; border-radius:4px; border:1px solid ${sevColor}; color:${sevColor};">${(v.severity || '').toUpperCase()}</span>
                </div>

                <div style="font-size:0.8rem; color:var(--text-secondary);">
                    ${v.cwe_id ? `<span style="color:var(--accent-cyan);">${v.cwe_id}</span> · ` : ''}
                    Status: ${v.status} · ID: #${v.id}
                </div>

                <div style="display:flex; justify-content:space-between; align-items:center; margin-top:4px;">
                    <span style="color:${sc.color}; font-size:0.82rem;">${sc.icon} ${sc.label}</span>
                    <div style="display:flex; gap:8px;">
                        ${v.ai_report_status === 'completed'
                            ? `<button class="btn" style="padding:6px 12px; font-size:0.78rem; background:rgba(176,38,255,0.15); color:var(--accent-purple); border:1px solid var(--accent-purple);" onclick="viewReport(${v.id})">View Report</button>`
                            : `<button class="btn" style="padding:6px 12px; font-size:0.78rem; background:rgba(0,240,255,0.1); color:var(--accent-cyan); border:1px solid var(--accent-cyan);" onclick="generateReport(${v.id}, this)" ${v.ai_report_status === 'generating' ? 'disabled' : ''}>
                                    ${v.ai_report_status === 'generating' ? '⏳ Generating...' : '🧠 Generate Report'}
                               </button>`}
                        ${v.ai_report_status === 'completed'
                            ? `<button class="btn" style="padding:6px 12px; font-size:0.78rem; background:rgba(255,255,255,0.05); color:var(--text-secondary);" onclick="generateReport(${v.id}, this)">🔄</button>`
                            : ''}
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

async function generateReport(vulnId, btn) {
    if (btn) { btn.disabled = true; btn.textContent = '⏳ Starting...'; }
    try {
        await fetch(`${API_BASE}/vulnerabilities/${vulnId}/advanced_analyze`, { method: 'POST' });
        setTimeout(loadAllVulns, 1500);
    } catch(e) {
        alert("Failed to trigger analysis.");
        if (btn) { btn.disabled = false; btn.textContent = '🧠 Generate Report'; }
    }
}

async function generateAllPending() {
    const pending = allVulns.filter(v => v.ai_report_status === 'none' || v.ai_report_status === 'failed');
    if (pending.length === 0) { alert("No pending vulnerabilities to analyze."); return; }
    if (!confirm(`Start AI analysis for ${pending.length} vulnerabilities? This may take several minutes.`)) return;

    for (const v of pending) {
        await fetch(`${API_BASE}/vulnerabilities/${v.id}/advanced_analyze`, { method: 'POST' });
        await new Promise(r => setTimeout(r, 500)); // stagger
    }
    alert(`${pending.length} analysis tasks queued!`);
    setTimeout(loadAllVulns, 2000);
}

async function viewReport(vulnId) {
    activeDetailVulnId = vulnId;
    const resp = await fetch(`${API_BASE}/vulnerabilities/${vulnId}`);
    const v = await resp.json();
    document.getElementById('detail-title').textContent = v.vuln_type;
    document.getElementById('detail-meta').textContent = `${v.severity.toUpperCase()} | ${v.cwe_id || 'No CWE'} | ID: #${v.id}`;
    document.getElementById('detail-report-body').textContent = v.advanced_ai_report || 'No report content found.';
    document.getElementById('detail-modal').style.display = 'flex';
}

function closeDetailModal() {
    document.getElementById('detail-modal').style.display = 'none';
    activeDetailVulnId = null;
}

async function regenReport() {
    if (!activeDetailVulnId) return;
    await fetch(`${API_BASE}/vulnerabilities/${activeDetailVulnId}/advanced_analyze`, { method: 'POST' });
    closeDetailModal();
    setTimeout(loadAllVulns, 1500);
}

function downloadReport() {
    const content = document.getElementById('detail-report-body').textContent;
    const title = document.getElementById('detail-title').textContent;
    const blob = new Blob([content], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `AI_Report_${title.replace(/[^a-z0-9]/gi, '_')}.txt`;
    a.click();
}

document.getElementById('detail-modal')?.addEventListener('click', (e) => {
    if (e.target === document.getElementById('detail-modal')) closeDetailModal();
});
