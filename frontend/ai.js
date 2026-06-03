const API_BASE = "/api";
let activeTargetFilter = "";
let allData = { vulnerabilities: [], code_reviews: [] };
let targetMap = {}; // ID -> URL mapping

document.addEventListener('DOMContentLoaded', () => {
    console.log("AI Intelligence Core Initialized");
    loadTargets();
    checkAIStatus();
    fetchAIReports();
    setInterval(fetchAIReports, 5000); // Poll every 5s
    setInterval(loadTargets, 8000); // Poll targets every 8s
});

async function loadTargets() {
    try {
        const resp = await fetch(`${API_BASE}/targets`);
        if (!resp.ok) throw new Error("API responded with error");
        const targets = await resp.json();
        
        // Update target map for labels
        targets.forEach(t => {
            targetMap[t.id] = t.url;
        });
        
        renderTargetList(targets);
    } catch(e) { 
        console.error("AI Intelligence: Failed to load targets", e); 
    }
}

function renderTargetList(targets) {
    const list = document.getElementById('target-list');
    if (!list) return;

    // "All Targets" master option
    let html = `
        <div class="target-item ${activeTargetFilter === "" ? 'active' : ''}" onclick="selectTarget('')" style="margin-bottom: 12px; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 12px;">
            <div style="flex: 1;">
                <div class="target-url">🌐 ALL TARGETS</div>
                <div class="target-status">Unified Forensic View</div>
            </div>
        </div>
    `;

    // Individual target items
    html += targets.map(t => `
        <div class="target-item ${String(t.id) === activeTargetFilter ? 'active' : ''}" onclick="selectTarget('${t.id}')">
            <div style="flex: 1; overflow: hidden;">
                <div class="target-url">${t.url}</div>
                <div class="target-status">${t.status.replace('_', ' ')}</div>
            </div>
            <div class="delete-btn" onclick="event.stopPropagation(); deleteTarget(${t.id})">&times;</div>
        </div>
    `).join('');

    list.innerHTML = html || '<div class="empty-state">No targets found</div>';
}

async function deleteTarget(id) {
    if(!confirm("Permanently delete this scan history?")) return;
    try {
        await fetch(`${API_BASE}/targets/${id}`, { method: 'DELETE' });
        if(activeTargetFilter === String(id)) activeTargetFilter = "";
        loadTargets();
    } catch(e) { alert("Delete failed"); }
}

function selectTarget(id) {
    activeTargetFilter = id;
    applyFilters();
    loadTargets(); // Refresh UI classes
}

async function checkAIStatus() {
    const statusEl = document.getElementById('ai-core-status');
    try {
        const resp = await fetch(`${API_BASE}/ai/status`);
        const data = await resp.json();
        
        if (data.status === 'online') {
            statusEl.innerHTML = `
                <div style="display: flex; align-items: center; gap: 10px;">
                    <span class="scanning-pulse" style="background: var(--accent-purple); box-shadow: 0 0 10px var(--accent-purple);"></span>
                    <span style="color: var(--accent-purple); font-weight: bold; text-transform: uppercase;">CORE ONLINE [${data.model}]</span>
                </div>
            `;
        } else {
            statusEl.innerHTML = `<span style="color: var(--accent-danger); font-weight: bold;">CORE OFFLINE</span>`;
        }
    } catch (e) {
        statusEl.innerHTML = `<span style="color: var(--accent-danger); font-weight: bold;">CORE OFFLINE</span>`;
    }
}

async function fetchAIReports() {
    try {
        const resp = await fetch(`${API_BASE}/ai/reports`);
        if (!resp.ok) return;
        allData = await resp.json();
        applyFilters();
    } catch (e) {
        console.error("Failed to fetch AI reports:", e);
    }
}

function applyFilters() {
    let vulns = allData.vulnerabilities || [];
    let reviews = allData.code_reviews || [];

    if (activeTargetFilter) {
        vulns = vulns.filter(v => String(v.target_id) === activeTargetFilter);
        reviews = reviews.filter(r => String(r.target_id) === activeTargetFilter);
    }

    renderVulnAnalysis(vulns);
    renderCodeAnalysis(reviews);
}

function renderVulnAnalysis(vulns) {
    const list = document.getElementById('ai-vuln-list');
    
    if (!vulns || vulns.length === 0) {
        list.innerHTML = '<div class="empty-state">No AI forensic data available yet.</div>';
        return;
    }

    list.innerHTML = vulns.map(v => {
        const targetUrl = targetMap[v.target_id] || "Unknown Target";
        return `
        <div class="glass-panel" style="padding: 15px; border-radius: 8px; border-left: 3px solid var(--accent-purple); background: rgba(0,0,0,0.3);">
            <div style="font-size: 0.7rem; color: var(--accent-purple); text-transform: uppercase; font-weight: bold; margin-bottom: 8px;">Target: ${targetUrl}</div>
            <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 10px; margin-bottom: 10px;">
                <h4 style="color: var(--text-primary); font-size: 1rem;">${v.vuln_type}</h4>
                <span class="badge" style="background: rgba(255, 42, 85, 0.1); color: var(--accent-danger); border: 1px solid var(--accent-danger);">${v.severity.toUpperCase()}</span>
            </div>
            
            <div style="margin-bottom: 15px;">
                <div style="color: var(--accent-purple); font-size: 0.75rem; text-transform: uppercase; font-weight: bold; margin-bottom: 5px;">AI Explanation</div>
                <div style="color: var(--text-secondary); font-size: 0.85rem; line-height: 1.5;">${v.explanation || 'No explanation generated.'}</div>
            </div>
            
            <div style="margin-bottom: 15px;">
                <div style="color: var(--text-secondary); font-size: 0.75rem; text-transform: uppercase; font-weight: bold; margin-bottom: 5px;">Proof of Concept / Evidence</div>
                <div style="background: rgba(255, 255, 255, 0.05); padding: 10px; border-radius: 4px; color: var(--text-primary); font-size: 0.8rem; font-family: monospace; word-wrap: break-word;">
                    ${v.evidence || 'No direct evidence provided.'}
                </div>
            </div>
            
            <div style="margin-bottom: 15px;">
                <div style="color: var(--accent-warning); font-size: 0.75rem; text-transform: uppercase; font-weight: bold; margin-bottom: 5px;">Risk Impact</div>
                <div style="color: var(--text-secondary); font-size: 0.85rem; line-height: 1.5;">${v.risk || 'No risk assessed.'}</div>
            </div>
            
            <div>
                <div style="color: var(--accent-success); font-size: 0.75rem; text-transform: uppercase; font-weight: bold; margin-bottom: 5px;">Remediation Fix</div>
                <div style="background: rgba(0, 230, 118, 0.05); border: 1px dashed rgba(0, 230, 118, 0.3); padding: 10px; border-radius: 4px; color: var(--accent-success); font-size: 0.85rem; font-family: monospace;">
                    ${v.fix || 'No fix suggested.'}
                </div>
            </div>
        </div>
    `; }).join('');
}

function renderCodeAnalysis(reviews) {
    const list = document.getElementById('ai-code-list');
    
    if (!reviews || reviews.length === 0) {
        list.innerHTML = '<div class="empty-state">No source code audits available.</div>';
        return;
    }

    list.innerHTML = reviews.map(r => {
        const targetUrl = targetMap[r.target_id] || "Unknown Target";
        return `
        <div class="glass-panel" style="padding: 15px; border-radius: 8px; border-left: 3px solid var(--accent-success); background: rgba(0,0,0,0.3);">
            <div style="font-size: 0.7rem; color: var(--accent-success); text-transform: uppercase; font-weight: bold; margin-bottom: 8px;">Target: ${targetUrl}</div>
            <div style="color: var(--text-primary); font-weight: bold; font-size: 0.9rem; margin-bottom: 10px;">
                📄 ${r.file_path}
            </div>
            
            <div style="background: rgba(0,0,0,0.5); padding: 10px; border-radius: 4px; border: 1px solid rgba(255,255,255,0.05); margin-bottom: 10px;">
                <pre style="color: #bbb; font-size: 0.75rem; font-family: monospace; white-space: pre-wrap; word-wrap: break-word;">${r.snippet}</pre>
            </div>
            
            <div>
                <div style="color: var(--accent-purple); font-size: 0.75rem; text-transform: uppercase; font-weight: bold; margin-bottom: 5px;">Gemma Analysis</div>
                <div style="color: var(--text-secondary); font-size: 0.85rem; line-height: 1.5;">
                    ${r.ai_analysis || 'Awaiting analysis...'}
                </div>
            </div>
        </div>
    `; }).join('');
}
