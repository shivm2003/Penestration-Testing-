const API_BASE = "/api";
let currentTargetId = null;
let currentData = {
    targets: [],
    chains: [],
    vulnerabilities: []
};

// Initialization
document.addEventListener('DOMContentLoaded', () => {
    fetchTargets();
});

async function fetchTargets() {
    try {
        const resp = await fetch(`${API_BASE}/targets`);
        const targets = await resp.json();
        currentData.targets = targets;
        renderTargetList(targets);
    } catch (e) {
        console.error("Fetch targets error:", e);
    }
}

function renderTargetList(targets) {
    const list = document.getElementById('target-list');
    list.innerHTML = targets.map(t => `
        <div class="target-item ${t.id === currentTargetId ? 'active' : ''}" onclick="selectTarget(${t.id}, '${t.url}')">
            <div style="flex: 1; overflow: hidden;">
                <div class="target-url">${t.url}</div>
                <div class="target-status" style="font-size:0.7rem; color:var(--text-secondary);">${t.status.replace('_', ' ')}</div>
            </div>
        </div>
    `).join('') || '<div class="empty-state">No targets found.</div>';
}

async function selectTarget(id, url) {
    currentTargetId = id;
    document.getElementById('active-target-display').textContent = `ACTIVE TARGET: ${url}`;
    renderTargetList(currentData.targets); // Update active class
    
    // Clear container
    const container = document.getElementById('chain-container');
    container.innerHTML = '<div class="empty-state">Analyzing intelligence...</div>';
    
    try {
        // Fetch vulnerabilities first (needed for proofs)
        const reportResp = await fetch(`${API_BASE}/targets/${id}/report`);
        const reportData = await reportResp.json();
        currentData.vulnerabilities = reportData.vulnerabilities || [];
        
        // Fetch chains
        const chainResp = await fetch(`${API_BASE}/targets/${id}/chains`);
        const chains = await chainResp.json();
        currentData.chains = chains;
        
        renderChains(chains);
    } catch (e) {
        container.innerHTML = '<div class="empty-state text-danger">Failed to load intelligence.</div>';
    }
}

function renderChains(chains) {
    const container = document.getElementById('chain-container');
    document.getElementById('chain-stats').textContent = `${chains.length} Chains Identified`;
    
    if (chains.length === 0) {
        container.innerHTML = '<div class="empty-state">No correlated attack chains found for this target yet. Run the full pipeline with Chain Analysis enabled.</div>';
        return;
    }

    container.innerHTML = chains.map(c => {
        const involvedIds = (c.vuln_ids_involved || "").split(",").map(id => parseInt(id.trim()));
        const involvedVulns = currentData.vulnerabilities.filter(v => involvedIds.includes(v.id));
        
        return `
            <div class="intel-card glass-panel" style="margin-bottom: 30px; border-color: rgba(255, 42, 85, 0.4); background: rgba(255, 42, 85, 0.02);">
                <div class="card-header" style="background: rgba(255, 42, 85, 0.1); display: flex; justify-content: space-between; align-items: center; padding: 15px 20px;">
                    <div>
                        <h4 style="color: var(--accent-danger); font-size: 1.1rem; margin: 0;">⚡ ${c.chain_title}</h4>
                        <div style="font-size: 0.75rem; color: var(--text-secondary); margin-top: 4px;">SEVERITY: <span style="color: var(--accent-danger); font-weight: 800;">${c.severity.toUpperCase()}</span> | CONFIDENCE: ${c.confidence}%</div>
                    </div>
                    <button class="btn btn-launch" onclick="openChainModal(${c.id})" style="padding: 6px 14px; font-size: 0.75rem; background: var(--accent-danger); color: #000;">VIEW ANALYSIS</button>
                </div>
                <div class="card-body" style="padding: 20px;">
                    <div style="margin-bottom: 20px;">
                        <div style="color: var(--text-secondary); font-size: 0.75rem; text-transform: uppercase; font-weight: 700; margin-bottom: 8px;">Attack Narrative Preview</div>
                        <p style="font-size: 0.85rem; color: var(--text-primary); line-height: 1.6;">${c.attack_narrative ? c.attack_narrative.substring(0, 200) + '...' : 'Building narrative...'}</p>
                    </div>
                    
                    <div style="display: flex; flex-direction: column; gap: 10px;">
                        <div style="color: var(--accent-cyan); font-size: 0.75rem; text-transform: uppercase; font-weight: 700; margin-bottom: 5px;">Chain Path Nodes</div>
                        <div style="display: flex; flex-wrap: wrap; gap: 10px;">
                            ${involvedVulns.map(v => `
                                <div style="background: rgba(0, 240, 255, 0.1); border: 1px solid rgba(0, 240, 255, 0.3); padding: 5px 12px; border-radius: 20px; font-size: 0.75rem; color: var(--accent-cyan);">
                                    ${v.vuln_type}
                                </div>
                            `).join(' <span style="color:rgba(255,255,255,0.2);">→</span> ')}
                        </div>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

function openChainModal(chainId) {
    const chain = currentData.chains.find(c => c.id === chainId);
    if (!chain) return;

    document.getElementById('modal-title').textContent = chain.chain_title.toUpperCase();
    document.getElementById('modal-meta').textContent = `CHAIN ID: ${chain.id} | SEVERITY: ${chain.severity.toUpperCase()} | CONFIDENCE: ${chain.confidence}%`;
    document.getElementById('modal-narrative').textContent = chain.attack_narrative || "No narrative generated.";

    const involvedIds = (chain.vuln_ids_involved || "").split(",").map(id => parseInt(id.trim()));
    const involvedVulns = currentData.vulnerabilities.filter(v => involvedIds.includes(v.id));

    const proofContainer = document.getElementById('modal-proofs');
    proofContainer.innerHTML = involvedVulns.map(v => `
        <div class="glass-panel" style="padding: 15px; border-radius: 8px; border-left: 3px solid var(--accent-cyan);">
            <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                <span style="font-weight: 700; color: var(--text-primary); font-size: 0.9rem;">${v.vuln_type}</span>
                <span style="color: var(--accent-${v.severity.toLowerCase() === 'critical' ? 'danger' : 'warning'}); font-weight: 800; font-size: 0.75rem;">${v.severity.toUpperCase()}</span>
            </div>
            <div style="font-size: 0.75rem; color: var(--text-secondary); margin-bottom: 8px;">CWE: ${v.cwe_id || 'N/A'} | ID: ${v.id}</div>
            <div style="background: rgba(0,0,0,0.3); padding: 10px; border-radius: 4px; font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; color: var(--accent-cyan); overflow-x: auto;">
                ${v.evidence || 'No evidence recorded.'}
            </div>
        </div>
    `).join('');

    document.getElementById('chain-detail-modal').style.display = 'flex';
}

function closeModal() {
    document.getElementById('chain-detail-modal').style.display = 'none';
}

function triggerAIDeepDive() {
    alert("AI Deep Dive initialized. Gemma is correlating historical data for this chain...");
}

function downloadChainReport() {
    alert("Forensic Briefing generated. Starting download...");
}
