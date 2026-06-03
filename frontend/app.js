const API_BASE = "/api";
let currentTargetId = null;
let currentData = null; // Global storage for active target data
let pollInterval = null;
let lastLogCount = 0;

// DOM Elements
const targetList = document.getElementById('target-list');
const targetInput = document.getElementById('target-input');
const addTargetBtn = document.getElementById('add-target-btn');
const activeStatus = document.getElementById('active-status');
const startScanBtn = document.getElementById('start-scan-btn');
const stopScanBtn = document.getElementById('stop-scan-btn');
const killChainStatus = document.getElementById('kill-chain-status');
const crawlerConsole = document.getElementById('crawler-console');
const liveFeed = document.getElementById('live-feed');

let activeDashboardFilter = null;

// Initialization
document.addEventListener('DOMContentLoaded', () => {
    fetchTargets();
    
    addTargetBtn.addEventListener('click', addTarget);
    targetInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') addTarget();
    });
    
    startScanBtn.addEventListener('click', startScan);
    stopScanBtn.addEventListener('click', stopScan);
    
    const syncIntelBtn = document.getElementById('sync-intel-btn');
    if (syncIntelBtn) {
        syncIntelBtn.addEventListener('click', syncIntelligence);
    }

    // Setup Filters
    const cards = document.querySelectorAll('.metric-card');
    cards.forEach(card => {
        card.addEventListener('click', () => {
            const filter = card.dataset.filter;
            if (activeDashboardFilter === filter) {
                // Toggle off
                activeDashboardFilter = null;
                card.classList.remove('active-filter');
            } else {
                // Toggle on
                activeDashboardFilter = filter;
                cards.forEach(c => c.classList.remove('active-filter'));
                card.classList.add('active-filter');
            }
            if (currentTargetId) updateDashboard(); // Force re-render with filter
        });
    });

    // Event delegation for vulnerability modal
    document.getElementById('vuln-list')?.addEventListener('click', (e) => {
        const item = e.target.closest('[data-vuln-id]');
        if (item) openVulnModal(parseInt(item.dataset.vulnId));
    });

    // Event delegation for chain modal
    document.getElementById('chain-list')?.addEventListener('click', (e) => {
        const item = e.target.closest('[data-chain-id]');
        if (item) openChainModal(parseInt(item.dataset.chainId));
    });

    // Close modals on backdrop click
    document.getElementById('vuln-modal')?.addEventListener('click', (e) => {
        if (e.target === document.getElementById('vuln-modal')) closeVulnModal();
    });
    document.getElementById('chain-modal')?.addEventListener('click', (e) => {
        if (e.target === document.getElementById('chain-modal')) closeChainModal();
    });

    // Intel card click
    document.getElementById('card-intel')?.addEventListener('click', openIntelModal);

    // Close on backdrop click
    document.getElementById('intel-modal')?.addEventListener('click', (e) => {
        if (e.target === document.getElementById('intel-modal')) closeIntelModal();
    });
});

// Target Management
async function fetchTargets() {
    try {
        const resp = await fetch(`${API_BASE}/targets`);
        if (!resp.ok) throw new Error("Failed to fetch");
        const targets = await resp.json();
        renderTargetList(targets);
    } catch (e) {
        console.error("Fetch targets error:", e);
    }
}

function renderTargetList(targets) {
    targetList.innerHTML = targets.map(t => `
        <div class="target-item ${t.id === currentTargetId ? 'active' : ''}" onclick="selectTarget(${t.id}, '${t.url}')">
            <div style="flex: 1; overflow: hidden;">
                <div class="target-url">${t.url}</div>
                <div class="target-status">${t.status.replace('_', ' ')}</div>
            </div>
            <div class="delete-btn" onclick="event.stopPropagation(); deleteTarget(${t.id})">&times;</div>
        </div>
    `).join('') || '<div class="empty-state">No targets found</div>';
}

async function addTarget() {
    const url = targetInput.value.trim();
    if (!url) return;
    try {
        const resp = await fetch(`${API_BASE}/targets`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ url })
        });
        if (resp.ok) {
            targetInput.value = '';
            fetchTargets();
        }
    } catch(e) {
        alert("Failed to add target");
    }
}

async function deleteTarget(id) {
    if(!confirm("Permanently delete this scan history?")) return;
    try {
        await fetch(`${API_BASE}/targets/${id}`, { method: 'DELETE' });
        if(currentTargetId === id) {
            currentTargetId = null;
            clearInterval(pollInterval);
            resetDashboard();
        }
        fetchTargets();
    } catch(e) {
        alert("Delete failed");
    }
}

// Scanning Operations
function selectTarget(id, url) {
    console.log(`[SYSTEM] Selecting Target: ${id} (${url})`);
    currentTargetId = id;
    lastLogCount = 0;
    
    // UI Reset for new target
    crawlerConsole.innerHTML = '> CONNECTING TO TARGET NODES...';
    liveFeed.innerHTML = '';
    
    // Explicitly Enable and Show the Launch Button
    startScanBtn.disabled = false;
    startScanBtn.style.display = 'block';
    stopScanBtn.style.display = 'none';
    
    // Set active status
    activeStatus.innerHTML = `
        <div style="text-align: right;">
            <div style="color: var(--text-primary); font-weight: bold; font-size: 1.1rem;">${url}</div>
            <div style="color: var(--text-secondary); font-size: 0.8rem; text-transform: uppercase;">INITIALIZING SESSION...</div>
        </div>
    `;
    
    fetchTargets(); // Update active class
    
    if (pollInterval) clearInterval(pollInterval);
    updateDashboard(); // Initial fetch
    pollInterval = setInterval(updateDashboard, 2000);
}

async function startScan() {
    if (!currentTargetId) return;
    try {
        await fetch(`${API_BASE}/targets/${currentTargetId}/start_mythos`, { method: 'POST' });
        logToConsole("SYSTEM", "Autonomous Pipeline Initialized.", "var(--accent-cyan)");
        updateDashboard();
    } catch(e) {
        alert("Failed to launch scan");
    }
}

async function stopScan() {
    if (!currentTargetId) return;
    try {
        await fetch(`${API_BASE}/targets/${currentTargetId}/stop`, { method: 'POST' });
        logToConsole("SYSTEM", "EMERGENCY STOP SIGNAL SENT.", "var(--accent-danger)");
        stopScanBtn.style.display = 'none';
        startScanBtn.style.display = 'block';
    } catch(e) {
        alert("Failed to stop scan");
    }
}

async function syncIntelligence() {
    const btn = document.getElementById('sync-intel-btn');
    const originalText = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'SYNCING...';
    logToConsole("SYSTEM", "Requesting Global CWE Intelligence Synchronization...", "var(--accent-success)");
    
    try {
        const resp = await fetch(`${API_BASE}/intel/sync`, { method: 'POST' });
        const data = await resp.json();
        logToConsole("SYSTEM", `Sync Complete: ${data.synced_count} CWE patterns synchronized.`, "var(--accent-success)");
        updateGlobalStats();
    } catch(e) {
        logToConsole("SYSTEM", "Intelligence Sync Failed.", "var(--accent-danger)");
    } finally {
        btn.disabled = false;
        btn.textContent = originalText;
    }
}

async function updateGlobalStats() {
    try {
        const resp = await fetch(`${API_BASE}/stats`);
        const stats = await resp.json();
        const intelEl = document.getElementById('stat-intel');
        if (intelEl) intelEl.textContent = stats.intel_cwes || 0;
    } catch(e) {}
}

// Initial stats fetch
updateGlobalStats();
setInterval(updateGlobalStats, 30000);

// Dashboard Updates
async function updateDashboard() {
    const tid = currentTargetId;
    if (!tid) return;
    
    try {
        // 1. Fetch Report (Recon & Vulns)
        const reportResp = await fetch(`${API_BASE}/targets/${tid}/report`);
        if (!reportResp.ok) return;
        const data = await reportResp.json();
        
        // Safety check: if target changed while we were fetching, discard
        if (currentTargetId !== tid) return;

        currentData = data;
        
        updateStatus(data);
        updateKillChain(data.status);
        updateReconAndVulns(data);
        
        // 2. Fetch Code Reviews
        const crResp = await fetch(`${API_BASE}/targets/${tid}/code_reviews`);
        if(crResp.ok) updateCodeReviews(await crResp.json());
        
        // 3. Fetch Chains
        const chainResp = await fetch(`${API_BASE}/targets/${tid}/chains`);
        if(chainResp.ok) {
            const chains = await chainResp.json();
            currentData.chains = chains; // Store in global state
            updateChains(chains);
        }
        
        // 4. Fetch Brute Force
        const bruteResp = await fetch(`${API_BASE}/targets/${tid}/brute_findings`);
        if(bruteResp.ok) updateBruteFindings(await bruteResp.json());
        
        // 5. Fetch Logs
        const logsResp = await fetch(`${API_BASE}/targets/${tid}/logs`);
        if(logsResp.ok) updateLogs(await logsResp.json());
        
    } catch (e) {
        console.error("[CRITICAL] Dashboard update failed:", e);
        // If we hit a 422 or 404, maybe stop polling to prevent console flood
        if (e.message.includes('422') || e.message.includes('404')) {
            console.warn("[SYSTEM] Critical error detected. Pausing telemetry.");
            clearInterval(pollInterval);
        }
    }
}

function updateStatus(data) {
    const isRunning = data.status.includes('running');
    
    startScanBtn.style.display = isRunning ? 'none' : 'block';
    stopScanBtn.style.display = isRunning ? 'block' : 'none';
    
    activeStatus.innerHTML = `
        <div style="display: flex; align-items: center; justify-content: flex-end; gap: 10px;">
            ${isRunning ? '<span class="scanning-pulse"></span>' : ''}
            <div style="text-align: right;">
                <div style="color: var(--text-primary); font-weight: bold; font-size: 1.1rem;">${data.url}</div>
                <div style="color: var(--text-secondary); font-size: 0.8rem; text-transform: uppercase;">STATUS: <span style="color: ${isRunning ? 'var(--accent-cyan)' : 'var(--text-secondary)'}">${data.status.replace('_', ' ')}</span></div>
            </div>
        </div>
    `;
}

function updateKillChain(status) {
    killChainStatus.textContent = status.toUpperCase().replace('_', ' ');
    
    const steps = ['recon', 'weapon', 'exploit', 'chain', 'report'];
    
    const statusMap = {
        'pending': -1,
        'recon_running': 0,
        'scanning': 1,
        'validating': 2,
        'analyzing': 3,
        'scanned': 4,
        'stopped': -1,
        'failed': -1
    };
    
    // For single scan pipeline, map status generically if mythos_running
    let currentStep = statusMap[status] ?? (status.includes('running') ? 0 : -1);
    if(status === 'scanned') currentStep = 4;
    
    steps.forEach((step, index) => {
        const el = document.getElementById(`step-${step}`);
        if(index <= currentStep) {
            el.style.background = status === 'scanned' ? 'var(--accent-success)' : 'var(--accent-cyan)';
            el.style.boxShadow = `0 0 10px ${status === 'scanned' ? 'var(--accent-success)' : 'var(--accent-cyan)'}`;
        } else {
            el.style.background = '#222';
            el.style.boxShadow = 'none';
        }
    });
}

function updateReconAndVulns(data) {
    const reconData = data.recon_data || [];
    const rawVulns = data.vulnerabilities || [];
    
    // Deduplicate vulnerabilities globally for the target
    const seenVulnsGlobal = new Set();
    const vulns = rawVulns.filter(v => {
        const key = `${v.vuln_type}-${v.severity}-${v.evidence}`;
        if (seenVulnsGlobal.has(key)) return false;
        seenVulnsGlobal.add(key);
        return true;
    });
    
    const endpoints = reconData.filter(r => r.data_type === 'endpoint');
    const params = reconData.filter(r => r.data_type === 'parameter');
    const ports = reconData.filter(r => r.data_type === 'port');
    
    // Categorize vulnerabilities
    const tokens = vulns.filter(v => v.vuln_type.toLowerCase().includes('token') || v.vuln_type.toLowerCase().includes('jwt'));
    const cloud = vulns.filter(v => v.vuln_type.toLowerCase().includes('cloud') || v.vuln_type.toLowerCase().includes('s3') || v.vuln_type.toLowerCase().includes('metadata'));
    const graphql = vulns.filter(v => v.vuln_type.toLowerCase().includes('graphql'));
    const websockets = vulns.filter(v => v.vuln_type.toLowerCase().includes('websocket') || v.vuln_type.toLowerCase().includes('ws:'));
    const ratelimit = vulns.filter(v => v.vuln_type && v.vuln_type.toLowerCase().includes('rate limit'));
    const redteam = vulns.filter(v => v.vuln_type && (v.vuln_type.toLowerCase().includes('lateral') || v.vuln_type.toLowerCase().includes('persistence')));
    const brutes = data.brute_findings || [];
    const defensive = vulns.filter(v => v.vuln_type.toLowerCase().includes('waf') || v.vuln_type.toLowerCase().includes('honeypot'));

    document.getElementById('stat-endpoints').textContent = endpoints.length;
    document.getElementById('stat-params').textContent = params.length;
    document.getElementById('stat-ports').textContent = ports.length;
    document.getElementById('stat-vulns').textContent = vulns.length;
    document.getElementById('stat-tokens').textContent = tokens.length;
    document.getElementById('stat-cloud').textContent = cloud.length;
    document.getElementById('stat-graphql').textContent = graphql.length;
    document.getElementById('stat-websockets').textContent = websockets.length;
    document.getElementById('stat-ratelimit').textContent = ratelimit.length;
    document.getElementById('stat-defensive').textContent = defensive.length;
    document.getElementById('stat-redteam').textContent = redteam.length;
    document.getElementById('stat-brute').textContent = brutes.length;
    
    let filteredRecon = reconData;
    let filteredVulns = vulns;

    if (activeDashboardFilter === 'endpoints') filteredRecon = endpoints;
    else if (activeDashboardFilter === 'params') filteredRecon = params;
    else if (activeDashboardFilter === 'ports') filteredRecon = ports;
    else if (activeDashboardFilter === 'vulns') filteredRecon = []; 
    else if (activeDashboardFilter === 'tokens') { filteredRecon = []; filteredVulns = tokens; }
    else if (activeDashboardFilter === 'cloud') { filteredRecon = []; filteredVulns = cloud; }
    else if (activeDashboardFilter === 'graphql') { filteredRecon = []; filteredVulns = graphql; }
    else if (activeDashboardFilter === 'websockets') { filteredRecon = []; filteredVulns = websockets; }
    else if (activeDashboardFilter === 'ratelimit') { filteredRecon = []; filteredVulns = ratelimit; }
    else if (activeDashboardFilter === 'defensive') { filteredRecon = []; filteredVulns = defensive; }
    else if (activeDashboardFilter === 'chains') { filteredRecon = []; filteredVulns = []; }

    if (activeDashboardFilter && activeDashboardFilter !== 'vulns') filteredVulns = []; // hide vulns if filtering others

    document.getElementById('recon-count').textContent = filteredRecon.length;
    document.getElementById('vuln-count').textContent = filteredVulns.length;
    
    const reconList = document.getElementById('recon-list');
    reconList.innerHTML = filteredRecon.slice().reverse().map(r => `
        <div class="list-item">
            <span style="color: var(--accent-cyan); font-weight: bold; font-size: 0.75rem;">[${r.data_type.toUpperCase()}]</span> 
            <span style="color: var(--text-secondary); margin: 0 5px;">${r.method}</span> 
            <span style="color: var(--text-primary);">${r.path}</span>
        </div>
    `).join('') || '<div class="empty-state">No surface data.</div>';
    
    const vulnList = document.getElementById('vuln-list');
    vulnList.innerHTML = filteredVulns.map(v => `
        <div class="vuln-item ${v.severity.toLowerCase()}" data-vuln-id="${v.id}" style="cursor: pointer;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <div style="font-weight: 600;">${v.vuln_type}</div>
                <div style="display: flex; gap: 5px;">
                    ${v.cvss_score ? `<span style="font-size:0.7rem; background:rgba(255,255,255,0.1); color:#fff; padding:2px 6px; border-radius:4px; font-weight: 800;">CVSS: ${v.cvss_score}</span>` : ''}
                    ${v.ai_report_status === 'completed' ? '<span style="font-size:0.7rem; background:rgba(176,38,255,0.15); color:var(--accent-purple); border:1px solid var(--accent-purple); padding:2px 6px; border-radius:4px;">AI REPORT ✓</span>' : ''}
                </div>
            </div>
            <div style="font-size: 0.75rem; color: var(--text-secondary); margin-top: 4px;">
                ${v.severity.toUpperCase()} | ${v.status} | ${v.cwe_id || 'CWE-Pending'}
            </div>
            <div style="font-size: 0.8rem; margin-top: 6px; font-family: monospace; color: #ccc; word-break: break-all;">
                ${(v.evidence || '').substring(0, 100)}...
            </div>
            <div style="font-size:0.72rem; color: var(--text-secondary); margin-top:6px;">🔍 Click to view full details &amp; generate AI Report</div>
        </div>
    `).join('') || '<div class="empty-state">No vulnerabilities found.</div>';
}

function updateCodeReviews(reviews) {
    document.getElementById('cr-count').textContent = reviews.length;
    const crList = document.getElementById('code-review-list');
    crList.innerHTML = reviews.map(r => `
        <div class="list-item" style="border-left: 2px solid var(--accent-success); padding-left: 10px;">
            <div style="color: var(--accent-success); font-weight: 600;">${r.file_path}</div>
            <div style="font-size: 0.8rem; color: var(--text-secondary); margin-top: 4px;">
                ${r.ai_analysis ? r.ai_analysis.substring(0, 100) + '...' : 'Awaiting AI Analysis...'}
            </div>
        </div>
    `).join('') || '<div class="empty-state">No code disclosures.</div>';
}

function updateChains(chains) {
    document.getElementById('stat-chains').textContent = chains.length;
    
    let filteredChains = chains;
    if (activeDashboardFilter && activeDashboardFilter !== 'chains') {
        filteredChains = [];
    }

    document.getElementById('chain-count').textContent = filteredChains.length;
    const chainList = document.getElementById('chain-list');
    chainList.innerHTML = filteredChains.map(c => `
        <div class="list-item" data-chain-id="${c.id}" style="background: rgba(255, 42, 85, 0.05); padding: 12px; border-radius: 6px; border-left: 3px solid var(--accent-danger); cursor: pointer; transition: 0.2s; margin-bottom: 8px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div style="color: var(--accent-danger); font-weight: 700; font-size: 0.95rem;">⚡ ${c.chain_title}</div>
                <div style="color: var(--accent-warning); font-size: 0.7rem; font-weight: 800;">${c.confidence}% CONF</div>
            </div>
            <div style="font-size: 0.82rem; color: var(--text-secondary); margin-top: 6px; line-height: 1.4;">
                ${c.attack_narrative ? c.attack_narrative.substring(0, 100) + '...' : 'Building narrative...'}
            </div>
            <div style="font-size: 0.7rem; color: var(--accent-cyan); margin-top: 8px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;">🔍 Click for Full Forensic Briefing</div>
        </div>
    `).join('') || '<div class="empty-state">No correlated chains.</div>';
}

function openChainModal(chainId) {
    if (!currentData || !currentData.chains) return;
    const chain = currentData.chains.find(c => c.id === chainId);
    if (!chain) return;

    document.getElementById('modal-chain-title').textContent = chain.chain_title.toUpperCase();
    document.getElementById('modal-chain-meta').textContent = `CHAIN ID: ${chain.id} | TARGET: ${currentData.url} | STATUS: CONFIRMED`;
    document.getElementById('modal-chain-severity').textContent = chain.severity.toUpperCase();
    document.getElementById('modal-chain-confidence').textContent = `${chain.confidence}%`;
    document.getElementById('modal-chain-narrative').textContent = chain.attack_narrative || "Forensic narrative pending.";
    
    // Resolve involved vulnerabilities
    const involvedIds = (chain.vuln_ids_involved || "").split(",").map(id => parseInt(id.trim()));
    const involvedVulns = (currentData.vulnerabilities || []).filter(v => involvedIds.includes(v.id));
    
    document.getElementById('modal-chain-vulns-count').textContent = involvedVulns.length;

    // Render Proofs
    const proofContainer = document.getElementById('modal-chain-proofs');
    if (involvedVulns.length === 0) {
        proofContainer.innerHTML = '<div class="empty-state">No technical proofs correlated for this chain yet.</div>';
    } else {
        proofContainer.innerHTML = involvedVulns.map(v => `
            <div class="glass-panel" style="padding: 15px; border-radius: 8px; border-left: 3px solid var(--accent-cyan); background: rgba(0, 240, 255, 0.02);">
                <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                    <span style="font-weight: 700; color: var(--text-primary); font-size: 0.9rem;">${v.vuln_type}</span>
                    <span style="color: var(--accent-${v.severity.toLowerCase() === 'critical' ? 'danger' : 'warning'}); font-weight: 800; font-size: 0.75rem;">${v.severity.toUpperCase()}</span>
                </div>
                <div style="font-size: 0.75rem; color: var(--text-secondary); margin-bottom: 8px; font-family: monospace;">Vector ID: ${v.id} | CWE: ${v.cwe_id || 'N/A'}</div>
                <pre style="background: rgba(0,0,0,0.4); padding: 12px; border-radius: 6px; font-family: monospace; font-size: 0.8rem; color: var(--accent-cyan); white-space: pre-wrap; word-break: break-all; border: 1px solid rgba(0,240,255,0.1);">${v.evidence || 'No technical evidence recorded.'}</pre>
            </div>
        `).join('');
    }

    document.getElementById('chain-modal').style.display = 'flex';
}

function switchTab(tab) {
    ['details', 'report', 'forensic'].forEach(t => {
        const el = document.getElementById(`modal-tab-${t}`);
        const tabBtn = document.getElementById(`tab-${t}`);
        if(el) el.style.display = (t === tab) ? 'block' : 'none';
        if(tabBtn) {
            if(t === tab) tabBtn.classList.add('active');
            else tabBtn.classList.remove('active');
        }
    });
}

function decodeJWT(evidence) {
    const headerEl = document.getElementById('jwt-header');
    const payloadEl = document.getElementById('jwt-payload');
    const strengthBar = document.getElementById('jwt-strength-bar');
    const strengthLabel = document.getElementById('jwt-strength-label');

    try {
        const tokenMatch = evidence.match(/ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/);
        if (tokenMatch) {
            const parts = tokenMatch[0].split('.');
            headerEl.textContent = JSON.stringify(JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/'))), null, 2);
            payloadEl.textContent = JSON.stringify(JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'))), null, 2);
            
            // Heuristic strength
            if (evidence.toLowerCase().includes('cracked') || evidence.toLowerCase().includes('weak secret')) {
                strengthBar.style.width = '100%';
                strengthBar.style.background = 'var(--accent-danger)';
                strengthLabel.textContent = 'CRACKED';
            } else {
                strengthBar.style.width = '40%';
                strengthBar.style.background = 'var(--accent-warning)';
                strengthLabel.textContent = 'WEAK';
            }
        } else {
            headerEl.textContent = "Token not found in evidence.";
            payloadEl.textContent = "Token not found in evidence.";
        }
    } catch (e) {
        headerEl.textContent = "Error decoding JWT.";
        payloadEl.textContent = e.message;
    }
}

function closeChainModal() {
    document.getElementById('chain-modal').style.display = 'none';
}

function updateBruteFindings(findings) {
    document.getElementById('brute-count').textContent = findings.length;
    const bruteList = document.getElementById('brute-list');
    bruteList.innerHTML = findings.map(f => `
        <div class="list-item" style="border-left: 2px solid var(--accent-purple); padding-left: 10px;">
            <div style="color: var(--text-primary); font-weight: 600;">${f.success_status}</div>
            <div style="font-size: 0.8rem; color: var(--text-secondary); margin-top: 4px;">${f.url}</div>
            ${f.otp_leak ? `<div style="color: var(--accent-warning); font-size: 0.75rem; margin-top: 4px;">⚠️ ${f.otp_leak}</div>` : ''}
        </div>
    `).join('') || '<div class="empty-state">No active hits.</div>';
}

function updateLogs(logs) {
    if (!logs || logs.length === 0) return;
    
    // Only process new logs
    if (logs.length > lastLogCount) {
        const newLogs = logs.slice(lastLogCount);
        
        newLogs.forEach(log => {
            // Append to Global Console
            const line = document.createElement('div');
            line.innerHTML = `> <span style="color: #666;">[${new Date(log.created_at).toLocaleTimeString()}]</span> <span style="color: var(--accent-cyan);">[${log.agent_name}]</span> ${log.message}`;
            
            if(log.log_level === 'CRITICAL') line.style.color = 'var(--accent-danger)';
            if(log.log_level === 'WARNING') line.style.color = 'var(--accent-warning)';
            if(log.log_level === 'SUCCESS') line.style.color = 'var(--accent-success)';
            
            crawlerConsole.appendChild(line);
            
            // Append to Live Feed (Visualized)
            const iconMap = { SPIDER: '🔍', SCANNER: '🚀', ANALYZER: '🧠', VALIDATOR: '🛡️', ORCHESTRATOR: '⚙️', PORT_SCANNER: '🌐', CONFIG_AUDIT: '⚙️', CODE_REVIEW: '📝', CHAIN_ANALYZER: '⚡', BRUTE_FORCE: '🔐' };
            const feedLine = document.createElement('div');
            feedLine.className = 'list-item';
            feedLine.style.padding = '6px 0';
            feedLine.innerHTML = `
                <span style="font-size: 1.2rem; margin-right: 8px;">${iconMap[log.agent_name] || '⚡'}</span>
                <span style="color: var(--text-primary); font-size: 0.8rem;">${log.message}</span>
            `;
            liveFeed.prepend(feedLine);
        });
        
        // Auto scroll console
        crawlerConsole.scrollTop = crawlerConsole.scrollHeight;
        
        // Keep live feed trimmed
        while (liveFeed.children.length > 50) {
            liveFeed.removeChild(liveFeed.lastChild);
        }
        
        lastLogCount = logs.length;
    }
}

function logToConsole(agent, message, color) {
    const line = document.createElement('div');
    line.innerHTML = `> <span style="color: #666;">[${new Date().toLocaleTimeString()}]</span> <span style="color: var(--accent-cyan);">[${agent}]</span> <span style="color: ${color || '#fff'};">${message}</span>`;
    crawlerConsole.appendChild(line);
    crawlerConsole.scrollTop = crawlerConsole.scrollHeight;
}

function resetDashboard() {
    activeStatus.innerHTML = '<span class="status-text">Select a target to begin</span>';
    startScanBtn.disabled = true;
    startScanBtn.style.display = 'block';
    stopScanBtn.style.display = 'none';
    killChainStatus.textContent = 'INITIALIZING';
    document.querySelectorAll('.step').forEach(s => { s.style.background = '#222'; s.style.boxShadow = 'none'; });
    
    ['stat-endpoints', 'stat-params', 'stat-vulns', 'stat-chains', 'stat-ports', 'stat-tokens', 'stat-cloud', 'stat-graphql', 'stat-websockets', 'stat-ratelimit', 'stat-defensive', 'stat-redteam', 'stat-brute', 'recon-count', 'cr-count', 'vuln-count', 'chain-count', 'brute-count'].forEach(id => {
        const el = document.getElementById(id);
        if(el) el.textContent = '0';
    });
    
    ['recon-list', 'code-review-list', 'vuln-list', 'chain-list', 'brute-list'].forEach(id => {
        const el = document.getElementById(id);
        if(el) el.innerHTML = `<div class="empty-state">Data reset.</div>`;
    });
    
    crawlerConsole.innerHTML = '> SYSTEM IDLE...';
    liveFeed.innerHTML = '<div><span style="color: #666;">> Awaiting pipeline initiation...</span></div>';
    
    // Reset filters
    activeDashboardFilter = null;
    document.querySelectorAll('.metric-card').forEach(c => c.classList.remove('active-filter'));
}

// ============================
// Vulnerability Modal Logic
// ============================
let currentVulnId = null;
let reportPollTimer = null;

async function openVulnModal(vulnId) {
    currentVulnId = vulnId;
    switchTab('details');
    const modal = document.getElementById('vuln-modal');
    modal.style.display = 'flex';

    try {
        const resp = await fetch(`/api/vulnerabilities/${vulnId}`);
        if (!resp.ok) throw new Error('Not found');
        const v = await resp.json();
        populateModal(v);
    } catch(e) {
        console.error('Failed to load vulnerability', e);
    }
}

function populateModal(vuln) {
    const typeEl = document.getElementById('modal-vuln-type');
    const metaEl = document.getElementById('modal-vuln-meta');
    const severity = document.getElementById('modal-severity');
    const cwe = document.getElementById('modal-cwe');
    const evidence = document.getElementById('modal-evidence');
    const explanation = document.getElementById('modal-explanation');
    const risk = document.getElementById('modal-risk');
    const fix = document.getElementById('modal-fix');

    // Forensic containers
    const forensicJwt = document.getElementById('forensic-jwt');
    const forensicCloud = document.getElementById('forensic-cloud');
    const forensicGraphql = document.getElementById('forensic-graphql');
    const forensicWebsocket = document.getElementById('forensic-websocket');
    const forensicRatelimit = document.getElementById('forensic-ratelimit');
    const forensicDefensive = document.getElementById('forensic-defensive');
    const forensicEmpty = document.getElementById('forensic-empty');

    typeEl.textContent = vuln.vuln_type;
    metaEl.textContent = `ID: ${vuln.id} | Path: ${vuln.path} | Method: ${vuln.method}`;
    severity.textContent = (vuln.cvss_score ? `CVSS ${vuln.cvss_score}` : vuln.severity.toUpperCase());
    severity.className = `metric-value text-${vuln.severity.toLowerCase()}`;
    cwe.textContent = vuln.cwe_id || 'CWE-Unknown';
    evidence.textContent = vuln.evidence || 'No evidence captured.';
    explanation.textContent = vuln.explanation || 'Analyzing with AI...';
    risk.textContent = vuln.risk || 'Assessing impact...';
    fix.textContent = vuln.fix || 'Drafting remediation...';

    // Hide all forensic views first
    [forensicJwt, forensicCloud, forensicGraphql, forensicWebsocket, forensicRatelimit, forensicDefensive, forensicEmpty].forEach(el => { if(el) el.style.display = 'none'; });

    const typeLower = vuln.vuln_type.toLowerCase();
    if (typeLower.includes('jwt') || typeLower.includes('token')) {
        forensicJwt.style.display = 'block';
        decodeJWT(vuln.evidence);
    } else if (typeLower.includes('cloud') || typeLower.includes('s3') || typeLower.includes('metadata')) {
        forensicCloud.style.display = 'block';
    } else if (typeLower.includes('graphql')) {
        forensicGraphql.style.display = 'block';
    } else if (typeLower.includes('websocket') || typeLower.includes('ws:')) {
        forensicWebsocket.style.display = 'block';
    } else if (typeLower.includes('rate limit') || typeLower.includes('throttling')) {
        forensicRatelimit.style.display = 'block';
    } else if (typeLower.includes('waf') || typeLower.includes('honeypot')) {
        forensicDefensive.style.display = 'block';
        if (typeLower.includes('waf')) {
            document.getElementById('waf-type').textContent = vuln.vuln_type.split(': ')[1] || 'DETECTED';
            document.getElementById('honeypot-risk').textContent = 'LOW';
        } else {
            document.getElementById('waf-type').textContent = 'NONE DETECTED';
            document.getElementById('honeypot-risk').textContent = 'CRITICAL';
        }
    } else {
        forensicEmpty.style.display = 'block';
    }

    // Advanced report section
    const genBtn = document.getElementById('modal-gen-btn');
    const regenBtn = document.getElementById('modal-regen-btn');
    const reportContent = document.getElementById('advanced-report-content');
    const statusBanner = document.getElementById('report-status-banner');

    if (vuln.ai_report_status === 'completed') {
        if (vuln.advanced_ai_report) {
            reportContent.textContent = vuln.advanced_ai_report;
            currentReportContent = vuln.advanced_ai_report;
            genBtn.style.display = 'none';
            regenBtn.style.display = 'block';
            statusBanner.innerHTML = `<div style="color:var(--accent-success); font-size:0.85rem;">✅ Official Forensic Report Generated</div>`;
            document.getElementById('report-download-container').style.display = 'block';
        } else {
            document.getElementById('report-download-container').style.display = 'none';
        }
    } else if (vuln.ai_report_status === 'generating') {
        genBtn.disabled = true;
        genBtn.textContent = '⏳ Generating...';
        statusBanner.innerHTML = `<div style="color:var(--accent-warning); font-size:0.85rem;">⏳ Gemma AI is analyzing this vulnerability. This may take a minute...</div>`;
        startReportPolling();
    } else if (vuln.ai_report_status === 'failed') {
        genBtn.style.display = 'block';
        regenBtn.style.display = 'none';
        genBtn.textContent = '🧠 Retry Advanced Report';
        statusBanner.innerHTML = `<div style="color:var(--accent-danger); font-size:0.85rem;">❌ Report generation failed. Click retry.</div>`;
    } else {
        genBtn.style.display = 'block';
        genBtn.disabled = false;
        genBtn.textContent = '🧠 Generate Forensic Analysis Report';
        regenBtn.style.display = 'none';
        statusBanner.innerHTML = '';
        reportContent.textContent = 'No report generated yet. Click the button below to start deep forensic AI analysis.';
        document.getElementById('report-download-container').style.display = 'none';
    }
}

function downloadForensicReport() {
    if (!currentVulnId || !currentReportContent) return;
    const blob = new Blob([currentReportContent], { type: 'text/markdown' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Forensic_Report_Vuln_${currentVulnId}.md`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
}

let currentReportContent = ""; // Global to store for download

function closeVulnModal() {
    document.getElementById('vuln-modal').style.display = 'none';
    clearInterval(reportPollTimer);
    reportPollTimer = null;
    currentVulnId = null;
}

function switchTab(tab) {
    document.getElementById('modal-tab-details').style.display = tab === 'details' ? 'block' : 'none';
    document.getElementById('modal-tab-forensic').style.display = tab === 'forensic' ? 'block' : 'none';
    document.getElementById('modal-tab-report').style.display = tab === 'report' ? 'block' : 'none';
    
    document.getElementById('tab-details').classList.toggle('active', tab === 'details');
    document.getElementById('tab-forensic').classList.toggle('active', tab === 'forensic');
    document.getElementById('tab-report').classList.toggle('active', tab === 'report');
}

async function triggerAdvancedReport() {
    if (!currentVulnId) return;
    const genBtn = document.getElementById('modal-gen-btn');
    const regenBtn = document.getElementById('modal-regen-btn');
    const statusBanner = document.getElementById('report-status-banner');

    genBtn.disabled = true;
    genBtn.textContent = '⏳ Generating...';
    regenBtn.style.display = 'none';
    statusBanner.innerHTML = `<div style="color:var(--accent-warning); font-size:0.85rem;">⏳ Gemma AI is analyzing this vulnerability. This may take a minute...</div>`;

    try {
        await fetch(`/api/vulnerabilities/${currentVulnId}/advanced_analyze`, { method: 'POST' });
        switchTab('report');
        startReportPolling();
    } catch(e) {
        statusBanner.innerHTML = `<div style="color:var(--accent-danger); font-size:0.85rem;">❌ Failed to start analysis.</div>`;
        genBtn.disabled = false;
    }
}

function startReportPolling() {
    clearInterval(reportPollTimer);
    reportPollTimer = setInterval(async () => {
        if (!currentVulnId) { clearInterval(reportPollTimer); return; }
        try {
            const resp = await fetch(`/api/vulnerabilities/${currentVulnId}`);
            const v = await resp.json();
            if (v.ai_report_status === 'completed' || v.ai_report_status === 'failed') {
                clearInterval(reportPollTimer);
                populateModal(v);
            }
        } catch(e) {}
    }, 3000);
}

// Close modal on backdrop click — moved to DOMContentLoaded

// Draggable Console Logic
const globalConsole = document.querySelector('.global-console');
const consoleHeader = document.querySelector('.console-header');

let isDragging = false;
let currentX;
let currentY;
let initialX;
let initialY;
let xOffset = 0;
let yOffset = 0;

consoleHeader.addEventListener('mousedown', dragStart);
document.addEventListener('mouseup', dragEnd);
document.addEventListener('mousemove', drag);

function dragStart(e) {
    initialX = e.clientX - xOffset;
    initialY = e.clientY - yOffset;
    if (e.target === consoleHeader) {
        isDragging = true;
    }
}

function dragEnd(e) {
    initialX = currentX;
    initialY = currentY;
    isDragging = false;
}

function drag(e) {
    if (isDragging) {
        e.preventDefault();
        currentX = e.clientX - initialX;
        currentY = e.clientY - initialY;
        xOffset = currentX;
        yOffset = currentY;
        globalConsole.style.transform = `translate3d(${currentX}px, ${currentY}px, 0)`;
    }
}async function openIntelModal() {
    const modal = document.getElementById('intel-modal');
    const body = document.getElementById('intel-modal-body');
    modal.style.display = 'flex';
    body.innerHTML = '<div class="empty-state">⚡ Querying Global CWE Database...</div>';

    try {
        const resp = await fetch('/api/intel/recent');
        const cwes = await resp.json();
        
        if (cwes.length === 0) {
            body.innerHTML = '<div class="empty-state">No intelligence data synced yet. Click "Sync Intelligence" to fetch data.</div>';
            return;
        }

        body.innerHTML = `
            <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(400px, 1fr)); gap: 15px;">
                ${cwes.map(c => `
                    <div class="glass-panel" style="padding: 15px; border-radius: 8px; border-left: 3px solid var(--accent-cyan); background: rgba(255,255,255,0.02);">
                        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 10px;">
                            <div>
                                <div style="font-weight: 800; color: var(--text-primary); font-size: 1.1rem;">${c.cwe_id}</div>
                                <div style="font-size: 0.7rem; color: var(--text-secondary); margin-top: 2px;">NAME: ${c.name}</div>
                            </div>
                            <div style="color: var(--accent-cyan); font-weight: 900; font-size: 0.9rem;">
                                INTEL
                            </div>
                        </div>
                        <div style="font-size: 0.85rem; color: var(--text-secondary); line-height: 1.5; margin-bottom: 12px; display: -webkit-box; -webkit-line-clamp: 5; -webkit-box-orient: vertical; overflow: hidden;">
                            ${c.description}
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    } catch (e) {
        body.innerHTML = '<div class="empty-state text-danger">Failed to fetch intelligence data.</div>';
    }
}

function closeIntelModal() {
    document.getElementById('intel-modal').style.display = 'none';
}
