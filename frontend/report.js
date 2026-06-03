const API_BASE = "/api";
let selectedTargetId = null;
let currentReportData = null;

document.addEventListener('DOMContentLoaded', () => {
    fetchTargets();
    document.getElementById('target-select').addEventListener('change', (e) => {
        const val = e.target.value;
        if (val) {
            selectedTargetId = val;
            loadReport(val);
        } else {
            document.getElementById('report-content').style.display = 'none';
            document.getElementById('empty-prompt').style.display = 'flex';
        }
    });
});

async function fetchTargets() {
    try {
        const resp = await fetch(`${API_BASE}/targets`);
        const targets = await resp.json();
        const select = document.getElementById('target-select');
        targets.forEach(t => {
            const option = document.createElement('option');
            option.value = t.id;
            option.textContent = `[${t.status.toUpperCase()}] ${t.url}`;
            select.appendChild(option);
        });
    } catch (e) {
        console.error("Failed to load targets", e);
    }
}

async function loadReport(targetId) {
    document.getElementById('empty-prompt').style.display = 'none';
    document.getElementById('report-content').style.display = 'block';
    
    try {
        // Fetch Report Data
        const reportResp = await fetch(`${API_BASE}/targets/${targetId}/report`);
        const data = await reportResp.json();
        
        // Fetch Chains (Not included in standard report endpoint yet)
        const chainResp = await fetch(`${API_BASE}/targets/${targetId}/chains`);
        const chains = await chainResp.json();
        
        currentReportData = { ...data, chains };
        
        renderReport(currentReportData);
    } catch(e) {
        console.error("Failed to load report", e);
        alert("Error loading report data.");
    }
}

function renderReport(data) {
    document.getElementById('report-target-url').textContent = `Target: ${data.url}`;
    document.getElementById('report-date').textContent = `Generated: ${new Date().toLocaleString()}`;
    
    // Deduplicate vulnerabilities for the report
    const seenVulns = new Set();
    const vulns = (data.vulnerabilities || []).filter(v => {
        const key = `${v.vuln_type}-${v.severity}-${v.evidence}`;
        if (seenVulns.has(key)) return false;
        seenVulns.add(key);
        return true;
    });
    const chains = data.chains || [];
    const recon = data.recon_data || [];
    
    // Categorize findings
    const defensiveFindings = vulns.filter(v => v.vuln_type && (v.vuln_type.toLowerCase().includes('waf') || v.vuln_type.toLowerCase().includes('honeypot')));
    const redTeamFindings = vulns.filter(v => v.vuln_type && (v.vuln_type.toLowerCase().includes('lateral') || v.vuln_type.toLowerCase().includes('persistence')));
    const generalVulns = vulns.filter(v => !defensiveFindings.includes(v) && !redTeamFindings.includes(v));
    
    let criticalCount = 0;
    let highCount = 0;
    let medLowCount = 0;
    
    generalVulns.forEach(v => {
        const s = v.severity.toLowerCase();
        if (s === 'critical') criticalCount++;
        else if (s === 'high') highCount++;
        else medLowCount++;
    });
    
    document.getElementById('rep-critical').textContent = criticalCount;
    document.getElementById('rep-high').textContent = highCount;
    document.getElementById('rep-medlow').textContent = medLowCount;
    document.getElementById('rep-chains').textContent = chains.length;
    document.getElementById('rep-surface').textContent = recon.length;
    
    // Calculate Global Risk Score
    calculateRiskScore(criticalCount, highCount, medLowCount, chains.length);
    
    // Render Vuln Summary
    const vulnList = document.getElementById('report-vulns');
    if (generalVulns.length === 0) {
        vulnList.innerHTML = '<p style="color: var(--text-secondary);">No vulnerabilities detected during assessment.</p>';
    } else {
        vulnList.innerHTML = generalVulns.map(v => `
            <div style="border-bottom: 1px solid rgba(255,255,255,0.05); padding: 12px 0;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                    <span style="font-weight: 600; font-size: 1rem;">${v.vuln_type}</span>
                    <span style="color: var(--accent-${v.severity.toLowerCase() === 'critical' ? 'danger' : v.severity.toLowerCase() === 'high' ? 'warning' : 'success'}); font-weight: 800;">${v.severity.toUpperCase()}</span>
                </div>
                ${v.evidence ? `
                    <span class="proof-label">Technical Proof of Concept</span>
                    <div class="proof-block">${v.evidence}</div>
                ` : ''}
            </div>
        `).join('');
    }

    // Render Defensive Profile
    const defContainer = document.getElementById('report-defensive');
    if (defensiveFindings.length === 0) {
        defContainer.innerHTML = '<p style="color: var(--text-secondary);">No defensive appliances identified.</p>';
    } else {
        defContainer.innerHTML = defensiveFindings.map(v => `
            <div class="glass-panel" style="padding:15px; border-radius:8px; border:1px solid rgba(0,230,118,0.2);">
                <div style="color:var(--accent-success); font-weight:700; font-size:0.8rem; margin-bottom:5px;">${v.vuln_type.toUpperCase()}</div>
                <div style="font-size:0.85rem; color:var(--text-primary); font-family:monospace;">${v.evidence}</div>
            </div>
        `).join('');
    }

    // Render Red Team Impact
    const redContainer = document.getElementById('report-redteam');
    if (redTeamFindings.length === 0) {
        redContainer.innerHTML = '<p style="color: var(--text-secondary);">No lateral movement or persistence vectors identified.</p>';
    } else {
        redContainer.innerHTML = redTeamFindings.map(v => `
            <div class="list-item" style="border-left:3px solid var(--accent-danger); padding:15px;">
                <div style="color:var(--accent-danger); font-weight:800; font-size:1rem; margin-bottom:5px;">⚡ ${v.vuln_type}</div>
                <div style="font-size:0.9rem; color:var(--text-primary); margin-bottom:8px;">${v.explanation || 'Post-exploitation impact analysis pending.'}</div>
                <div style="font-size:0.8rem; color:var(--text-secondary);"><strong>Risk Escalation:</strong> ${v.risk || 'N/A'}</div>
            </div>
        `).join('');
    }
    
    // Render Chains
    const chainList = document.getElementById('report-chains');
    if (chains.length === 0) {
        chainList.innerHTML = '<p style="color: var(--text-secondary);">No attack chains correlated.</p>';
    } else {
        chainList.innerHTML = chains.map(c => {
            // Find evidence from involved vulnerabilities
            const involvedIds = (c.vuln_ids_involved || "").split(",").map(id => parseInt(id.trim()));
            const involvedVulns = (data.vulnerabilities || []).filter(v => involvedIds.includes(v.id));
            
            return `
                <div style="background: rgba(255, 42, 85, 0.05); border: 1px solid rgba(255, 42, 85, 0.2); padding: 20px; border-radius: 8px; margin-bottom: 15px;">
                    <div style="color: var(--accent-danger); font-weight: bold; font-size: 1.1rem; margin-bottom: 8px;">${c.chain_title}</div>
                    <div style="color: var(--text-secondary); font-size: 0.95rem; line-height: 1.5; margin-bottom: 15px;">${c.attack_narrative || 'Narrative pending...'}</div>
                    
                    ${involvedVulns.length > 0 ? `
                        <div style="margin-top: 15px; border-top: 1px solid rgba(255, 42, 85, 0.2); padding-top: 15px;">
                            <span class="proof-label" style="color: var(--accent-danger);">Verified Technical Proofs</span>
                            ${involvedVulns.map(iv => `
                                <div style="margin-top: 12px;">
                                    <div style="font-size: 0.75rem; color: var(--text-secondary); margin-bottom: 4px; font-weight: 600;">Vector: ${iv.vuln_type}</div>
                                    <div class="proof-block" style="border-color: rgba(255, 42, 85, 0.3); color: #ff8fa3;">${iv.evidence || 'No evidence captured.'}</div>
                                </div>
                            `).join('')}
                        </div>
                    ` : ''}
                </div>
            `;
        }).join('');
    }
}

function calculateRiskScore(crit, high, medLow, chainCount) {
    // Arbitrary weighting
    let score = 100 - (crit * 20) - (high * 10) - (medLow * 2) - (chainCount * 25);
    if (score < 0) score = 0;
    
    const gradeEl = document.getElementById('risk-grade');
    let grade = 'A';
    let color = 'var(--accent-success)';
    
    if (score >= 90) { grade = 'A'; color = 'var(--accent-success)'; }
    else if (score >= 75) { grade = 'B'; color = '#aaff00'; }
    else if (score >= 60) { grade = 'C'; color = 'var(--accent-warning)'; }
    else if (score >= 40) { grade = 'D'; color = '#ff7b00'; }
    else { grade = 'F'; color = 'var(--accent-danger)'; }
    
    gradeEl.textContent = grade;
    gradeEl.style.color = color;
}

function downloadJSON() {
    if (!currentReportData) return;
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(currentReportData, null, 2));
    const dlAnchorElem = document.createElement('a');
    dlAnchorElem.setAttribute("href", dataStr);
    dlAnchorElem.setAttribute("download", `VAPT_Report_${currentReportData.url.replace(/[^a-z0-9]/gi, '_').toLowerCase()}.json`);
    dlAnchorElem.click();
}
