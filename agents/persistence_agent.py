from typing import List, Any
from core.base_agent import ShivamAgent, Finding, RiskLevel
from sqlalchemy.future import select
from models import ReconData, Vulnerability

class PersistenceAuditorAgent(ShivamAgent):
    name = "persistence_auditor"
    phase = "post_exploitation"

    async def execute(self, target: Any, session: Any = None) -> List[Finding]:
        findings = []
        url = getattr(target, 'url', str(target))

        # 1. Check for writable config/env files found during recon
        result = await session.execute(
            select(ReconData).where(
                ReconData.target_id == target.id,
                ReconData.path.like('%.env%') | ReconData.path.like('%config%') | ReconData.path.like('%settings%')
            )
        )
        sensitive_files = result.scalars().all()

        for file in sensitive_files:
            # Heuristic: If we can see it, can we write to it? (Simulated)
            findings.append(Finding(
                id=f"persistence_vector_{file.id}",
                agent_name=self.name,
                title="Potential Persistence Vector: Writable Configuration",
                description=f"Sensitive file '{file.path}' is accessible. In a post-exploitation scenario, this could be used to inject backdoors or steal database credentials for persistent access.",
                risk_level=RiskLevel.HIGH,
                evidence=f"File Discovered: {file.path}\nPermissions: Read-Access Confirmed",
                remediation="Restrict filesystem permissions. Ensure sensitive configuration files are not accessible via the web root.",
                cwe_id="CWE-538",
                cvss_score=7.5,
                target_url=url
            ))

        # 2. Check for broad API scopes or debug modes
        # (Simulated check for common debug flags in recon details)
        return findings
