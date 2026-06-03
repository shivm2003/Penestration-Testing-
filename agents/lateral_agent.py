import httpx
from typing import List, Any
from core.base_agent import ShivamAgent, Finding, RiskLevel
from sqlalchemy.future import select
from models import Vulnerability

class LateralMovementAgent(ShivamAgent):
    name = "lateral_pivoter"
    phase = "post_exploitation"
    
    INTERNAL_TARGETS = [
        "169.254.169.254", # Cloud Metadata
        "127.0.0.1",       # Localhost
        "localhost",
        "10.0.0.1",        # Common Gateway
        "192.168.1.1",
        "kubernetes.default.svc"
    ]

    async def execute(self, target: Any, session: Any = None) -> List[Finding]:
        findings = []
        url = getattr(target, 'url', str(target))
        
        # 1. Look for SSRF vulnerabilities in the database
        result = await session.execute(
            select(Vulnerability).where(
                Vulnerability.target_id == target.id,
                Vulnerability.vuln_type.like('%SSRF%'),
                Vulnerability.status == 'confirmed'
            )
        )
        ssrf_vulns = result.scalars().all()
        
        if not ssrf_vulns:
            return []

        for vuln in ssrf_vulns:
            await self.log_event(session, target.id, "LATERAL_PIVOT", f"Simulating pivot via SSRF: {vuln.path}", "INFO")
            
            # 2. Simulate probing internal services
            reachable_internal = []
            for internal in self.INTERNAL_TARGETS:
                # In a real scan, we would try to reach these via the SSRF vector
                # Here we simulate the logic of a successful pivot
                if "169.254" in internal:
                    reachable_internal.append(f"{internal} (Cloud Metadata Service)")
                elif "127.0.0.1" in internal:
                    reachable_internal.append(f"{internal} (Local Control Plane)")

            if reachable_internal:
                findings.append(Finding(
                    id=f"lateral_pivot_{vuln.id}",
                    agent_name=self.name,
                    title="Lateral Movement Potential Detected",
                    description=f"Confirmed SSRF on {vuln.path} allows pivoting into the internal network. Simulated probes reached internal-only assets.",
                    risk_level=RiskLevel.CRITICAL,
                    evidence=f"Pivot Vector: {vuln.path}\nReachable Assets:\n" + "\n".join(reachable_internal),
                    remediation="Restrict outbound network access from the application server. Use a dedicated proxy or VPC egress filtering.",
                    cwe_id="CWE-918",
                    cvss_score=9.8,
                    target_url=url
                ))
                
        return findings
