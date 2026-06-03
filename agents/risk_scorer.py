"""
Risk Scoring Engine
===================
Computes a custom risk score per vulnerability:

    Risk = Exploitability × Impact × Exposure

Where:
  Exploitability  → validator confidence (0.0–1.0)
  Impact          → Gemma AI reasoning score (0.0–1.0) or CVSS score
  Exposure        → internet-facing flag + auth level multiplier

Also provides an aggregate target risk score.
"""

import httpx
import json
import os
import re
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from models import Target, Vulnerability, AuthSurface
from agents.utils import log_event

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL    = os.getenv("OLLAMA_MODEL", "gemma:2b")

# Severity → base impact score
SEVERITY_IMPACT = {
    "Critical": 1.0,
    "High":     0.8,
    "Medium":   0.5,
    "Low":      0.2,
    "Info":     0.05,
}

# CWE → exploitability multiplier
CWE_EXPLOITABILITY = {
    "CWE-89":  1.0,   # SQLi
    "CWE-79":  0.85,  # XSS
    "CWE-22":  0.9,   # Path Traversal
    "CWE-284": 0.95,  # Improper Access Control
    "CWE-200": 0.7,   # Information Exposure
    "CWE-352": 0.75,  # CSRF
    "CWE-918": 0.85,  # SSRF
}


class RiskScorerAgent:

    def __init__(self, target: Target, session: AsyncSession):
        self.target  = target
        self.session = session

    async def run(self):
        await log_event(self.session, self.target.id, "RISK_SCORER",
                        "Computing custom risk scores for all vulnerabilities...", "INFO")

        # Check if target has auth surfaces (affects exposure score)
        surfaces_res = await self.session.execute(
            select(AuthSurface).where(AuthSurface.target_id == self.target.id)
        )
        has_auth_surface = len(surfaces_res.scalars().all()) > 0
        exposure_base = 0.9 if has_auth_surface else 0.6

        vulns_res = await self.session.execute(
            select(Vulnerability).where(
                Vulnerability.target_id == self.target.id,
                Vulnerability.status.in_(["confirmed", "analyzed"])
            )
        )
        vulns = vulns_res.scalars().all()

        if not vulns:
            await log_event(self.session, self.target.id, "RISK_SCORER",
                            "No confirmed vulnerabilities to score.", "INFO")
            return

        scores = []
        for vuln in vulns:
            score = await self._score_vulnerability(vuln, exposure_base)
            scores.append((vuln, score))

        # Sort by risk descending
        scores.sort(key=lambda x: x[1], reverse=True)

        # Append risk score to vuln.risk field
        for vuln, score in scores:
            risk_note = f"\n\n[RISK SCORE: {score:.2f}/1.00]"
            if vuln.risk:
                if "[RISK SCORE:" not in vuln.risk:
                    vuln.risk += risk_note
            else:
                vuln.risk = risk_note.strip()

        await self.session.commit()

        top = scores[0][1] if scores else 0
        await log_event(
            self.session, self.target.id, "RISK_SCORER",
            f"Risk scoring complete. {len(scores)} vulns scored. Highest: {top:.2f}",
            "SUCCESS"
        )
        return scores

    async def _score_vulnerability(self, vuln: Vulnerability, exposure_base: float) -> float:
        """Compute Risk = Exploitability × Impact × Exposure for one vulnerability."""

        # 1. Impact: Use CVSS score if available, otherwise fallback to severity
        if vuln.cvss_score:
            impact = vuln.cvss_score / 10.0
        else:
            impact = SEVERITY_IMPACT.get(vuln.severity, 0.5)

        # 2. Exploitability: CWE-based + validator confidence signal
        exploitability = CWE_EXPLOITABILITY.get(vuln.cwe_id or "", 0.6)
        
        # If we have a CVSS score, it already incorporates exploitability, 
        # but we still want the validator confidence boost.
        if vuln.status == "confirmed":
            exploitability = min(exploitability + 0.1, 1.0)

        # 3. Exposure: auth surface present = higher exposure
        exposure = exposure_base
        if vuln.path:
            path_lower = vuln.path.lower()
            if any(p in path_lower for p in ["/admin", "/dashboard", "/api"]):
                exposure = min(exposure + 0.1, 1.0)

        # Gemma impact refinement (async, only for High/Critical)
        if vuln.severity in ("Critical", "High") and not vuln.cvss_score:
            gemma_score = await self._gemma_impact(vuln)
            if gemma_score:
                impact = (impact + gemma_score) / 2.0

        risk = exploitability * impact * exposure
        return round(min(risk, 1.0), 4)

    async def _gemma_impact(self, vuln: Vulnerability) -> float:
        """Ask Gemma to rate the business impact of this vulnerability (0.0–1.0)."""
        prompt = f"""Rate the business impact of this vulnerability from 0.0 (no impact) to 1.0 (catastrophic).

Vulnerability: {vuln.vuln_type}
Severity: {vuln.severity}
Path: {vuln.path}
CWE: {vuln.cwe_id}
Evidence: {(vuln.evidence or '')[:300]}
Explanation: {(vuln.explanation or '')[:300]}

Respond ONLY with a JSON: {{"impact": <float 0.0-1.0>, "reason": "<one sentence>"}}"""
        try:
            async with httpx.AsyncClient(timeout=90.0) as client:
                r = await client.post(
                    f"{OLLAMA_BASE_URL}/api/generate",
                    json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False}
                )
                text = r.json().get("response", "")
                match = re.search(r'\{[^}]+\}', text, re.DOTALL)
                if match:
                    data = json.loads(match.group())
                    return float(data.get("impact", 0.5))
        except Exception:
            pass
        return 0.5


async def start_risk_scoring(target_id: int, db: AsyncSession):
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if target:
        agent = RiskScorerAgent(target, db)
        return await agent.run()
