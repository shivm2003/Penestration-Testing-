"""
Attack Graph Engine (Upgraded Chain Analyzer)
=============================================
Instead of simple rules, this agent treats vulnerabilities as nodes in a graph.
It uses Gemma to identify "leads to" relationships (edges) and builds 
multi-step attack narratives.
"""

import json
import os
import httpx
import re
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from models import Target, Vulnerability, ChainFinding
from agents.utils import log_event

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL    = os.getenv("OLLAMA_MODEL", "gemma:2b")

class ChainAnalyzerAgent:
    def __init__(self, target: Target, session: AsyncSession):
        self.target = target
        self.session = session

    async def run(self):
        try:
            await log_event(self.session, self.target.id, "ATTACK_GRAPH", "Building Attack Graph from confirmed findings...", "INFO")

            # 1. Fetch all confirmed vulns
            result = await self.session.execute(
                select(Vulnerability).where(
                    Vulnerability.target_id == self.target.id,
                    Vulnerability.status == "confirmed"
                )
            )
            vulns = result.scalars().all()

            if len(vulns) < 2:
                await log_event(self.session, self.target.id, "ATTACK_GRAPH", "Insufficient findings to build a graph.", "INFO")
                return

            # 2. Use Gemma to find edges (relationships) between findings
            chains = await self._find_chains_with_ai(vulns)

            # 3. Store chains in DB
            chains_created = 0
            for chain in chains:
                # Check if already exists
                existing = await self.session.execute(
                    select(ChainFinding).where(
                        ChainFinding.target_id == self.target.id,
                        ChainFinding.chain_title == chain["title"]
                    )
                )
                if existing.scalar_one_or_none():
                    continue

                new_chain = ChainFinding(
                    target_id=self.target.id,
                    chain_title=chain["title"],
                    vuln_ids_involved=",".join(map(str, chain["vuln_ids"])),
                    attack_narrative=chain["narrative"],
                    severity=chain["severity"],
                    confidence=chain["confidence"]
                )
                self.session.add(new_chain)
                chains_created += 1

            await self.session.commit()
            await log_event(self.session, self.target.id, "ATTACK_GRAPH", f"Attack Graph complete. Identified {chains_created} multi-step chains.", "SUCCESS")

        except Exception as e:
            await log_event(self.session, self.target.id, "ATTACK_GRAPH", f"Graph Analysis failed: {e}", "CRITICAL")

    async def _find_chains_with_ai(self, vulns):
        """Ask Gemma to correlate findings into attack paths."""
        vuln_list = []
        for v in vulns:
            vuln_list.append({
                "id": v.id,
                "type": v.vuln_type,
                "path": v.path,
                "severity": v.severity,
                "summary": (v.explanation or "")[:200]
            })

        prompt = f"""You are a Red Team Strategist. 
I have a list of vulnerabilities found on a target. 
Build a logical "Attack Graph" where one vulnerability leads to another or enhances the impact of another.

Findings:
{json.dumps(vuln_list, indent=2)}

Think about:
- How Information Disclosure (headers/files) helps craft payloads for SQLi/XSS.
- How SQLi leads to data breach or lateral movement.
- How XSS leads to session hijacking.
- How weak auth + internal IP disclosure = lateral movement.

Respond ONLY as a JSON array of objects:
[
  {{
    "title": "Chain Name",
    "vuln_ids": [id1, id2, ...],
    "severity": "Critical/High",
    "confidence": 0-100,
    "narrative": "Detailed step-by-step explanation of how these are chained."
  }}
]"""

        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                resp = await client.post(
                    f"{OLLAMA_BASE_URL}/api/generate",
                    json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False}
                )
                text = resp.json().get("response", "")
                # Extract JSON array
                match = re.search(r'\[.*\]', text, re.DOTALL)
                if match:
                    return json.loads(match.group())
        except Exception as e:
            print(f"AI Chain Analysis failed: {e}")
        return []

async def start_chain_analysis(target_id: int, db: AsyncSession):
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if target:
        agent = ChainAnalyzerAgent(target, db)
        await agent.run()
