"""
Phase 3 — Leak Analyzer Agent
==============================
Dedicated response exposure analyzer. Detects:
- OTP codes in responses
- JWT tokens
- Session IDs / API keys
- Stack traces / debug info
- Internal API paths
- PII (emails, phone numbers)

Uses: fast regex rules + entropy detection + Gemma semantic check.
"""

import re
import math
import json
import os
import httpx
from deepdiff import DeepDiff
from agents.utils import log_event
from typing import List, Dict, Optional

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL    = os.getenv("OLLAMA_MODEL", "gemma:2b")

# ─────────────────────────────────────────────────────────────────────────────
# Compiled regex patterns
# ─────────────────────────────────────────────────────────────────────────────
PATTERNS = {
    "otp_code":     re.compile(r'\b\d{4,8}\b'),
    "jwt_token":    re.compile(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
    "session_id":   re.compile(r'(?i)(session[_-]?id|sessid|phpsessid|jsessionid)["\s:=]+([A-Za-z0-9_\-]{16,})'),
    "api_key":      re.compile(r'(?i)(api[_-]?key|apikey|access[_-]?token|secret[_-]?key)["\s:=]+([A-Za-z0-9_\-]{16,64})'),
    "email":        re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b'),
    "phone":        re.compile(r'\b(?:\+?\d[\d\s\-()]{7,14}\d)\b'),
    "stack_trace":  re.compile(r'(?i)(traceback|stack trace|at line \d|exception in thread|fatal error|undefined (variable|index)|syntax error)'),
    "internal_ip":  re.compile(r'\b(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b'),
    "debug_info":   re.compile(r'(?i)(debug|verbose|var_dump|console\.log|print_r|die\(|exit\()'),
    "aws_key":      re.compile(r'(?:AKIA|AIPA|ASIA|AGPA|AROA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'),
    "private_key":  re.compile(r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    "bearer_token": re.compile(r'(?i)bearer\s+([A-Za-z0-9\-._~+/]+=*)'),
}

# High-entropy string detection threshold
ENTROPY_THRESHOLD = 4.2
ENTROPY_MIN_LEN   = 20


class LeakAnalyzer:
    """
    Stateless helper — call analyze() directly.
    Also used by LoginTesterAgent, can be used standalone.
    """

    def analyze(self, response_text: str, headers: dict = None) -> list:
        """Run all detection rules against response."""
        results = []
        
        # 1. Rule-based Regex Matching
        for rule_name, pattern in PATTERNS.items():
            matches = pattern.findall(response_text)
            for m in matches:
                value = m if isinstance(m, str) else (m[1] if len(m) > 1 else m[0])
                results.append({
                    "type": rule_name,
                    "value": value[:120],
                    "severity": self._severity(rule_name)
                })

        # 2. Shannon Entropy for High-Entropy Secrets
        results.extend(self._detect_high_entropy(response_text))

        # Deduplicate
        seen = set()
        unique = []
        for r in results:
            key = (r["type"], r["value"][:30])
            if key not in seen:
                seen.add(key)
                unique.append(r)
        return unique

    def semantic_diff(self, baseline: str, current: str) -> dict:
        """Perform structural and semantic diffing."""
        diff_report = {}
        try:
            b_json = json.loads(baseline)
            c_json = json.loads(current)
            ddiff = DeepDiff(b_json, c_json, ignore_order=True)
            if ddiff:
                diff_report["structural_changes"] = ddiff.to_dict()
        except Exception:
            pass
        return diff_report

    def _detect_high_entropy(self, text: str) -> list:
        results = []
        for token in re.findall(r'[A-Za-z0-9+/=_\-]{20,}', text):
            e = self._shannon_entropy(token)
            if e > ENTROPY_THRESHOLD:
                results.append({
                    "type": "high_entropy_string",
                    "value": token[:80],
                    "severity": "medium",
                    "entropy": round(e, 2)
                })
        return results

    def _shannon_entropy(self, data: str) -> float:
        if not data: return 0.0
        freq = {}
        for c in data:
            freq[c] = freq.get(c, 0) + 1
        length = len(data)
        return -sum((f / length) * math.log2(f / length) for f in freq.values())

    def _severity(self, leak_type: str) -> str:
        critical = {"jwt_token", "api_key", "aws_key", "private_key", "bearer_token"}
        high     = {"session_id", "otp_code", "stack_trace"}
        medium   = {"email", "internal_ip", "debug_info", "phone"}
        if leak_type in critical:
            return "critical"
        if leak_type in high:
            return "high"
        if leak_type in medium:
            return "medium"
        return "low"

    async def gemma_check(self, body: str, headers: Dict) -> Optional[str]:
        """
        Ask Gemma: does this response expose sensitive data?
        Returns a plain-text analysis or None if unavailable.
        """
        prompt = f"""You are a security analyst reviewing an HTTP response for data leaks.

Response headers:
{json.dumps(dict(headers), indent=2)[:500]}

Response body (first 800 chars):
{body[:800]}

Does this response expose any sensitive data (tokens, OTPs, credentials, debug info, PII)?
Answer concisely. If yes, list what was found and its risk level."""

        try:
            async with httpx.AsyncClient(timeout=90.0) as client:
                resp = await client.post(
                    f"{OLLAMA_BASE_URL}/api/generate",
                    json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False}
                )
                return resp.json().get("response", "").strip()
        except Exception:
            return None


class LeakAnalyzerAgent:
    """
    Full agent wrapper for use inside the orchestrator.
    Scans all AuthTestResults for a target and enhances with Gemma analysis.
    """

    def __init__(self, target, session):
        self.target  = target
        self.session = session
        self.analyzer = LeakAnalyzer()

    async def run(self):
        from agents.utils import log_event
        from models import AuthTestResult
        from sqlalchemy.future import select

        await log_event(self.session, self.target.id, "LEAK_ANALYZER",
                        "Phase 3: Starting Response Exposure Analysis", "INFO")

        results = await self.session.execute(
            select(AuthTestResult).where(AuthTestResult.target_id == self.target.id)
        )
        records = results.scalars().all()

        enriched = 0
        for record in records:
            if not record.raw_response_snippet:
                continue

            leaks = self.analyzer.analyze(record.raw_response_snippet)
            if leaks:
                gemma_note = await self.analyzer.gemma_check(
                    record.raw_response_snippet, {}
                )
                existing = json.loads(record.sensitive_data_detected or "[]")
                merged = existing + leaks
                record.sensitive_data_detected = json.dumps(merged)
                if gemma_note:
                    record.response_diff = (record.response_diff or "") + f"\n\n[Gemma Analysis]\n{gemma_note}"
                enriched += 1

        await self.session.commit()
        await log_event(self.session, self.target.id, "LEAK_ANALYZER",
                        f"Leak analysis complete. Enriched {enriched} results.", "SUCCESS")
