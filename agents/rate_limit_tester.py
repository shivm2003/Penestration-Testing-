import asyncio
import time
from typing import List, Any
from core.base_agent import ShivamAgent, Finding, RiskLevel

class RateLimitTesterAgent(ShivamAgent):
    name = "rate_limit_tester"
    phase = "analysis"
    
    async def execute(self, target: Any, session: Any = None) -> List[Finding]:
        findings = []
        url = getattr(target, 'url', str(target))
        
        # Test targets (Login, API endpoints)
        test_paths = ["/api/login", "/login", "/api/v1/user", "/forgot-password"]
        
        for path in test_paths:
            full_url = f"{url.rstrip('/')}{path}"
            try:
                start_time = time.time()
                responses = []
                
                # Burst 10 requests
                for _ in range(10):
                    responses.append(self.http_request("POST" if "login" in path else "GET", full_url))
                
                results = await asyncio.gather(*responses, return_exceptions=True)
                
                # Check for 429 Too Many Requests
                throttled = any(getattr(r, 'status_code', 0) == 429 for r in results)
                
                if not throttled:
                    findings.append(Finding(
                        id=f"no_rate_limit_{hash(full_url) % 10000}",
                        agent_name=self.name,
                        title="Missing Rate Limiting on Sensitive Endpoint",
                        description=f"The endpoint {path} does not implement rate limiting, allowing for brute-force or DoS attacks.",
                        risk_level=RiskLevel.MEDIUM,
                        evidence=f"Sent 10 rapid requests to {full_url}. All returned status: {[getattr(r, 'status_code', 'ERR') for r in results]}",
                        remediation="Implement rate limiting (e.g., using Redis or Nginx limit_req) on sensitive endpoints.",
                        cwe_id="CWE-770",
                        cvss_score=5.3,
                        target_url=full_url
                    ))
            except:
                continue
                
        return findings
