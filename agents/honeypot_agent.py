import time
from typing import List, Any
from core.base_agent import ShivamAgent, Finding, RiskLevel

class HoneypotAgent(ShivamAgent):
    name = "honeypot_detector"
    phase = "recon"
    
    async def execute(self, target: Any, session: Any = None) -> List[Finding]:
        findings = []
        url = getattr(target, 'url', str(target))
        
        try:
            # 1. Test "Accept Everything" Login
            login_url = f"{url.rstrip('/')}/login"
            # Random credentials
            payload = {"username": "admin_shivam_fake_user", "password": "random_password_123456"}
            
            start_time = time.time()
            resp = await self.http_request("POST", login_url, json=payload)
            latency = time.time() - start_time
            
            is_honeypot = False
            reason = ""
            
            # Heuristic 1: Success on random credentials
            if resp.status_code == 200 and ("success" in resp.text.lower() or "welcome" in resp.text.lower()):
                is_honeypot = True
                reason = "Target accepted random/fake credentials (Login Honeypot)."
                
            # Heuristic 2: Artificial Latency
            if latency > 5.0:
                is_honeypot = True
                reason = "Unusual artificial latency detected (Tarpit Honeypot)."

            # Heuristic 3: Common Honeypot Headers
            if "x-cowrie-version" in resp.headers or "x-kippo-id" in resp.headers:
                is_honeypot = True
                reason = "Detected known honeypot headers (Cowrie/Kippo)."

            if is_honeypot:
                findings.append(Finding(
                    id=f"honeypot_detected_{hash(url) % 10000}",
                    agent_name=self.name,
                    title="Potential Honeypot Detected",
                    description=f"Warning: The target exhibits behavioral patterns typical of a honeypot ({reason}). This may be a deception system designed to log attacker activity.",
                    risk_level=RiskLevel.HIGH, # High risk for the ATTACKER
                    evidence=f"Detection Reason: {reason}\nLatency: {latency:.2f}s",
                    remediation="Cease scanning immediately to avoid counter-intelligence tracking. Use highly anonymized proxies if proceeding.",
                    cwe_id="N/A",
                    cvss_score=0.0,
                    target_url=url
                ))
        except:
            pass
            
        return findings
