import httpx
import re
from typing import List, Any
from core.base_agent import ShivamAgent, Finding, RiskLevel

class WAFAgent(ShivamAgent):
    name = "waf_fingerprinter"
    phase = "recon"
    
    WAF_SIGNATURES = {
        "Cloudflare": ["__cfduid", "cf-ray", "cloudflare-nginx", "cloudflare"],
        "Akamai": ["akamai-ghost", "akamai", "ak_bmsc"],
        "ModSecurity": ["mod_security", "NOYB"],
        "AWS WAF": ["x-amz-cf-id", "awswaf"],
        "Sucuri": ["x-sucuri-id", "sucuri"],
        "FortiWeb": ["fortiwafsid"],
        "Imperva": ["incap_ses", "visid_incap", "imperva"]
    }

    async def execute(self, target: Any, session: Any = None) -> List[Finding]:
        findings = []
        url = getattr(target, 'url', str(target))
        
        try:
            # 1. Passive Fingerprinting (Headers)
            resp = await self.http_request("GET", url)
            detected_waf = None
            
            # Check Headers
            headers_str = str(resp.headers).lower()
            for waf, sigs in self.WAF_SIGNATURES.items():
                if any(sig.lower() in headers_str for sig in sigs):
                    detected_waf = waf
                    break
                    
            # 2. Active Probing (Triggering WAF)
            if not detected_waf:
                # Malicious-looking request
                probe_url = f"{url.rstrip('/')}/?id=' OR 1=1 --"
                resp_probe = await self.http_request("GET", probe_url)
                
                if resp_probe.status_code in [403, 406, 501]:
                    # Likely blocked by WAF
                    detected_waf = "Generic WAF (Behavioral Match)"
                    
            if detected_waf:
                findings.append(Finding(
                    id=f"waf_detected_{hash(url) % 10000}",
                    agent_name=self.name,
                    title=f"WAF Detected: {detected_waf}",
                    description=f"Identified {detected_waf} protecting the target. Scans must be throttled or mutated to bypass security rules.",
                    risk_level=RiskLevel.LOW, # WAF is a defense, but detection is high-priority for attackers
                    evidence=f"Detection Method: {'Header Signature' if '__cf' in headers_str else 'Behavioral Block (403/406)'}\nWAF Type: {detected_waf}",
                    remediation="Use stealthy scanning techniques or payload encoding to bypass specific WAF rules.",
                    cwe_id="CWE-693", # Protection Mechanism Failure (if bypassable)
                    cvss_score=0.0,
                    target_url=url
                ))
        except:
            pass
            
        return findings
