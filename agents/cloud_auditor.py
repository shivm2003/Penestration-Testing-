import re
from typing import List, Any
from core.base_agent import ShivamAgent, Finding, RiskLevel

class CloudAuditorAgent(ShivamAgent):
    name = "cloud_auditor"
    phase = "analysis"
    
    CLOUD_PATTERNS = {
        "aws_s3_url": r"https?://[\w\-]+\.s3[\w\-]*\.amazonaws\.com[/\w\-\.]*",
        "aws_access_key": r"AKIA[0-9A-Z]{16}",
        "gcp_bucket": r"https?://storage\.googleapis\.com/[\w\-]+[/\w\-\.]*",
        "azure_blob": r"https?://[\w\-]+\.blob\.core\.windows\.net[/\w\-\.]*",
    }
    
    METADATA_ENDPOINTS = [
        "http://169.254.169.254/latest/meta-data/",      # AWS
        "http://metadata.google.internal/computeMetadata/v1/",  # GCP
    ]
    
    async def execute(self, target: Any, session: Any = None) -> List[Finding]:
        findings = []
        url = getattr(target, 'url', str(target))
        self.log(f"Starting Cloud Audit on {url}")
        
        # 1. Passive Scan
        try:
            resp = await self.http_request("GET", url)
            text = resp.text
            for leak_type, pattern in self.CLOUD_PATTERNS.items():
                matches = re.findall(pattern, text)
                for match in matches:
                    risk = RiskLevel.CRITICAL if "key" in leak_type else RiskLevel.HIGH
                    findings.append(Finding(
                        id=f"cloud_leak_{leak_type}_{hash(match) % 10000}",
                        agent_name=self.name,
                        title=f"Cloud Resource/Credential Leaked: {leak_type}",
                        description=f"Found {leak_type} in application source.",
                        risk_level=risk,
                        evidence=f"Match: {match}\nFound in: {url}",
                        remediation="Remove hardcoded credentials/URLs from the client-side code.",
                        cwe_id="CWE-798" if "key" in leak_type else "CWE-200",
                        cvss_score=9.0 if "key" in leak_type else 7.5,
                        target_url=url
                    ))
        except:
            pass
            
        # 2. SSRF to Metadata Test
        test_params = ["url", "uri", "path", "file", "api"]
        for meta_url in self.METADATA_ENDPOINTS:
            for param in test_params:
                test_url = f"{url.rstrip('/')}?{param}={meta_url}"
                try:
                    resp = await self.http_request("GET", test_url, timeout=5)
                    if any(ind in resp.text for ind in ["instance-id", "ami-id", "computeMetadata"]):
                        findings.append(Finding(
                            id=f"ssrf_metadata_{hash(meta_url)}",
                            agent_name=self.name,
                            title="SSRF to Cloud Metadata Endpoint",
                            description="The application allows SSRF to internal cloud metadata endpoints, risking full instance takeover.",
                            risk_level=RiskLevel.CRITICAL,
                            evidence=f"Payload: ?{param}={meta_url}\nResponse snippet: {resp.text[:200]}",
                            remediation="Whitelist allowed redirect/fetch domains. Block access to 169.254.169.254.",
                            cwe_id="CWE-918",
                            cvss_score=9.8,
                            target_url=url
                        ))
                        break
                except:
                    continue
                    
        return findings
