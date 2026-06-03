import httpx
import json
from sqlalchemy.ext.asyncio import AsyncSession
from models import Target, Vulnerability, ReconData
from urllib.parse import urljoin

class ConfigAgent:
    def __init__(self, target: Target, session: AsyncSession):
        self.target = target
        self.session = session
        self.client = httpx.AsyncClient(timeout=5.0, verify=False, follow_redirects=False)

    async def run(self):
        try:
            print(f"Starting Nikto-style Config Audit for {self.target.url}...")
            
            # 1. Check for common sensitive paths
            await self.audit_sensitive_paths()
            
            # 2. Audit Server Headers for version disclosure
            await self.audit_server_headers()

        except Exception as e:
            print(f"Config Agent failed: {e}")
        finally:
            await self.client.aclose()

    async def audit_sensitive_paths(self):
        # Nikto-style common vulnerable paths
        nikto_paths = [
            {"path": "/phpinfo.php", "note": "PHP Info leakage"},
            {"path": "/.git/config", "note": "Git Repository found"},
            {"path": "/.env", "note": "Environment file exposure"},
            {"path": "/config.php.bak", "note": "Config backup found"},
            {"path": "/server-status", "note": "Apache server-status enabled"},
            {"path": "/test.cgi", "note": "Old CGI test script"},
            {"path": "/robots.txt", "note": "Robots.txt check"}
        ]
        
        for item in nikto_paths:
            url = urljoin(self.target.url, item['path'])
            try:
                resp = await self.client.get(url)
                if resp.status_code == 200:
                    await self._save_vuln(
                        "Information Disclosure", 
                        "Medium", 
                        f"Found sensitive path: {url} ({item['note']})",
                        cwe_id="CWE-548"
                    )
            except:
                pass

    async def audit_server_headers(self):
        try:
            resp = await self.client.get(self.target.url)
            server = resp.headers.get("Server")
            x_powered = resp.headers.get("X-Powered-By")
            
            findings = []
            if server: findings.append(f"Server: {server}")
            if x_powered: findings.append(f"X-Powered-By: {x_powered}")
            
            if findings:
                await self._save_vuln(
                    "Service Version Disclosure", 
                    "Low", 
                    f"Sensitive headers found: {', '.join(findings)}",
                    cwe_id="CWE-200"
                )
        except:
            pass

    async def _save_vuln(self, vuln_type, severity, evidence, cwe_id=None):
        vuln = Vulnerability(
            target_id=self.target.id,
            vuln_type=vuln_type,
            cwe_id=cwe_id,
            severity=severity,
            evidence=evidence,
            status="pending"
        )
        self.session.add(vuln)
        await self.session.commit()

async def start_config_audit(target_id: int, db: AsyncSession):
    from sqlalchemy import select
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if target:
        agent = ConfigAgent(target, db)
        await agent.run()
