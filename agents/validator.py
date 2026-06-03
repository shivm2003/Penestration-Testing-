import httpx
from bs4 import BeautifulSoup
import json
from urllib.parse import urlparse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from models import Target, Vulnerability
from core.session_manager import AuthSession
import asyncio

class ValidatorAgent:
    def __init__(self, target: Target, session: AsyncSession):
        self.target = target
        self.session = session
        self.base_url = target.url
        self.auth_session = AuthSession(self.base_url, self.session, self.target.id)

    async def run(self):
        try:
            # Fetch all pending vulnerabilities
            result = await self.session.execute(
                select(Vulnerability).where(
                    Vulnerability.target_id == self.target.id,
                    Vulnerability.status == "pending"
                )
            )
            vulnerabilities = result.scalars().all()

            for vuln in vulnerabilities:
                from main import STOPPED_TARGETS
                if self.target.id in STOPPED_TARGETS:
                    print(f"[VALIDATOR] Stop command received. Halting validation.")
                    break

                if "XSS" in vuln.vuln_type:
                    await self.validate_xss(vuln)
                elif "SQL" in vuln.vuln_type:
                    await self.validate_sqli(vuln)
                else:
                    # Default to confirmed for simpler checks (like headers)
                    vuln.status = "confirmed"
                
                await self.session.commit()
                
        except Exception as e:
            print(f"Validator failed: {e}")
        finally:
            await self.auth_session.close()

    async def validate_xss(self, vuln: Vulnerability):
        try:
            evidence = json.loads(vuln.evidence)
            url = evidence.get("url")
            payload = evidence.get("payload")

            if not url or not payload:
                vuln.status = "rejected"
                return

            # Active Re-testing
            response = await self.auth_session.send_request("GET", url)
            
            # Use BeautifulSoup to parse DOM
            soup = BeautifulSoup(response.text, 'html.parser')
            
            is_exploitable = False
            
            # Simple DOM check: Did the payload escape safely?
            # If payload contains <script>, check if there's an actual script tag with our payload
            if "<script>" in payload:
                # Find if any script tag contains the inner text we expect
                for script in soup.find_all('script'):
                    if script.string and "alert(1)" in script.string:
                        is_exploitable = True
                        break
                # Or check if it's rendered unescaped in the raw text
                if payload in response.text:
                    is_exploitable = True
            elif "onerror" in payload:
                for img in soup.find_all('img'):
                    if img.get("onerror"):
                        is_exploitable = True
                        break

            if is_exploitable:
                vuln.status = "confirmed"
            else:
                vuln.status = "rejected"
        except Exception as e:
            print(f"XSS Validation failed: {e}")
            vuln.status = "rejected"

    async def validate_sqli(self, vuln: Vulnerability):
        try:
            evidence = json.loads(vuln.evidence)
            url = evidence.get("url")
            param = evidence.get("param")
            
            if not url or not param:
                vuln.status = "rejected"
                return

            if evidence.get("type") == "error_based":
                # Actively trigger error again
                response = await self.auth_session.send_request("GET", url)
                resp_lower = response.text.lower()
                if "syntax error" in resp_lower or "mysql" in resp_lower or "postgresql" in resp_lower:
                    vuln.status = "confirmed"
                else:
                    vuln.status = "rejected"
            else:
                # Boolean logic check (simulate)
                # Parse URL, replace param with True condition and False condition
                # Here we simplify the logic to just assume if it was boolean, we would check response length differences
                parsed = urlparse(url)
                true_url = url.replace(evidence.get("payload"), f"1=1")
                false_url = url.replace(evidence.get("payload"), f"1=2")
                
                try:
                    r_true = await self.auth_session.send_request("GET", true_url)
                    r_false = await self.auth_session.send_request("GET", false_url)
                    if len(r_true.text) != len(r_false.text):
                        vuln.status = "confirmed"
                    else:
                        vuln.status = "rejected"
                except Exception:
                    vuln.status = "rejected"
        except Exception as e:
            print(f"SQLi Validation failed: {e}")
            vuln.status = "rejected"


async def start_validate(target_id: int, db: AsyncSession):
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if target:
        agent = ValidatorAgent(target, db)
        await agent.run()
