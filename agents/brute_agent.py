import asyncio
import httpx
import json
import re
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from models import Target, ReconData, BruteFinding
from urllib.parse import urljoin

class BruteForceAgent:
    def __init__(self, target: Target, session: AsyncSession):
        self.target = target
        self.session = session
        self.client = httpx.AsyncClient(timeout=5.0, verify=False)
        self.usernames = ["admin", "root", "user", "guest"]
        self.passwords = ["123456", "password", "admin123", "password123"]

    async def run(self):
        try:
            print(f"Starting Brute Force & OTP Discovery for {self.target.url}...")
            
            # Fetch all forms found during recon
            result = await self.session.execute(
                select(ReconData).where(
                    ReconData.target_id == self.target.id,
                    ReconData.data_type == "form"
                )
            )
            forms = result.scalars().all()
            
            for form in forms:
                details = json.loads(form.details)
                inputs = details.get("inputs", [])
                
                # Check if it's a login form (has a password field)
                has_password = any(i.get("type") == "password" or "pass" in i.get("name", "").lower() for i in inputs)
                # Check if it's an OTP form
                has_otp = any("otp" in i.get("name", "").lower() or "code" in i.get("name", "").lower() for i in inputs)
                
                if has_password:
                    await self.perform_brute_force(form, details)
                
                if has_otp:
                    await self.check_otp_disclosure(form, details)
                    
        except Exception as e:
            print(f"Brute Force Agent failed: {e}")
        finally:
            await self.client.aclose()

    async def perform_brute_force(self, form_data: ReconData, details: dict):
        url = details.get("action")
        inputs = details.get("inputs", [])
        
        user_field = next((i['name'] for i in inputs if "user" in i['name'].lower() or "email" in i['name'].lower()), None)
        pass_field = next((i['name'] for i in inputs if "pass" in i['name'].lower()), None)
        
        if not user_field or not pass_field:
            return

        print(f"[BRUTE FORCE] Attempting Cluster Bomb on {url}")
        attempts = 0
        success_creds = None
        
        # Simple Cluster Bomb: Every user x Every pass
        for user in self.usernames:
            for password in self.passwords:
                attempts += 1
                payload = {user_field: user, pass_field: password}
                try:
                    resp = await self.client.post(url, data=payload)
                    # Heuristic for success: Redirect or specific keywords
                    if resp.status_code in [301, 302] or "dashboard" in resp.text.lower() or "welcome" in resp.text.lower():
                        success_creds = f"{user}:{password}"
                        print(f"[SUCCESS] Credentials Found: {success_creds}")
                        break
                except:
                    pass
            if success_creds: break
            
        # Save result
        finding = BruteFinding(
            target_id=self.target.id,
            url=url,
            method="POST",
            payload_summary=f"Cluster Bomb: {attempts} combinations tested",
            success_status=f"Success: {success_creds}" if success_creds else "No success",
            severity="Critical" if success_creds else "Info"
        )
        self.session.add(finding)
        await self.session.commit()

    async def check_otp_disclosure(self, form_data: ReconData, details: dict):
        url = details.get("action")
        print(f"[OTP CHECK] Testing for OTP Disclosure on {url}")
        
        try:
            # 1. Trigger the OTP (assuming a simple GET or POST to the form action triggers it)
            resp = await self.client.get(url)
            
            # 2. Heuristic: Look for 4-6 digit codes in the response body (Common vulnerability)
            otp_match = re.search(r'\b\d{4,6}\b', resp.text)
            
            if otp_match:
                leaked_otp = otp_match.group(0)
                print(f"[VULNERABILITY] OTP Leaked in Response: {leaked_otp}")
                
                finding = BruteFinding(
                    target_id=self.target.id,
                    url=url,
                    method="GET",
                    payload_summary="Passive OTP Disclosure Check",
                    otp_leak=f"Leaked OTP: {leaked_otp}",
                    severity="High"
                )
                self.session.add(finding)
                await self.session.commit()
        except:
            pass

async def start_brute_force(target_id: int, db: AsyncSession):
    from sqlalchemy import select
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if target:
        agent = BruteForceAgent(target, db)
        await agent.run()
