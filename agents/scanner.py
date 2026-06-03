import httpx
from urllib.parse import urljoin
import json
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from models import Target, ReconData, Vulnerability, CWEData
from core.session_manager import AuthSession
from agents.payload_engine import PayloadEngine
import asyncio

class ScannerAgent:
    def __init__(self, target: Target, session: AsyncSession):
        self.target = target
        self.session = session
        self.base_url = target.url
        self.auth_session = AuthSession(self.base_url, self.session, self.target.id)
        self.payload_engine = PayloadEngine(self.session)

    async def run(self):
        try:
            self.target.status = "scanning"
            await self.session.commit()

            # Get all recon data
            result = await self.session.execute(
                select(ReconData).where(ReconData.target_id == self.target.id)
            )
            recon_items = result.scalars().all()

            for item in recon_items:
                from main import STOPPED_TARGETS
                if self.target.id in STOPPED_TARGETS:
                    print(f"[SCANNER] Stop command received. Halting scanning.")
                    break

                if item.data_type == "endpoint":
                    await self.test_headers(item)
                    await self.test_directory_exposure(item)
                elif item.data_type == "parameter":
                    await self.test_xss(item)
                    await self.test_sqli(item)
                    await self.test_open_redirect(item)
                    # Zero-Day Behavioral Detection
                    await self.test_blind_sqli_boolean(item)
                    await self.test_blind_sqli_time(item)
                elif item.data_type == "form":
                    # Use AI to fill forms
                    await self.ai_test_form(item)
                elif item.data_type == "port":
                    # Correlate with CWE Intelligence
                    await self.correlate_cwe(item)

            self.target.status = "scanned"
            await self.session.commit()
        except Exception as e:
            print(f"Scanner failed: {e}")
            self.target.status = "failed"
            await self.session.commit()
        finally:
            await self.auth_session.close()

    async def _save_vuln(self, recon_data_id: int, vuln_type: str, severity: str, evidence: str, cwe_id: str = None, cvss_score: float = None):
        # 1. Normalized deduplication check
        norm_evidence = (evidence or '').strip()
        evidence_fingerprint = norm_evidence[:200]
        
        result = await self.session.execute(
            select(Vulnerability).where(
                Vulnerability.target_id == self.target.id,
                Vulnerability.vuln_type == vuln_type
            )
        )
        existing_vulns = result.scalars().all()
        
        for v in existing_vulns:
            if (v.evidence or '').strip().startswith(evidence_fingerprint):
                print(f"[DEDUPE] Skipping duplicate vulnerability: {vuln_type} (evidence match)")
                return
        
        # 2. Also skip if same recon endpoint already has this vuln type
        if any(v.recon_data_id == recon_data_id for v in existing_vulns):
             print(f"[DEDUPE] Skipping duplicate vulnerability: {vuln_type} on endpoint {recon_data_id}")
             return

        vuln = Vulnerability(
            target_id=self.target.id,
            recon_data_id=recon_data_id,
            vuln_type=vuln_type,
            cwe_id=cwe_id,
            severity=severity,
            cvss_score=cvss_score,
            evidence=evidence
        )
        self.session.add(vuln)
        await self.session.commit()
        print(f"[VULN FOUND] {vuln_type} on item {recon_data_id}")

    async def correlate_cwe(self, item: ReconData):
        """Correlate detected service on a port with known CWE weaknesses."""
        try:
            details = json.loads(item.details)
            service = details.get("service", "").lower()
            if not service or service == "unknown":
                return

            # Heuristic mapping for common services to CWEs
            mapping = {
                "http": "CWE-693", # Missing Security Headers / Protection
                "ftp": "CWE-287",  # Improper Authentication
                "ssh": "CWE-287",
                "telnet": "CWE-319", # Cleartext Transmission
                "mysql": "CWE-89",   # SQL Injection
                "postgres": "CWE-89",
                "mongodb": "CWE-943", # NoSQL Injection
                "redis": "CWE-284",  # Improper Access Control
                "smb": "CWE-287"
            }

            cwe_id = mapping.get(service)
            if cwe_id:
                # Fetch CWE details from DB
                res = await self.session.execute(select(CWEData).where(CWEData.cwe_id == cwe_id))
                cwe = res.scalar_one_or_none()
                
                evidence = f"Service Correlation: Running '{service}' which is commonly associated with {cwe_id}."
                if cwe:
                    evidence += f"\nDescription: {cwe.name}"

                await self._save_vuln(
                    item.id,
                    f"CWE-Associated Service ({cwe_id})",
                    "Medium",
                    evidence,
                    cwe_id=cwe_id
                )
        except Exception as e:
            print(f"CWE Correlation failed: {e}")

    async def passive_scan(self, item: ReconData, response_text: str):
        import re
        patterns = {
            "Generic Secret/Key": r'(?:key|api|token|secret|auth)[_-]?[a-z0-9]{16,}',
            "AWS Access Key": r'AKIA[0-9A-Z]{16}',
            "Email Leakage": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            "Internal Path": r'/[a-zA-Z0-9/._-]*/[a-zA-Z0-9._-]+\.(?:php|py|js|json|conf|bak)'
        }
        
        for name, pattern in patterns.items():
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            if matches:
                unique_matches = list(set(matches))
                await self._save_vuln(item.id, "Passive Information Leakage", "Medium", f"Possible {name} found: {', '.join(unique_matches[:2])}")

    async def test_headers(self, item: ReconData):
        details = json.loads(item.details)
        url = details.get("url")
        if not url: return

        try:
            response = await self.client.get(url)
            await self.passive_scan(item, response.text) # Passive Scan
            missing = []
            if "Content-Security-Policy" not in response.headers:
                missing.append("Content-Security-Policy")
            if "X-Frame-Options" not in response.headers:
                missing.append("X-Frame-Options")
            
            if missing:
                await self._save_vuln(
                    item.id, 
                    "Missing Security Headers", 
                    "Low", 
                    f"Missing: {', '.join(missing)}",
                    cwe_id="CWE-693"
                )
        except Exception:
            pass

    async def test_xss(self, item: ReconData):
        details = json.loads(item.details)
        param_name = details.get("param")
        if not param_name: return

        payloads = await self.payload_engine.get_best("xss", limit=10)
        if not payloads:
            payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]

        for payload in payloads:
            test_url = urljoin(self.base_url, f"{item.path}?{param_name}={payload}")
            try:
                response = await self.auth_session.send_request("GET", test_url)
                if payload in response.text:
                    evidence_data = json.dumps({"url": test_url, "payload": payload, "param": param_name})
                    await self._save_vuln(item.id, "Cross-Site Scripting (XSS)", "High", evidence_data, cwe_id="CWE-79")
                    break
            except Exception:
                pass

    async def test_sqli(self, item: ReconData):
        details = json.loads(item.details)
        param_name = details.get("param")
        if not param_name: return

        payloads = await self.payload_engine.get_best("sqli", limit=10)
        if not payloads:
             payloads = ["' OR 1=1--", "1' UNION SELECT NULL--"]

        for payload in payloads:
            test_url = urljoin(self.base_url, f"{item.path}?{param_name}={payload}")
            try:
                response = await self.auth_session.send_request("GET", test_url)
                resp_lower = response.text.lower()
                if any(k in resp_lower for k in ["syntax error", "mysql", "postgresql", "sqlite"]):
                    evidence_data = json.dumps({"url": test_url, "payload": payload, "param": param_name, "type": "error_based"})
                    await self._save_vuln(item.id, "SQL Injection", "Critical", evidence_data, cwe_id="CWE-89")
                    break
            except Exception:
                pass

    async def test_open_redirect(self, item: ReconData):
        details = json.loads(item.details)
        param_name = details.get("param")
        if param_name not in ["url", "redirect", "next", "returnTo", "path"]:
            return

        payload = "http://evil.com"
        test_url = urljoin(self.base_url, f"{item.path}?{param_name}={payload}")

        try:
            response = await self.client.get(test_url)
            if response.status_code in [301, 302] and response.headers.get("Location") == payload:
                await self._save_vuln(item.id, "Open Redirect", "Medium", f"Redirected to evil.com from {test_url}", cwe_id="CWE-601")
        except Exception:
            pass

    async def test_directory_exposure(self, item: ReconData):
        # We only test from the base url once per scan technically, but let's just do a few common paths
        if item.path != "/": return # Only do this when processing root

        common_paths = ["/admin", "/backup", "/.env", "/config.json", "/.git/config"]
        for path in common_paths:
            test_url = urljoin(self.base_url, path)
            try:
                response = await self.client.get(test_url)
                if response.status_code == 200 and "html" not in response.headers.get("content-type", ""):
                    # Very naive check, but good enough for a basic agent
                    await self._save_vuln(item.id, "Directory/File Exposure", "High", f"Found accessible path: {test_url}")
            except Exception:
                pass
                
    async def test_blind_sqli_boolean(self, item: ReconData):
        """Boolean-based blind SQLi: Compare true/false responses."""
        details = json.loads(item.details)
        param_name = details.get("param")
        if not param_name: return

        true_payload = "1' AND '1'='1"
        false_payload = "1' AND '1'='2"

        true_url = urljoin(self.base_url, f"{item.path}?{param_name}={true_payload}")
        false_url = urljoin(self.base_url, f"{item.path}?{param_name}={false_payload}")

        try:
            true_resp = await self.client.get(true_url)
            false_resp = await self.client.get(false_url)

            # If response lengths differ significantly, it's likely injectable
            len_diff = abs(len(true_resp.text) - len(false_resp.text))
            if len_diff > 50 and true_resp.status_code == 200:
                evidence = json.dumps({
                    "url": true_url, "param": param_name,
                    "type": "boolean_blind",
                    "true_length": len(true_resp.text),
                    "false_length": len(false_resp.text),
                    "differential": len_diff
                })
                await self._save_vuln(item.id, "SQL Injection (Blind Boolean)", "Critical", evidence, cwe_id="CWE-89")
                print(f"[ZERO-DAY] Boolean Blind SQLi detected on {param_name} (Δ{len_diff} bytes)")
        except Exception:
            pass

    async def test_blind_sqli_time(self, item: ReconData):
        """Time-based blind SQLi: Detect response delay with SLEEP payloads."""
        import time
        details = json.loads(item.details)
        param_name = details.get("param")
        if not param_name: return

        payloads = [
            "1' AND SLEEP(3)--",
            "1; WAITFOR DELAY '0:0:3'--",
            "1' OR pg_sleep(3)--"
        ]

        # First get baseline response time
        baseline_url = urljoin(self.base_url, f"{item.path}?{param_name}=1")
        try:
            start = time.time()
            await self.client.get(baseline_url)
            baseline_time = time.time() - start
        except:
            return

        for payload in payloads:
            test_url = urljoin(self.base_url, f"{item.path}?{param_name}={payload}")
            try:
                start = time.time()
                await self.client.get(test_url)
                elapsed = time.time() - start

                # If response took 2+ seconds longer than baseline, likely vulnerable
                if elapsed - baseline_time > 2.0:
                    evidence = json.dumps({
                        "url": test_url, "param": param_name,
                        "type": "time_blind",
                        "payload": payload,
                        "baseline_ms": round(baseline_time * 1000),
                        "elapsed_ms": round(elapsed * 1000)
                    })
                    await self._save_vuln(item.id, "SQL Injection (Blind Time-Based)", "Critical", evidence, cwe_id="CWE-89")
                    print(f"[ZERO-DAY] Time-Based Blind SQLi on {param_name} ({round(elapsed*1000)}ms vs {round(baseline_time*1000)}ms baseline)")
                    break
            except Exception:
                pass

    async def ai_test_form(self, item: ReconData):
        if item.method != "POST": return
        details = json.loads(item.details)
        action_url = details.get("action")
        inputs = details.get("inputs", [])
        
        if not action_url or not inputs: return

        # 1. Fetch Scratchpad History for this form
        from models import OrchestratorState
        result = await self.session.execute(
            select(OrchestratorState).where(
                OrchestratorState.target_id == self.target.id,
                OrchestratorState.form_path == item.path
            )
        )
        history = result.scalars().all()
        history_text = "\n".join([f"Tried: {h.payload_tried} -> Result: {h.result_summary}" for h in history])

        # 2. Ask Gemma for a payload
        prompt = f"""
You are a penetration tester. You found an HTML form. Your goal is to bypass authentication or trigger a vulnerability (SQLi, XSS) by filling out the form.
Do NOT repeat payloads that have already been tried and failed.

Form Action: {action_url}
Inputs: {json.dumps(inputs)}

Previous Attempts History:
{history_text if history_text else "None yet."}

Respond with ONLY a raw JSON object representing the form data to submit. The keys must match the input names exactly.
Example: {{"username": "admin", "password": "' OR 1=1--"}}
"""
        try:
            import os
            base_url = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
            # Using 120s timeout as models can be slow to load
            ai_resp = await httpx.AsyncClient(timeout=300.0, verify=False).post(f"{base_url}/api/generate", json={
                "model": "gemma:2b",
                "prompt": prompt,
                "stream": False
            })
            
            if ai_resp.status_code == 200:
                text = ai_resp.json().get("response", "")
                
                # Try to parse JSON from Gemma's response
                try:
                    # Clean up markdown code blocks if any
                    clean_text = text.replace("```json", "").replace("```", "").strip()
                    payload_data = json.loads(clean_text)
                except json.JSONDecodeError:
                    print(f"Failed to parse AI JSON: {text}")
                    return

                # 3. Submit the form
                response = await self.client.post(action_url, data=payload_data)
                
                result_summary = f"Status: {response.status_code}, Length: {len(response.text)}"
                if response.status_code in [301, 302, 303]:
                    result_summary += f", Redirect: {response.headers.get('Location')}"

                # 4. Save to Scratchpad
                state = OrchestratorState(
                    target_id=self.target.id,
                    form_path=item.path,
                    payload_tried=json.dumps(payload_data),
                    result_summary=result_summary
                )
                self.session.add(state)

                # 5. Very basic vulnerability checks on the result
                if "syntax error" in response.text.lower() or "mysql" in response.text.lower():
                    await self._save_vuln(item.id, "SQL Injection (AI Found)", "Critical", f"Error triggered with payload: {payload_data}")
                for val in payload_data.values():
                    if isinstance(val, str) and "<script>" in val and val in response.text:
                        await self._save_vuln(item.id, "XSS (AI Found)", "High", f"Payload reflected: {val}")

                await self.session.commit()
                
        except Exception as e:
            print(f"AI Form Fill failed: {e}")

async def start_scan(target_id: int, db: AsyncSession):
    # Fetch target
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if target:
        agent = ScannerAgent(target, db)
        await agent.run()
