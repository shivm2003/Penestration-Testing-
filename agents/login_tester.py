"""
Phase 2 — Safe Interactive Login Testing Engine
Scratchpad Execution Model: Gemma suggests payloads → Executor sends → Leak Analyzer detects.
Focus: logic flaws, weak validation, response leakage. No brute force.
"""

import httpx, json, re, os, time, difflib
from urllib.parse import urljoin
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from models import Target, AuthSurface, AuthTestResult, PayloadLibrary
from agents.utils import log_event
from core.request_builder import RequestTemplate
from core.session_manager import AuthSession

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL    = os.getenv("OLLAMA_MODEL", "gemma:2b")

BASELINE_PAYLOADS = {
    "sqli":         ["' OR '1'='1", "' OR 1=1--", "admin'--", "' UNION SELECT null,null--"],
    "auth_bypass":  ["admin", "' OR 1=1#", "", "anything"],
    "error_probe":  ["A"*512, "<script>alert(1)</script>", "${7*7}", "../../etc/passwd", "null"],
    "fuzz":         ["' \"", "\x00", "%00", "\\", "%27 OR %271%27=%271"],
}


class LoginTesterAgent:
    def __init__(self, target: Target, session: AsyncSession):
        self.target   = target
        self.session  = session
        self.base_url = target.url
        self.auth_session = AuthSession(self.base_url, self.session, self.target.id)

    async def run(self):
        await log_event(self.session, self.target.id, "LOGIN_TESTER",
                        "Phase 2: Starting Safe Login Testing Engine", "INFO")
        try:
            surfaces = await self._get_login_surfaces()
            if not surfaces:
                await log_event(self.session, self.target.id, "LOGIN_TESTER",
                                "No login surfaces found. Run Page Classifier first.", "WARNING")
                return
            for surface in surfaces:
                await log_event(self.session, self.target.id, "LOGIN_TESTER",
                                f"Testing: {surface.url}", "INFO")
                await self._test_surface(surface)
            await log_event(self.session, self.target.id, "LOGIN_TESTER",
                            "Login Testing Engine completed.", "SUCCESS")
        finally:
            await self.auth_session.close()

    async def _get_login_surfaces(self):
        r = await self.session.execute(
            select(AuthSurface).where(
                AuthSurface.target_id == self.target.id,
                AuthSurface.page_type == "login"))
        return r.scalars().all()

    async def _test_surface(self, surface: AuthSurface):
        form_data = json.loads(surface.form_structure or "[]")
        if not form_data:
            return
        form       = form_data[0]
        action_url = urljoin(surface.url, form.get("action", "")) or surface.url
        method     = form.get("method", "POST").upper()
        fields     = form.get("fields", [])
        template   = RequestTemplate.from_form(action_url, method, fields)
        
        # Get baseline with initial session state (extracts CSRF/cookies)
        await self.auth_session.get_initial_state(surface.url)
        
        baseline_body = template.build_payload({"email": "test@test.com", "password": "testpassword"})
        baseline_resp, _ = await self._send_request(template.method, template.url, baseline_body)
        baseline_text = baseline_resp.text if baseline_resp else ""
        baseline_code = baseline_resp.status_code if baseline_resp else 0

        gemma_payloads = await self._ask_gemma_payloads(
            template.url, template.method, baseline_body, baseline_text[:1000], baseline_code)
        all_payloads = self._build_payload_set(template, gemma_payloads)

        for payload_desc, body, ptype in all_payloads:
            resp, _ = await self._send_request(template.method, template.url, body)
            if resp is None:
                continue
            resp_text = resp.text
            resp_code = resp.status_code
            diff      = self._compute_diff(baseline_text, resp_text)

            from agents.leak_analyzer import LeakAnalyzer
            leaks    = LeakAnalyzer().analyze(resp_text, dict(resp.headers))
            vuln_type = self._classify_result(resp_code, baseline_code, resp_text, leaks, ptype)
            confidence = self._score_confidence(vuln_type, leaks, diff)

            await self._save_result(template.url, payload_desc, ptype, resp_code,
                                    diff[:2000], leaks, vuln_type, confidence, resp_text[:1024])
            
            if vuln_type:
                await log_event(self.session, self.target.id, "LOGIN_TESTER",
                                f"Vulnerability detected: {vuln_type} on {template.url}", "WARNING")
            
            if confidence > 0.6 and vuln_type:
                await self._store_payload(payload_desc, vuln_type)

    # Removed _build_body as it is replaced by RequestTemplate.build_payload

    def _build_payload_set(self, template: RequestTemplate, gemma_payloads):
        results = []
        for p in gemma_payloads:
            body = template.build_payload({"email": p.get("username", "x"), "password": p.get("password", "x")})
            results.append((f"{p.get('type','fuzz')}: user={p.get('username','')!r}", body, p.get("type","fuzz")))
        for ptype, payloads in BASELINE_PAYLOADS.items():
            for pl in payloads:
                body = template.build_payload({"email": pl, "password": pl})
                results.append((f"{ptype}: {pl!r}", body, ptype))
        return results

    async def _send_request(self, method, url, body):
        t0 = time.time()
        try:
            r = await self.auth_session.send_request(method, url, data=body)
            return r, (time.time()-t0)*1000
        except Exception:
            return None, 0

    def _compute_diff(self, a, b):
        return "\n".join(list(difflib.unified_diff(a.splitlines(), b.splitlines(), lineterm="", n=2))[:80])

    def _classify_result(self, code, base_code, text, leaks, ptype):
        t = text.lower()
        if code in (200,302) and base_code not in (200,302): return "auth_bypass"
        if any(k in t for k in ["welcome","dashboard","logged in","logout"]): return "auth_bypass"
        if any(k in t for k in ["sql syntax","mysql","sqlite","ora-","pg_query","syntax error"]): return "sqli"
        if leaks: return "info_leak"
        if any(k in t for k in ["traceback","exception","stack trace","fatal error"]): return "verbose_error"
        return None

    def _score_confidence(self, vuln_type, leaks, diff):
        if not vuln_type: return 0.0
        s = 0.5
        if leaks: s += 0.3
        if vuln_type in ("auth_bypass","sqli"): s += 0.2
        if diff and len(diff) > 100: s += 0.1
        return min(s, 1.0)

    async def _ask_gemma_payloads(self, url, method, body, resp_snippet, resp_code):
        prompt = f"""You are a web security tester focused on logic flaws only.
Login request: URL={url} Method={method} Body={json.dumps(body)}
Server response code: {resp_code}
Response: {resp_snippet[:300]}
Suggest 5 safe test cases (NO brute force) to detect SQLi, auth bypass, verbose errors.
Respond ONLY as JSON array: [{{"type":"sqli","username":"payload","password":"payload"}}]"""
        try:
            async with httpx.AsyncClient(timeout=90.0) as c:
                r = await c.post(f"{OLLAMA_BASE_URL}/api/generate",
                                 json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False})
                text = r.json().get("response","")
                m = re.search(r'\[.*?\]', text, re.DOTALL)
                if m: return json.loads(m.group())
        except Exception:
            pass
        return []

    async def _save_result(self, url, payload, ptype, code, diff, leaks, vuln_type, confidence, snippet):
        self.session.add(AuthTestResult(
            target_id=self.target.id, url=url, payload=payload, payload_type=ptype,
            response_code=code, response_diff=diff,
            sensitive_data_detected=json.dumps(leaks) if leaks else None,
            vulnerability_type=vuln_type, confidence=confidence, raw_response_snippet=snippet))
        await self.session.commit()

    async def _store_payload(self, payload, vuln_type):
        ex = (await self.session.execute(
            select(PayloadLibrary).where(
                PayloadLibrary.payload == payload,
                PayloadLibrary.vuln_type == vuln_type))).scalar_one_or_none()
        if ex:
            ex.used_count += 1
            ex.success_rate = min(ex.success_rate + 0.05, 1.0)
        else:
            self.session.add(PayloadLibrary(payload=payload, vuln_type=vuln_type,
                                            success_rate=0.6, used_count=1, source="agent"))
        await self.session.commit()


async def start_login_testing(target_id: int, db: AsyncSession):
    r = await db.execute(select(Target).where(Target.id == target_id))
    t = r.scalar_one_or_none()
    if t:
        await LoginTesterAgent(t, db).run()
