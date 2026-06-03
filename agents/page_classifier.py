"""
Phase 1 — Page Classifier Agent
Detects login, admin, dashboard, and public pages via:
  1. URL-pattern heuristics
  2. HTML indicator heuristics  
  3. HTTP status code signals
  4. Gemma LLM semantic classification (fallback / confirmation)
Results are stored in the AuthSurfaces table.
"""

import httpx
import json
import re
import os
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from models import Target, ReconData, AuthSurface
from agents.utils import log_event
from agents.traffic_proxy import ProxyClient

# ─────────────────────────────────────────────────────────────────────────────
# Heuristic patterns
# ─────────────────────────────────────────────────────────────────────────────
AUTH_URL_PATTERNS = {
    "login":     ["/login", "/signin", "/sign-in", "/log-in", "/auth", "/authenticate"],
    "admin":     ["/admin", "/administrator", "/wp-admin", "/cpanel", "/dashboard/admin",
                  "/manage", "/manager", "/control", "/backend", "/staff", "/superuser"],
    "dashboard": ["/dashboard", "/home", "/portal", "/app", "/user/home", "/profile",
                  "/account", "/my-account", "/settings"],
}

AUTH_TITLE_PATTERNS = {
    "login":     ["login", "sign in", "log in", "authenticate", "member login"],
    "admin":     ["admin", "administration", "control panel", "management console", "cpanel"],
    "dashboard": ["dashboard", "overview", "my account", "user panel", "portal"],
}

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL    = os.getenv("OLLAMA_MODEL", "gemma:2b")


class PageClassifierAgent:
    """
    Classifies every discovered endpoint into:
      login | admin | dashboard | public
    using fast heuristics first, then Gemma for uncertain cases.
    """

    def __init__(self, target: Target, session: AsyncSession):
        self.target  = target
        self.session = session
        self.base_url = target.url
        self.domain   = urlparse(self.base_url).netloc
        self.client   = ProxyClient(
            session=self.session,
            target_id=self.target.id,
            tag="recon",
            timeout=10.0, 
            follow_redirects=True, 
            verify=False
        )

    async def run(self):
        await log_event(self.session, self.target.id, "PAGE_CLASSIFIER",
                        "Starting Phase 1: Login/Admin Surface Detection", "INFO")
        try:
            # Pull all discovered endpoints from ReconData
            result = await self.session.execute(
                select(ReconData).where(
                    ReconData.target_id == self.target.id,
                    ReconData.data_type == "endpoint"
                )
            )
            endpoints = result.scalars().all()

            if not endpoints:
                await log_event(self.session, self.target.id, "PAGE_CLASSIFIER",
                                "No endpoints found — run Recon first.", "WARNING")
                return

            classified = 0
            for ep in endpoints:
                details = json.loads(ep.details) if ep.details else {}
                url = details.get("url", urljoin(self.base_url, ep.path))
                await self._classify_url(url, ep.path)
                classified += 1

            await log_event(self.session, self.target.id, "PAGE_CLASSIFIER",
                            f"Classified {classified} endpoints. Auth surfaces stored.", "SUCCESS")
        finally:
            await self.client.aclose()

    # ──────────────────────────────────────────────────────────────────────────
    async def _classify_url(self, url: str, path: str):
        """Run heuristics + optional LLM classification for one URL."""

        # 1. URL pattern heuristic
        page_type, confidence, method = self._heuristic_url(path)

        # 2. Fetch page for HTML analysis
        try:
            resp = await self.client.get(url, timeout=5.0)
            html = resp.text
            status_code = resp.status_code

            # HTTP status signals
            if status_code in (401, 403):
                page_type = "login"
                confidence = max(confidence, 0.75)
                method = "heuristic"

            # HTML heuristics
            h_type, h_conf = self._heuristic_html(html)
            if h_conf > confidence:
                page_type = h_type
                confidence = h_conf
                method = "heuristic"

            # Parse title + form structure
            soup = BeautifulSoup(html, "html.parser")
            title = (soup.title.string.strip() if soup.title else "") or ""
            form_structure = self._extract_forms(soup)

            # Title heuristic boost
            t_type, t_conf = self._heuristic_title(title)
            if t_conf > confidence:
                page_type = t_type
                confidence = t_conf
                method = "heuristic"

            # LLM confirmation for uncertain cases (0.3 < confidence < 0.8)
            if 0.3 < confidence < 0.8 or page_type == "unknown":
                llm_type, llm_conf = await self._llm_classify(
                    url, title, form_structure, html[:2000], status_code
                )
                if llm_conf > confidence:
                    page_type = llm_type
                    confidence = llm_conf
                    method = "llm"

        except Exception as e:
            status_code = 0
            title = ""
            form_structure = []
            html = ""

        # Only store if it's actually an auth surface
        if page_type in ("login", "admin", "dashboard") and confidence > 0.3:
            await self._save_surface(url, page_type, method, confidence,
                                     form_structure, title, status_code)

    # ──────────────────────────────────────────────────────────────────────────
    def _heuristic_url(self, path: str):
        """Fast URL pattern matching. Returns (type, confidence, method)."""
        path_lower = path.lower()
        for ptype, patterns in AUTH_URL_PATTERNS.items():
            for p in patterns:
                if p in path_lower:
                    return ptype, 0.85, "heuristic"
        return "unknown", 0.0, "heuristic"

    def _heuristic_html(self, html: str):
        """Check HTML for password fields and auth-indicative forms."""
        soup = BeautifulSoup(html, "html.parser")
        has_password = bool(soup.find("input", {"type": "password"}))
        has_username = bool(soup.find("input", attrs={"name": re.compile(r"user|email|login", re.I)}))

        if has_password and has_username:
            return "login", 0.90
        if has_password:
            return "login", 0.75
        return "unknown", 0.0

    def _heuristic_title(self, title: str):
        """Check page title for auth keywords."""
        title_lower = title.lower()
        for ptype, keywords in AUTH_TITLE_PATTERNS.items():
            for kw in keywords:
                if kw in title_lower:
                    return ptype, 0.80
        return "unknown", 0.0

    def _extract_forms(self, soup: BeautifulSoup):
        """Extract form field info. Detects <form> tags and loose inputs."""
        forms = []
        
        # 1. Standard <form> tags
        for form in soup.find_all("form"):
            fields = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name") or inp.get("id") or ""
                itype = inp.get("type", "text")
                fields.append({"name": name, "type": itype,
                               "required": inp.has_attr("required")})
            forms.append({
                "action": form.get("action", ""),
                "method": (form.get("method") or "POST").upper(),
                "fields": fields
            })
        
        # 2. Loose inputs (if no form tag found, but has password field)
        if not forms:
            pass_fields = soup.find_all("input", {"type": "password"})
            if pass_fields:
                fields = []
                # Find associated user/email fields in the whole page
                for inp in soup.find_all(["input", "textarea"]):
                    name = inp.get("name") or inp.get("id") or ""
                    itype = inp.get("type", "text")
                    if itype in ["text", "email", "password"] or any(k in name.lower() for k in ["user", "email", "login", "pass"]):
                         fields.append({"name": name, "type": itype, "required": inp.has_attr("required")})
                
                if fields:
                    forms.append({
                        "action": "", # Submit to current URL
                        "method": "POST",
                        "fields": fields
                    })
        return forms

    # ──────────────────────────────────────────────────────────────────────────
    async def _llm_classify(self, url, title, form_fields, response_snippet, status_code):
        """Send metadata to Gemma for semantic page classification."""
        prompt = f"""You are a web security analyst.

Classify this web page into exactly one category:
- login       (user authentication page)
- admin       (administrative control panel)
- dashboard   (user portal/home after login)
- public      (publicly accessible informational page)

Page metadata:
URL: {url}
Title: {title}
HTTP Status: {status_code}
Form fields: {json.dumps(form_fields, indent=2)}
Response snippet (first 500 chars):
{response_snippet[:500]}

Respond with ONLY a JSON object: {{"type": "<category>", "confidence": <0.0-1.0>, "reason": "<one sentence>"}}"""

        try:
            async with httpx.AsyncClient(timeout=90.0) as client:
                resp = await client.post(
                    f"{OLLAMA_BASE_URL}/api/generate",
                    json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False}
                )
                text = resp.json().get("response", "")
                # Extract JSON from response
                match = re.search(r'\{[^}]+\}', text, re.DOTALL)
                if match:
                    data = json.loads(match.group())
                    ptype = data.get("type", "public").lower()
                    conf  = float(data.get("confidence", 0.5))
                    return ptype, conf
        except Exception:
            pass
        return "public", 0.3

    # ──────────────────────────────────────────────────────────────────────────
    async def _save_surface(self, url, page_type, method, confidence,
                            form_structure, title, response_code):
        """Deduplicate and save to AuthSurface table."""
        existing = await self.session.execute(
            select(AuthSurface).where(
                AuthSurface.target_id == self.target.id,
                AuthSurface.url == url
            )
        )
        if existing.scalar_one_or_none():
            return  # Already recorded

        surface = AuthSurface(
            target_id=self.target.id,
            url=url,
            page_type=page_type,
            detection_method=method,
            confidence_score=confidence,
            form_structure=json.dumps(form_structure),
            page_title=title[:200] if title else None,
            response_code=response_code,
        )
        self.session.add(surface)
        await self.session.commit()
        await log_event(self.session, self.target.id, "PAGE_CLASSIFIER",
                        f"Auth surface [{page_type.upper()}] {url} (conf={confidence:.0%}, via {method})",
                        "WARNING" if page_type in ("admin", "login") else "INFO")


async def start_page_classification(target_id: int, db: AsyncSession):
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if target:
        agent = PageClassifierAgent(target, db)
        await agent.run()
