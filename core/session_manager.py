import httpx
import re
from typing import Dict, Optional, Any
from bs4 import BeautifulSoup
from agents.traffic_proxy import ProxyClient
from sqlalchemy.ext.asyncio import AsyncSession

class AuthSession:
    """
    Maintains persistent authentication state (cookies, CSRF, headers).
    Phase 5 / Explorer-Level Session Simulation.
    Now integrated with ProxyClient for traffic logging.
    """
    def __init__(self, base_url: str, db_session: AsyncSession, target_id: int):
        self.base_url = base_url
        self.db_session = db_session
        self.target_id = target_id
        self.cookies: Dict[str, str] = {}
        self.headers: Dict[str, str] = {
            "User-Agent": "Mozilla/5.0 (VAPT-Agent-v1.0; Shivam-OS)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        self.csrf_token: Optional[str] = None
        self.client = ProxyClient(
            session=self.db_session,
            target_id=self.target_id,
            tag="auth",
            follow_redirects=True, 
            verify=False,
            timeout=15.0
        )

    async def get_initial_state(self, url: str):
        """Fetch the page and extract CSRF tokens / cookies."""
        try:
            resp = await self.client.get(url)
            self.cookies.update(dict(resp.cookies))
            self.csrf_token = self._extract_csrf(resp.text)
            if self.csrf_token:
                self.headers["X-CSRF-Token"] = self.csrf_token
            return resp
        except Exception:
            return None

    def _extract_csrf(self, html: str) -> Optional[str]:
        """Look for common CSRF patterns in forms/meta tags."""
        soup = BeautifulSoup(html, "html.parser")
        # 1. Hidden inputs
        for inp in soup.find_all("input", type="hidden"):
            name = inp.get("name", "").lower()
            if any(k in name for k in ["csrf", "xsrf", "token", "authenticity"]):
                return inp.get("value")
        
        # 2. Meta tags
        meta = soup.find("meta", attrs={"name": re.compile(r"csrf|token", re.I)})
        if meta:
            return meta.get("content")
            
        return None

    async def send_request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """Send request using the persistent ProxyClient."""
        # Inject CSRF if we have it and it's a POST/PUT/DELETE
        if self.csrf_token and method.upper() in ["POST", "PUT", "DELETE"]:
            # If using 'data', inject there
            if "data" in kwargs and isinstance(kwargs["data"], dict):
                for k in ["csrf", "csrf_token", "authenticity_token"]:
                    if k not in kwargs["data"]:
                        kwargs["data"][k] = self.csrf_token
            # If using 'json', inject there
            elif "json" in kwargs and isinstance(kwargs["json"], dict):
                 for k in ["csrf", "csrf_token", "authenticity_token"]:
                    if k not in kwargs["json"]:
                        kwargs["json"][k] = self.csrf_token

        resp = await self.client.request(method, url, headers=self.headers, **kwargs)
        self.cookies.update(dict(resp.cookies))
        return resp

    async def close(self):
        await self.client.aclose()
