"""
Traffic Proxy Logger
====================
Wraps httpx requests with automatic logging to the TrafficLogs table.
All agents can use `ProxyClient` instead of httpx.AsyncClient directly
to get automatic traffic capture.
"""

import httpx
import json
import time
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from models import TrafficLog

# Max bytes to store for request/response bodies
MAX_BODY_BYTES = 2048


class ProxyClient:
    """
    Drop-in wrapper around httpx.AsyncClient that logs every request/response
    to the TrafficLogs table.
    """

    def __init__(self, session: AsyncSession, target_id: Optional[int] = None,
                 tag: str = "general", **client_kwargs):
        self.session   = session
        self.target_id = target_id
        self.tag       = tag
        self._client   = httpx.AsyncClient(**client_kwargs)

    async def get(self, url: str, **kwargs):
        return await self._request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs):
        return await self._request("POST", url, **kwargs)

    async def request(self, method: str, url: str, **kwargs):
        return await self._request(method, url, **kwargs)

    async def aclose(self):
        await self._client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.aclose()

    async def _request(self, method: str, url: str, **kwargs):
        req_body = ""
        if "data" in kwargs:
            req_body = _truncate(json.dumps(kwargs["data"]))
        elif "json" in kwargs:
            req_body = _truncate(json.dumps(kwargs["json"]))
        elif "content" in kwargs:
            req_body = _truncate(str(kwargs["content"]))

        t0 = time.time()
        resp = None
        try:
            resp = await self._client.request(method, url, **kwargs)
            latency = (time.time() - t0) * 1000
            await self._log(
                method=method, url=url,
                req_headers=dict(resp.request.headers),
                req_body=req_body,
                resp_status=resp.status_code,
                resp_headers=dict(resp.headers),
                resp_body=_truncate(resp.text),
                latency=latency,
            )
            return resp
        except Exception as e:
            latency = (time.time() - t0) * 1000
            await self._log(
                method=method, url=url,
                req_headers={}, req_body=req_body,
                resp_status=0,
                resp_headers={}, resp_body=str(e),
                latency=latency,
            )
            raise

    async def _log(self, method, url, req_headers, req_body,
                   resp_status, resp_headers, resp_body, latency):
        # Auto-tag based on URL / status
        tag = self.tag
        url_lower = url.lower()
        if any(p in url_lower for p in ["/login", "/auth", "/signin", "/admin"]):
            tag = "auth"
        elif any(p in url_lower for p in ["/api/", "/v1/", "/v2/", "/graphql"]):
            tag = "api"
        elif any(url_lower.endswith(ext) for ext in
                 [".js", ".css", ".png", ".jpg", ".svg", ".ico", ".woff"]):
            tag = "static"

        # Detect sensitive flags in response
        from agents.leak_analyzer import LeakAnalyzer
        leaks = LeakAnalyzer().analyze(resp_body, resp_headers)
        flags = json.dumps(leaks) if leaks else None

        log = TrafficLog(
            target_id=self.target_id,
            method=method,
            url=url,
            request_headers=json.dumps(req_headers)[:2048],
            request_body=req_body,
            response_status=resp_status,
            response_headers=json.dumps(resp_headers)[:2048],
            response_body=resp_body,
            latency_ms=round(latency, 2),
            tag=tag,
            sensitive_flags=flags,
        )
        self.session.add(log)
        try:
            await self.session.commit()
        except Exception:
            await self.session.rollback()


def _truncate(text: str) -> str:
    if not text:
        return ""
    encoded = text.encode("utf-8", errors="replace")
    return encoded[:MAX_BODY_BYTES].decode("utf-8", errors="replace")
