import jwt
import base64
import json
import time
import re
from pathlib import Path
from typing import List, Optional, Any
from core.base_agent import ShivamAgent, Finding, RiskLevel

class JWTAnalyzerAgent(ShivamAgent):
    name = "jwt_analyzer"
    phase = "weaponization"
    
    def __init__(self, config=None):
        super().__init__(config)
        self.wordlist_path = config.get("wordlist", "wordlists/jwt_secrets.txt") if config else "wordlists/jwt_secrets.txt"
        self.secrets = self._load_wordlist()
    
    def _load_wordlist(self) -> List[str]:
        default_secrets = [
            "secret", "Secret", "SECRET", "your-256-bit-secret",
            "mysecret", "jwt-secret", "supersecret", "password",
            "123456", "admin", "changeme", "default", "key", "root"
        ]
        try:
            if Path(self.wordlist_path).exists():
                with open(self.wordlist_path) as f:
                    return [line.strip() for line in f if line.strip()]
        except:
            pass
        return default_secrets
    
    async def execute(self, target: Any, session: Any = None) -> List[Finding]:
        findings = []
        url = getattr(target, 'url', str(target))
        self.log(f"Starting JWT analysis on {url}")
        
        tokens = await self._extract_tokens(target)
        
        for token in tokens:
            findings.extend(await self._analyze_token(token, target))
        
        return findings
    
    async def _extract_tokens(self, target: Any) -> List[str]:
        tokens = []
        url = getattr(target, 'url', str(target))
        
        # Probe common auth endpoints
        auth_endpoints = ["/api/auth/login", "/api/login", "/auth", "/login", "/api/token"]
        for endpoint in auth_endpoints:
            try:
                resp = await self.http_request("POST", f"{url.rstrip('/')}{endpoint}", 
                    json={"username": "admin", "password": "password"},
                    headers={"Content-Type": "application/json"})
                
                # Search for JWT patterns in headers and body
                all_text = resp.text + str(resp.headers)
                matches = re.findall(r"ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*", all_text)
                for m in matches:
                    if self._is_jwt(m):
                        tokens.append(m)
            except:
                continue
        
        return list(set(tokens))
    
    def _is_jwt(self, token: str) -> bool:
        parts = token.split(".")
        return len(parts) >= 2 # Can be JWS (3) or JWE (5)
    
    async def _analyze_token(self, token: str, target: Any) -> List[Finding]:
        findings = []
        url = getattr(target, 'url', str(target))
        
        try:
            # Decode without verification to see content
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})
        except Exception as e:
            self.log(f"Failed to decode token: {e}")
            return findings
        
        # Check 1: Algorithm none
        if header.get("alg", "").lower() in ["none", "null", ""]:
            findings.append(Finding(
                id=f"jwt_none_alg_{hash(token) % 10000}",
                agent_name=self.name,
                title="JWT Algorithm Confusion — 'none' Algorithm Accepted",
                description="The JWT accepts 'none' as a valid algorithm, allowing attackers to forge tokens by removing the signature.",
                risk_level=RiskLevel.CRITICAL,
                evidence=f"Header: {json.dumps(header)}\nToken: {token[:50]}...",
                remediation="Explicitly reject tokens with 'alg': 'none' on the server side.",
                cwe_id="CWE-345",
                cvss_score=9.8,
                target_url=url
            ))
        
        # Check 2: Weak HMAC secrets
        if header.get("alg") in ["HS256", "HS384", "HS512"]:
            for secret in self.secrets:
                try:
                    jwt.decode(token, secret, algorithms=[header["alg"]])
                    findings.append(Finding(
                        id=f"jwt_weak_secret_{hash(token) % 10000}",
                        agent_name=self.name,
                        title=f"Weak JWT Secret Cracked — '{secret}'",
                        description=f"The JWT HMAC signature uses a weak secret that was brute-forced: '{secret}'.",
                        risk_level=RiskLevel.CRITICAL,
                        evidence=f"Algorithm: {header['alg']}\nCracked Secret: {secret}",
                        remediation="Use a cryptographically secure random secret of at least 256 bits.",
                        cwe_id="CWE-798",
                        cvss_score=9.1,
                        target_url=url
                    ))
                    break
                except jwt.InvalidSignatureError:
                    continue
                except:
                    continue
        
        # Check 3: Sensitive data
        sensitive_keys = ["password", "ssn", "secret", "admin", "role", "privilege"]
        leaked = [k for k in payload.keys() if any(s in k.lower() for s in sensitive_keys)]
        if leaked:
            findings.append(Finding(
                id=f"jwt_sensitive_data_{hash(token) % 10000}",
                agent_name=self.name,
                title="Sensitive Data Exposed in JWT Payload",
                description=f"The JWT payload contains sensitive fields: {', '.join(leaked)}.",
                risk_level=RiskLevel.HIGH,
                evidence=f"Payload keys: {list(payload.keys())}",
                remediation="Never store sensitive data in JWT payloads. JWTs are base64-encoded, not encrypted.",
                cwe_id="CWE-312",
                cvss_score=7.5,
                target_url=url
            ))
            
        return findings
