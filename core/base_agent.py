from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum
import asyncio
import httpx

class RiskLevel(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class Finding:
    id: str
    agent_name: str
    title: str
    description: str
    risk_level: RiskLevel
    evidence: str
    remediation: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    target_url: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def fingerprint(self) -> str:
        """For deduplication — normalize and hash core fields"""
        normalized = f"{self.title}:{self.evidence.strip()[:200]}".lower()
        return normalized

class ShivamAgent(ABC):
    name: str = "base"
    phase: str = "recon"  # recon | weaponization | exploitation | analysis
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.scratchpad: List[str] = []
    
    @abstractmethod
    async def execute(self, target: Any) -> List[Finding]:
        """Main entry point — must be implemented by every agent"""
        pass
    
    def log(self, message: str):
        self.scratchpad.append(f"[{self.name}] {message}")
    
    async def http_request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """Shared async HTTP client with timeout/retry logic"""
        async with httpx.AsyncClient(timeout=30, follow_redirects=True, verify=False) as client:
            return await client.request(method, url, **kwargs)
