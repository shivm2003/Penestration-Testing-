@dataclass
class TargetContext:
    url: str
    base_domain: str
    discovered_endpoints: List[str] = None
    open_ports: List[Dict] = None
    previous_findings: List[Finding] = None  # For chain analysis
    cookies: Dict[str, str] = None
    headers: Dict[str, str] = None
    
    def __post_init__(self):
        if self.discovered_endpoints is None:
            self.discovered_endpoints = []
        if self.previous_findings is None:
            self.previous_findings = []