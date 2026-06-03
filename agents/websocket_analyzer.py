import asyncio
import websockets
from typing import List, Any
from core.base_agent import ShivamAgent, Finding, RiskLevel

class WebSocketAnalyzerAgent(ShivamAgent):
    name = "websocket_analyzer"
    phase = "recon"
    
    async def execute(self, target: Any, session: Any = None) -> List[Finding]:
        findings = []
        url = getattr(target, 'url', str(target))
        
        # Determine ws/wss scheme
        ws_url = url.replace("http://", "ws://").replace("https://", "wss://")
        
        # Common WS paths
        ws_paths = ["/ws", "/socket.io", "/chat", "/stream", "/graphql"]
        
        for path in ws_paths:
            full_ws = f"{ws_url.rstrip('/')}{path}"
            try:
                # 1. Test Connection (No Auth)
                async with websockets.connect(full_ws, timeout=5) as websocket:
                    findings.append(Finding(
                        id=f"ws_unauth_conn_{hash(full_ws) % 10000}",
                        agent_name=self.name,
                        title="Unauthenticated WebSocket Connection",
                        description=f"Established a WebSocket connection to {full_ws} without any authentication headers.",
                        risk_level=RiskLevel.MEDIUM,
                        evidence=f"Connected successfully to: {full_ws}",
                        remediation="Ensure all WebSocket handshakes require a valid JWT or Session cookie.",
                        cwe_id="CWE-287",
                        cvss_score=5.0,
                        target_url=full_ws
                    ))
                    
                    # 2. Listen for messages (Information Disclosure)
                    try:
                        message = await asyncio.wait_for(websocket.recv(), timeout=3)
                        findings.append(Finding(
                            id=f"ws_info_leak_{hash(full_ws) % 10000}",
                            agent_name=self.name,
                            title="WebSocket Information Disclosure",
                            description="Received unsolicited message upon connection, potentially leaking system info or data.",
                            risk_level=RiskLevel.HIGH,
                            evidence=f"Received: {message[:200]}",
                            remediation="Do not broadcast sensitive data immediately upon connection.",
                            cwe_id="CWE-200",
                            cvss_score=7.5,
                            target_url=full_ws
                        ))
                    except asyncio.TimeoutError:
                        pass
            except:
                continue
                
        return findings
