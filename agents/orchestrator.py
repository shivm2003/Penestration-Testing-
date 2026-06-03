import asyncio
from core.celery_app import celery_app
from database import AsyncSessionLocal
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from models import Target
from agents.recon import ReconAgent
from agents.scanner import ScannerAgent
from agents.validator import ValidatorAgent
from agents.analyzer import AnalyzerAgent
from agents.port_scanner import PortScannerAgent
from agents.config_agent import ConfigAgent
from agents.code_review_agent import CodeReviewAgent
from agents.chain_analyzer import ChainAnalyzerAgent
from agents.brute_agent import BruteForceAgent
from agents.jwt_analyzer import JWTAnalyzerAgent
from agents.cloud_auditor import CloudAuditorAgent
from agents.graphql_analyzer import GraphQLAnalyzerAgent
from agents.websocket_analyzer import WebSocketAnalyzerAgent
from agents.rate_limit_tester import RateLimitTesterAgent
from agents.waf_agent import WAFAgent
from agents.honeypot_agent import HoneypotAgent
from agents.lateral_agent import LateralMovementAgent
from agents.persistence_agent import PersistenceAuditorAgent
from agents.utils import log_event
from agents.page_classifier import PageClassifierAgent
from agents.login_tester import LoginTesterAgent
from agents.leak_analyzer import LeakAnalyzerAgent
from agents.risk_scorer import RiskScorerAgent
from agents.payload_engine import PayloadEngine
from agents.intelligence_collector import IntelligenceCollectorAgent
from models import Vulnerability

class OrchestratorAgent:
    def __init__(self, target: Target, session: AsyncSession, max_iterations: int = 3):
        self.target = target
        self.session = session
        self.max_iterations = max_iterations

    async def run(self):
        try:
            self.target.status = "mythos_running"
            await self.session.commit()

            from main import STOPPED_TARGETS
            if self.target.id in STOPPED_TARGETS:
                await log_event(self.session, self.target.id, "ORCHESTRATOR", "Stop command received. Terminating scan...", "WARNING")
                STOPPED_TARGETS.remove(self.target.id)
                self.target.status = "stopped"
                await self.session.commit()
                return

            await log_event(self.session, self.target.id, "ORCHESTRATOR", f"Starting Single Scan Pipeline", "INFO")
            
            # Phase 0: Vulnerability Intelligence Sync
            await log_event(self.session, self.target.id, "CWE_SYNC", "Phase 0: Synchronizing Global CWE Intelligence...", "INFO")
            intel_collector = IntelligenceCollectorAgent(self.session)
            await intel_collector.sync_cwe()

            self.target.iteration_count = 1
            await self.session.commit()

            # 0a. Seed payload library (idempotent)
            payload_engine = PayloadEngine(self.session)
            await payload_engine.seed()

            # 0. Infrastructure Scan
            await log_event(self.session, self.target.id, "PORT_SCANNER", "Initializing Infrastructure Scan...", "INFO")
            port_scanner = PortScannerAgent(self.target, self.session)
            await port_scanner.run()

            # 1. Recon
            await log_event(self.session, self.target.id, "SPIDER", "Starting Network Mapping and Crawling...", "INFO")
            recon = ReconAgent(self.target, self.session)
            await recon.run()

            # 1.1 Phase 1: Login/Admin Surface Detection
            await log_event(self.session, self.target.id, "PAGE_CLASSIFIER", "Detecting Login & Admin Surfaces...", "INFO")
            page_clf = PageClassifierAgent(self.target, self.session)
            await page_clf.run()

            # 1.2 Defensive Audit (WAF & Honeypot)
            await log_event(self.session, self.target.id, "WAF_PROBE", "Fingerprinting Web Application Firewall...", "INFO")
            waf_agent = WAFAgent()
            waf_findings = await waf_agent.execute(self.target, self.session)
            for f in waf_findings: await self.save_finding(f)

            await log_event(self.session, self.target.id, "HONEYPOT_DECEPTION", "Scanning for Deception Systems & Honeypots...", "INFO")
            hp_agent = HoneypotAgent()
            hp_findings = await hp_agent.execute(self.target, self.session)
            for f in hp_findings: await self.save_finding(f)

            # 1.5 Config Audit
            await log_event(self.session, self.target.id, "CONFIG_AUDIT", "Performing Security Configuration Audit...", "INFO")
            config_audit = ConfigAgent(self.target, self.session)
            await config_audit.run()

            # 1.7 Code Review
            await log_event(self.session, self.target.id, "CODE_REVIEW", "Scanning for Source Code Disclosure...", "INFO")
            code_review = CodeReviewAgent(self.target, self.session)
            await code_review.run()

            # 2. Scan
            await log_event(self.session, self.target.id, "SCANNER", "Executing Vulnerability Injections & AI Form Filling...", "INFO")
            scanner = ScannerAgent(self.target, self.session)
            await scanner.run()

            # 3. Validate
            await log_event(self.session, self.target.id, "VALIDATOR", "Confirming Vulnerabilities & Eliminating False Positives...", "INFO")
            validator = ValidatorAgent(self.target, self.session)
            await validator.run()
            
            # 3.5 Specialized Agents (Phase 2)
            await log_event(self.session, self.target.id, "JWT_ANALYZER", "Analyzing Authentication Tokens...", "INFO")
            jwt_agent = JWTAnalyzerAgent()
            jwt_findings = await jwt_agent.execute(self.target, self.session)
            for f in jwt_findings: await self.save_finding(f)

            await log_event(self.session, self.target.id, "CLOUD_AUDITOR", "Auditing Cloud Configuration & SSRF Vectors...", "INFO")
            cloud_agent = CloudAuditorAgent()
            cloud_findings = await cloud_agent.execute(self.target, self.session)
            for f in cloud_findings: await self.save_finding(f)

            await log_event(self.session, self.target.id, "GRAPHQL_ANALYZER", "Mapping GraphQL Schema & Mutations...", "INFO")
            gql_agent = GraphQLAnalyzerAgent()
            gql_findings = await gql_agent.execute(self.target, self.session)
            for f in gql_findings: await self.save_finding(f)

            await log_event(self.session, self.target.id, "WEBSOCKET_ANALYZER", "Probing WebSocket Protocol Handshakes...", "INFO")
            ws_agent = WebSocketAnalyzerAgent()
            ws_findings = await ws_agent.execute(self.target, self.session)
            for f in ws_findings: await self.save_finding(f)

            await log_event(self.session, self.target.id, "RATE_LIMIT_TESTER", "Testing API Resilience & Burst Limits...", "INFO")
            rl_agent = RateLimitTesterAgent()
            rl_findings = await rl_agent.execute(self.target, self.session)
            for f in rl_findings: await self.save_finding(f)

            # 3.7 Phase 2 & 3: Login Testing + Leak Analysis
            await log_event(self.session, self.target.id, "LOGIN_TESTER", "Phase 2: Safe Login Logic-Flaw Testing...", "INFO")
            login_tester = LoginTesterAgent(self.target, self.session)
            await login_tester.run()

            await log_event(self.session, self.target.id, "LEAK_ANALYZER", "Phase 3: Response Exposure Analysis...", "INFO")
            leak_agent = LeakAnalyzerAgent(self.target, self.session)
            await leak_agent.run()

            # 4. Analyze
            await log_event(self.session, self.target.id, "ANALYZER", "Gemma AI: Analyzing Risk & Remediation...", "INFO")
            analyzer = AnalyzerAgent(self.target, self.session)
            await analyzer.run()

            # 5. Chain Analysis
            await log_event(self.session, self.target.id, "CHAIN_ANALYZER", "Correlating findings into Attack Chains...", "INFO")
            chain_analyzer = ChainAnalyzerAgent(self.target, self.session)
            await chain_analyzer.run()

            # 6. Brute Force
            await log_event(self.session, self.target.id, "BRUTE_FORCE", "Testing Credentials & OTP Disclosure...", "INFO")
            brute_agent = BruteForceAgent(self.target, self.session)
            await brute_agent.run()

            # 7. Red Team Operations (Post-Exploitation)
            await log_event(self.session, self.target.id, "RED_TEAM", "Simulating Lateral Movement & Persistence...", "INFO")
            lateral_agent = LateralMovementAgent()
            lat_findings = await lateral_agent.execute(self.target, self.session)
            for f in lat_findings: await self.save_finding(f)

            persistence_agent = PersistenceAuditorAgent()
            pers_findings = await persistence_agent.execute(self.target, self.session)
            for f in pers_findings: await self.save_finding(f)

            # 8. Risk Scoring
            await log_event(self.session, self.target.id, "RISK_SCORER", "Computing Custom Risk Scores...", "INFO")
            risk_scorer = RiskScorerAgent(self.target, self.session)
            await risk_scorer.run()

            self.target.status = "scanned"
            await self.session.commit()
            await log_event(self.session, self.target.id, "ORCHESTRATOR", "Scan Completed Successfully", "SUCCESS")

        except Exception as e:
            await log_event(self.session, self.target.id, "ORCHESTRATOR", f"Orchestrator failed: {e}", "CRITICAL")
            self.target.status = "failed"
            await self.session.commit()

    async def save_finding(self, finding):
        # Map Finding dataclass to Vulnerability model
        new_vuln = Vulnerability(
            target_id=self.target.id,
            vuln_type=finding.title,
            severity=finding.risk_level.value,
            path=finding.target_url.replace(self.target.url, "") or "/",
            method="GET", # Default for these scans
            evidence=finding.evidence,
            status="confirmed", # High confidence from specialized agents
            explanation=finding.description,
            fix=finding.remediation,
            cwe_id=finding.cwe_id,
            ai_report_status="completed" # We treat the agent's description as the report
        )
        self.session.add(new_vuln)
        await self.session.commit()
        await log_event(self.session, self.target.id, finding.agent_name.upper(), f"Finding: {finding.title}", "WARNING")

@celery_app.task(name="shivam_os.start_mythos_task")
def start_mythos_task(target_id: int):
    """Distributed task entry point for Orchestrator."""
    async def _run():
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(Target).where(Target.id == target_id))
            target = result.scalar_one_or_none()
            if target:
                orchestrator = OrchestratorAgent(target, db)
                await orchestrator.run()
    
    asyncio.run(_run())

async def start_mythos(target_id: int, db: AsyncSession):
    # This remains for backward compatibility or local calling
    # In main.py, we will switch to start_mythos_task.delay()
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if target:
        orchestrator = OrchestratorAgent(target, db)
        await orchestrator.run()
