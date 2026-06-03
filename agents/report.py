from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from models import Target

class ReportAgent:
    def __init__(self, target: Target):
        self.target = target

    def generate_json_report(self) -> dict:
        # Categorize all vulnerabilities
        all_vulns = self.target.vulnerabilities
        analyzed_vulns = [v for v in all_vulns if v.status == "analyzed"]
        
        # Defensive findings
        defensive = [v for v in all_vulns if v.vuln_type and ("waf" in v.vuln_type.lower() or "honeypot" in v.vuln_type.lower())]
        
        # Red Team / Post-Exploitation findings
        red_team = [v for v in all_vulns if v.vuln_type and ("lateral" in v.vuln_type.lower() or "persistence" in v.vuln_type.lower())]

        # Risk Breakdown
        breakdown = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for v in analyzed_vulns:
            if v.severity in breakdown:
                breakdown[v.severity] += 1
                
        report = {
            "ExecutiveSummary": {
                "Target": self.target.url,
                "TotalVulnerabilities": len(analyzed_vulns),
                "RiskBreakdown": breakdown,
                "SecurityScore": self.calculate_score(breakdown)
            },
            "DefensiveProfile": [
                {"Type": v.vuln_type, "Evidence": v.evidence} for v in defensive
            ],
            "RedTeamImpact": [
                {"Title": v.vuln_type, "Description": v.explanation, "Risk": v.risk} for v in red_team
            ],
            "DetailedVulnerabilities": []
        }
        
        for v in analyzed_vulns:
            report["DetailedVulnerabilities"].append({
                "Type": v.vuln_type,
                "Severity": v.severity,
                "Evidence": v.evidence,
                "Explanation": v.explanation,
                "Risk": v.risk,
                "Fix": v.fix
            })
            
        return report

    def calculate_score(self, breakdown):
        # Professional risk score calculation
        score = 100
        score -= (breakdown["Critical"] * 20)
        score -= (breakdown["High"] * 10)
        score -= (breakdown["Medium"] * 5)
        score -= (breakdown["Low"] * 2)
        return max(0, score)

async def generate_report(target_id: int, db: AsyncSession) -> dict:
    from models import ChainFinding, BruteFinding, CodeReview
    result = await db.execute(
        select(Target)
        .options(selectinload(Target.vulnerabilities), selectinload(Target.recon_data))
        .where(Target.id == target_id)
    )
    target = result.scalar_one_or_none()
    if target:
        # Fetch extra intelligence
        c_res = await db.execute(select(ChainFinding).where(ChainFinding.target_id == target_id))
        chains = c_res.scalars().all()
        
        b_res = await db.execute(select(BruteFinding).where(BruteFinding.target_id == target_id))
        brutes = b_res.scalars().all()

        cr_res = await db.execute(select(CodeReview).where(CodeReview.target_id == target_id))
        reviews = cr_res.scalars().all()

        agent = ReportAgent(target)
        report = agent.generate_json_report()
        
        # Add extra intelligence
        report["AttackChains"] = [
            {"Title": c.chain_title, "Narrative": c.attack_narrative, "Severity": c.severity} for c in chains
        ]
        report["BruteFindings"] = [
            {"URL": b.url, "Status": b.success_status, "OTP": b.otp_leak} for b in brutes
        ]
        report["CodeReviews"] = [
            {"File": r.file_path, "Analysis": r.ai_analysis} for r in reviews
        ]
        
        return report
    return {}
