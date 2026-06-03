import httpx
import json
import os
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from models import Target, Vulnerability

class AnalyzerAgent:
    def __init__(self, target: Target, session: AsyncSession):
        self.target = target
        self.session = session
        self.client = httpx.AsyncClient(timeout=600.0, verify=False) # Significant increase for local LLM inference
        # Try to get URL from env, else default to 127.0.0.1
        self.base_url = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
        self.ollama_url = f"{self.base_url}/api/generate"

    async def run(self):
        try:
            result = await self.session.execute(
                select(Vulnerability).where(
                    Vulnerability.target_id == self.target.id,
                    Vulnerability.status == "confirmed"
                )
            )
            vulnerabilities = result.scalars().all()

            for vuln in vulnerabilities:
                # 1. Hardcode severity
                if "SQL" in vuln.vuln_type:
                    vuln.severity = "Critical"
                elif "XSS" in vuln.vuln_type:
                    vuln.severity = "High"

                # 2. Ask Gemma for professional Forensic Analysis
                prompt = f"""
[OFFICIAL SECURITY FORENSIC ADVISORY]
You are a Lead Forensic Analyst at a top-tier cybersecurity firm. Analyze the following discovery and provide a high-fidelity forensic breakdown.

### FORENSIC INVESTIGATION STEPS:
1.  **Vector Identification**: Trace the exact entry point and payload interaction.
2.  **Logic Verification**: Explain the server-side failure that allows this interaction.
3.  **Threat Narratization**: Describe how an advanced persistent threat (APT) would utilize this for data exfiltration or lateral movement.
4.  **Business Impact Assessment**: Quantify the risk in terms of Data Integrity, Confidentiality, and Financial exposure.
5.  **Mitigation Strategy**: Provide defense-in-depth recommendations.

### REQUIRED OUTPUT STRUCTURE (STRICT):
FORENSIC_SUMMARY: [A professional executive summary of the discovery]
ATTACK_VECTOR: [Technical breakdown of the exploitation path]
BUSINESS_IMPACT: [Detailed analysis of financial, operational, and regulatory risk]
MITIGATION_STRATEGY: [Step-by-step developer-centric remediation steps]
CWE: [CWE-ID]
ACTION: [NONE | RECURSIVE_RECON <path> | RECURSIVE_SCAN <path> <param>]

Vulnerability Discovery:
- Type: {vuln.vuln_type}
- Evidence: {vuln.evidence}
- Target: {self.target.url}
"""
                try:
                    response = await self.client.post(self.ollama_url, json={
                        "model": "gemma:2b",
                        "prompt": prompt,
                        "stream": False
                    })
                    if response.status_code == 200:
                        data = response.json()
                        text = data.get("response", "")
                        
                        # Parse the response
                        explanation = ""
                        risk = ""
                        fix = ""
                        action = "NONE"
                        thoughts = ""
                        
                        for line in text.split('\n'):
                            if line.startswith("FORENSIC_SUMMARY:"):
                                explanation = line.replace("FORENSIC_SUMMARY:", "").strip()
                            elif line.startswith("ATTACK_VECTOR:"):
                                thoughts = line.replace("ATTACK_VECTOR:", "").strip()
                            elif line.startswith("BUSINESS_IMPACT:"):
                                risk = line.replace("BUSINESS_IMPACT:", "").strip()
                            elif line.startswith("MITIGATION_STRATEGY:"):
                                fix = line.replace("MITIGATION_STRATEGY:", "").strip()
                            elif line.startswith("CWE:"):
                                vuln.cwe_id = line.replace("CWE:", "").strip()
                            elif line.startswith("ACTION:"):
                                action = line.replace("ACTION:", "").strip()
                                
                        vuln.explanation = f"### ATTACK VECTOR\n{thoughts}\n\n### FORENSIC SUMMARY\n{explanation}" if thoughts else explanation
                        vuln.risk = risk
                        vuln.fix = fix
                        vuln.status = "analyzed"

                        # Handle Recursive Action
                        if action != "NONE":
                            await self.handle_recursive_action(action)

                        # === ADVERSARIAL SELF-REVIEW ===
                        await self.adversarial_review(vuln)

                    else:
                        print(f"Ollama error: {response.text}")
                except Exception as e:
                    print(f"Failed to connect to Ollama: {e}")
                
                await self.session.commit()
                
        except Exception as e:
            print(f"Analyzer failed to connect to Ollama at {self.ollama_url}: {e}")
            self.target.status = "failed"
            await self.session.commit()
        finally:
            await self.client.aclose()

    async def handle_recursive_action(self, action_str: str):
        """Processes AI requests for more data and saves them to the DB."""
        from agents.utils import log_event
        from models import RecursiveAction
        
        await log_event(self.session, self.target.id, "ANALYZER_RECURSIVE", f"AI requested action: {action_str}", "INFO")
        
        try:
            parts = action_str.split()
            cmd = parts[0].upper()
            
            if cmd == "RECON" and len(parts) > 1:
                path = parts[1]
                new_action = RecursiveAction(
                    target_id=self.target.id,
                    action_type="RECON",
                    target_path=path,
                    status="pending"
                )
                self.session.add(new_action)
                await log_event(self.session, self.target.id, "RECURSIVE_RECON", f"Targeted path: {path} queued.", "INFO")
                
            elif cmd == "SCAN" and len(parts) > 2:
                path = parts[1]
                param = parts[2]
                new_action = RecursiveAction(
                    target_id=self.target.id,
                    action_type="SCAN",
                    target_path=path,
                    target_param=param,
                    status="pending"
                )
                self.session.add(new_action)
                await log_event(self.session, self.target.id, "RECURSIVE_SCAN", f"Targeted param: {param} on {path} queued.", "INFO")
            
            await self.session.commit()
        except Exception as e:
            print(f"Failed to handle recursive action: {e}")

    async def adversarial_review(self, vuln):
        """Second AI pass: attack own finding to eliminate false positives."""
        review_prompt = f"""
You are a skeptical senior security auditor performing a FALSE POSITIVE review.
Given the following vulnerability finding, assess whether it is a REAL vulnerability or a FALSE POSITIVE.

Vulnerability Type: {vuln.vuln_type}
CWE: {vuln.cwe_id or 'Unknown'}
Evidence: {vuln.evidence}
AI Explanation: {vuln.explanation}

Respond with EXACTLY two lines:
CONFIDENCE: [number 0-100, where 100 = definitely real, 0 = definitely false positive]
REASON: [one sentence explaining your confidence level]
"""
        try:
            response = await self.client.post(self.ollama_url, json={
                "model": "gemma:2b",
                "prompt": review_prompt,
                "stream": False
            })
            if response.status_code == 200:
                text = response.json().get("response", "")
                confidence = 75  # Default if parsing fails
                reason = ""
                
                for line in text.split('\n'):
                    if line.startswith("CONFIDENCE:"):
                        try:
                            confidence = int(''.join(filter(str.isdigit, line.split(":")[1].strip()[:3])))
                        except:
                            confidence = 75
                    elif line.startswith("REASON:"):
                        reason = line.replace("REASON:", "").strip()

                print(f"[ADVERSARIAL REVIEW] {vuln.vuln_type}: Confidence={confidence}% — {reason}")

                if confidence < 40:
                    vuln.status = "rejected"
                    vuln.fix = f"[REJECTED by Adversarial Review] Confidence: {confidence}%. {reason}"
                    print(f"[FALSE POSITIVE REJECTED] {vuln.vuln_type}")
        except Exception as e:
            print(f"Adversarial review failed: {e}")


async def start_analyze(target_id: int, db: AsyncSession):
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if target:
        agent = AnalyzerAgent(target, db)
        await agent.run()


async def generate_advanced_report(vuln_id: int, db: AsyncSession):
    """Generates a deep, standalone advanced AI report for a specific vulnerability."""
    import os
    import traceback

    base_url = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
    ollama_url = f"{base_url}/api/generate"

    # 1. Pre-flight: Check if Ollama is reachable
    try:
        async with httpx.AsyncClient(timeout=5.0, verify=False) as probe:
            r = await probe.get(base_url)
            if r.status_code != 200:
                raise ConnectionError("Ollama returned non-200")
    except Exception as e:
        print(f"[ADVANCED REPORT] Ollama unreachable at {base_url}: {e}")
        # Mark as failed and return early
        result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
        vuln = result.scalar_one_or_none()
        if vuln:
            vuln.ai_report_status = "failed"
            await db.commit()
        return

    # 2. Load vulnerability
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        print(f"[ADVANCED REPORT] Vulnerability ID {vuln_id} not found.")
        return

    # 3. Mark as generating and capture attributes before commit expires the object
    vuln.ai_report_status = "generating"
    await db.commit()

    # Capture all needed attributes before the session expires the object
    vuln_type = vuln.vuln_type
    severity = vuln.severity
    cwe_id = vuln.cwe_id or 'Unknown'
    evidence = vuln.evidence or 'None'
    explanation = vuln.explanation or 'None'
    risk = vuln.risk or 'None'

    prompt = f"""You are a Lead Forensic Security Consultant at a global cybersecurity firm.
Write a board-ready, high-fidelity Advanced Forensic Impact Report for the following vulnerability.

Use professional Markdown formatting with clear hierarchies and premium technical language.

# AI IMPACT DEEP-DIVE: {vuln_type}

## 1. Executive Intelligence Summary
A high-level summary for stakeholders detailing the discovery and its immediate significance.

## 2. Technical Forensic Analysis
A deep-dive into the underlying weakness, exploitation mechanics, and confirmation evidence.

## 3. Threat Modeling & Attack Scenario
Describe a realistic attack scenario where an APT actor leverages this weakness to achieve specific objectives (e.g., Ransomware deployment, Data Exfiltration, Financial Fraud).

## 4. Business & Compliance Impact
- **Data Privacy**: Impact on PII/Sensitive data.
- **Operational Risk**: Potential for service disruption.
- **Regulatory Exposure**: GDPR/HIPAA/SEC implications.
- **Financial Risk**: Estimated cost of breach.

## 5. CVSS v3.1 Impact Metrics
Detailed breakdown of Attack Vector, Complexity, Privileges Required, and Impact on Confidentiality/Integrity/Availability.

## 6. Strategic Remediation Roadmap
- **Immediate Action**: Short-term patches/WAF rules.
- **Strategic Fix**: Architectural changes to eliminate the root cause.
- **Verification**: Post-remediation testing steps.

Vulnerability Context:
- Type: {vuln_type}
- Severity: {severity}
- CWE: {cwe_id}
- Evidence: {evidence}
- AI Forensic Summary: {explanation}
- Initial Risk Assessment: {risk}
"""

    report_text = None
    new_status = "failed"

    try:
        async with httpx.AsyncClient(timeout=600.0, verify=False) as client:
            response = await client.post(ollama_url, json={
                "model": "gemma:2b",
                "prompt": prompt,
                "stream": False
            })
            if response.status_code == 200:
                report_text = response.json().get("response", "")
                new_status = "completed"
                print(f"[ADVANCED REPORT] Completed for vuln {vuln_id} ({vuln_type})")
            else:
                print(f"[ADVANCED REPORT] Ollama returned {response.status_code}: {response.text[:200]}")
    except Exception as e:
        print(f"[ADVANCED REPORT] Exception during generation for vuln {vuln_id}: {e}")
        traceback.print_exc()

    # 4. Re-fetch and update — avoids expired instance issue after earlier commit
    try:
        result2 = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
        vuln2 = result2.scalar_one_or_none()
        if vuln2:
            vuln2.ai_report_status = new_status
            if report_text:
                vuln2.advanced_ai_report = report_text
            await db.commit()
    except Exception as e:
        print(f"[ADVANCED REPORT] Failed to save result for vuln {vuln_id}: {e}")
        traceback.print_exc()
