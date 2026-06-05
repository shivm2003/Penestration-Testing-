from sqlalchemy import Column, Integer, String, Text, ForeignKey, DateTime, Float
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from database import Base

class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, unique=True, index=True, nullable=False)
    status = Column(String, default="pending") # pending, mythos_running, scanned, failed
    iteration_count = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    recon_data = relationship("ReconData", back_populates="target", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="target", cascade="all, delete-orphan")
    orchestrator_states = relationship("OrchestratorState", back_populates="target", cascade="all, delete-orphan")
    code_reviews = relationship("CodeReview", cascade="all, delete-orphan")
    chain_findings = relationship("ChainFinding", cascade="all, delete-orphan")
    brute_findings = relationship("BruteFinding", cascade="all, delete-orphan")
    system_logs = relationship("SystemLog", cascade="all, delete-orphan")
    auth_surfaces = relationship("AuthSurface", cascade="all, delete-orphan")
    auth_test_results = relationship("AuthTestResult", cascade="all, delete-orphan")
    traffic_logs = relationship("TrafficLog", cascade="all, delete-orphan")
    recursive_actions = relationship("RecursiveAction", cascade="all, delete-orphan")


class ReconData(Base):
    __tablename__ = "recon_data"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    data_type = Column(String, nullable=False) # endpoint, parameter, form, api
    path = Column(String, nullable=False)
    method = Column(String, default="GET")
    details = Column(Text, nullable=True) # JSON payload, form fields etc
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    target = relationship("Target", back_populates="recon_data")
    vulnerabilities = relationship("Vulnerability", back_populates="recon_data")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    recon_data_id = Column(Integer, ForeignKey("recon_data.id"), nullable=True)
    vuln_type = Column(String, nullable=False) # XSS, SQLi, Open Redirect, etc
    path = Column(String, nullable=True)
    method = Column(String, nullable=True)
    cwe_id = Column(String, nullable=True) # E.g., CWE-89
    severity = Column(String, nullable=False) # Low, Medium, High, Critical
    cvss_score = Column(Float, nullable=True)
    evidence = Column(Text, nullable=True) # Payload used, HTTP response snippet
    status = Column(String, default="pending") # pending, confirmed, rejected, analyzed
    explanation = Column(Text, nullable=True)
    risk = Column(Text, nullable=True)
    fix = Column(Text, nullable=True)
    ai_report_status = Column(String, default="none") # none, generating, completed, failed
    advanced_ai_report = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    target = relationship("Target", back_populates="vulnerabilities")
    recon_data = relationship("ReconData", back_populates="vulnerabilities")


class OrchestratorState(Base):
    __tablename__ = "orchestrator_state"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    form_path = Column(String, nullable=False)
    payload_tried = Column(Text, nullable=False) # JSON
    result_summary = Column(Text, nullable=True) # E.g., 'Redirected to /dashboard' or '403 Forbidden'
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    target = relationship("Target", back_populates="orchestrator_states")

class CodeReview(Base):
    __tablename__ = "code_reviews"
    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    file_path = Column(String, nullable=False)
    snippet = Column(Text, nullable=False)
    ai_analysis = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

class ChainFinding(Base):
    __tablename__ = "chain_findings"
    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    chain_title = Column(String, nullable=False)
    vuln_ids_involved = Column(String, nullable=False)  # comma-separated IDs
    attack_narrative = Column(Text, nullable=True)
    severity = Column(String, default="Critical")
    confidence = Column(Integer, default=90)  # 0-100
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class BruteFinding(Base):
    __tablename__ = "brute_findings"
    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    url = Column(String, nullable=False)
    method = Column(String, default="POST")
    payload_summary = Column(Text, nullable=True) # e.g. "Cluster Bomb: 100 combinations"
    success_status = Column(String, default="No success") # "Success: admin/1234"
    otp_leak = Column(String, nullable=True) # "OTP Leaked: 5562"
    severity = Column(String, default="High")
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class SystemLog(Base):
    __tablename__ = "system_logs"
    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=True)
    log_level = Column(String, default="INFO") # INFO, SUCCESS, WARNING, CRITICAL
    agent_name = Column(String, nullable=False)
    message = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class RecursiveAction(Base):
    __tablename__ = "recursive_actions"
    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    action_type = Column(String, nullable=False) # RECON, SCAN, etc
    target_path = Column(String, nullable=False)
    target_param = Column(String, nullable=True)
    status = Column(String, default="pending") # pending, executing, completed
    created_at = Column(DateTime(timezone=True), server_default=func.now())


# ─────────────────────────────────────────────────────────────────────────────
# Phase 1: Auth Surface Detection
# ─────────────────────────────────────────────────────────────────────────────
class AuthSurface(Base):
    """Stores detected login/admin pages and auth-related surfaces."""
    __tablename__ = "auth_surfaces"
    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    url = Column(String, nullable=False)
    page_type = Column(String, nullable=False)  # login, admin, dashboard, public
    detection_method = Column(String, default="heuristic")  # heuristic, llm
    confidence_score = Column(Float, default=0.0)  # 0.0 – 1.0
    form_structure = Column(Text, nullable=True)   # JSON: [{name, type, required}]
    page_title = Column(String, nullable=True)
    response_code = Column(Integer, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    target = relationship("Target", back_populates="auth_surfaces")


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2: Login Logic-Flaw Test Results
# ─────────────────────────────────────────────────────────────────────────────
class AuthTestResult(Base):
    """Stores results from the safe login testing engine."""
    __tablename__ = "auth_test_results"
    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    url = Column(String, nullable=False)
    payload = Column(Text, nullable=True)          # Payload sent
    payload_type = Column(String, nullable=True)   # sqli, bypass, fuzz, error_probe
    response_code = Column(Integer, nullable=True)
    response_diff = Column(Text, nullable=True)    # What changed vs baseline
    sensitive_data_detected = Column(Text, nullable=True)  # JSON list of leaks
    vulnerability_type = Column(String, nullable=True)     # sqli, auth_bypass, info_leak
    confidence = Column(Float, default=0.0)        # 0.0 – 1.0
    raw_response_snippet = Column(Text, nullable=True)     # First 1KB of response
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    target = relationship("Target", back_populates="auth_test_results")


# ─────────────────────────────────────────────────────────────────────────────
# Phase 3 / Traffic Proxy: Network Traffic Capture
# ─────────────────────────────────────────────────────────────────────────────
class TrafficLog(Base):
    """HTTP traffic captured by the agent proxy layer."""
    __tablename__ = "traffic_logs"
    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=True)  # nullable for global logs
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    method = Column(String, nullable=False)
    url = Column(String, nullable=False)
    request_headers = Column(Text, nullable=True)   # JSON
    request_body = Column(Text, nullable=True)
    response_status = Column(Integer, nullable=True)
    response_headers = Column(Text, nullable=True)  # JSON
    response_body = Column(Text, nullable=True)     # Truncated to 2KB
    latency_ms = Column(Float, nullable=True)
    tag = Column(String, default="general")         # auth, api, static, general
    sensitive_flags = Column(Text, nullable=True)   # JSON: detected tokens/PIIs


# ─────────────────────────────────────────────────────────────────────────────
# Advanced: Payload Evolution Library
# ─────────────────────────────────────────────────────────────────────────────
class PayloadLibrary(Base):
    """Stores successful payloads for context-aware reuse and Gemma mutation."""
    __tablename__ = "payload_library"
    id = Column(Integer, primary_key=True, index=True)
    payload = Column(Text, nullable=False)
    vuln_type = Column(String, nullable=False)      # sqli, xss, auth_bypass, etc.
    context = Column(Text, nullable=True)            # JSON: target tech stack, endpoint type
    success_rate = Column(Float, default=0.0)        # 0.0 – 1.0
    used_count = Column(Integer, default=0)
    source = Column(String, default="manual")        # manual, gemma, evolved
    created_at = Column(DateTime(timezone=True), server_default=func.now())


# ─────────────────────────────────────────────────────────────────────────────
# Phase 0: Weakness Intelligence (CWE Catalog)
# ─────────────────────────────────────────────────────────────────────────────
class CWEData(Base):
    """Local catalog of CWE weaknesses for classification and remediation."""
    __tablename__ = "cwe_data"
    
    cwe_id = Column(String, primary_key=True, index=True) # e.g., CWE-89
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    common_consequences = Column(Text, nullable=True) # JSON
    mitigation_strategies = Column(Text, nullable=True) # JSON
    last_modified = Column(DateTime(timezone=True), server_default=func.now())
    created_at = Column(DateTime(timezone=True), server_default=func.now())
