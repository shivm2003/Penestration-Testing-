# Software Requirements Specification (SRS)

## 1. Introduction

### 1.1 Purpose
This document defines the functional and non-functional requirements for the Shivam OS VAPT Agent Orchestrator project. It acts as a Product Requirements Document (PRD) and System Requirements Specification (SRS) for the current repository.

### 1.2 Scope
The system is an autonomous vulnerability assessment and penetration testing platform that coordinates reconnaissance, vulnerability discovery, validation, AI analysis, chain correlation, and reporting. It supports backend orchestration, agent execution, data storage, and frontend dashboards.

### 1.3 Intended Audience
- Product managers
- Developers
- Security engineers
- QA testers
- Technical architects

### 1.4 References
- `README.md`
- `PIPELINE_ARCHITECTURE.md`
- `main.py`
- `models.py`
- `schemas.py`
- `database.py`
- `agents/orchestrator.py`
- `core/celery_app.py`
- `frontend/app.js`
- `frontend/auth_lab.js`

---

## 2. System Overview

Shivam OS is a next-generation distributed VAPT platform. It uses an asynchronous Python backend with FastAPI, a PostgreSQL database, Celery task orchestration, and a JavaScript frontend. The system is designed to:
- create and manage scan targets
- execute reconnaissance and vulnerability pipelines
- validate vulnerabilities
- generate AI-backed risk analysis
- visualize scan progress and findings
- persist intelligence data for reuse

The core orchestrator lives in `agents/orchestrator.py` and is invoked from the API service at `main.py`.

---

## 3. Functional Requirements

### 3.1 Target Management
- Create targets via `POST /api/targets`
- List targets via `GET /api/targets`
- Delete targets via `DELETE /api/targets/{target_id}`
- Stop active scans with `POST /api/targets/{target_id}/stop`

### 3.2 Scan Orchestration
- Start the full orchestrated scan pipeline with `POST /api/targets/{target_id}/start_mythos`
- The pipeline is implemented by `OrchestratorAgent.run()` in `agents/orchestrator.py`
- The system supports distributed execution through Celery (`core/celery_app.py`) and local fallback via FastAPI `BackgroundTasks`

### 3.3 Reconnaissance and Discovery
- Execute port scan and crawling agents
- Persist reconnaissance data in the `ReconData` table
- Detect login/admin surfaces using `PageClassifierAgent`

### 3.4 Vulnerability Engines
- Scan for vulnerabilities with `ScannerAgent`
- Validate findings with `ValidatorAgent`
- Perform login logic testing with `LoginTesterAgent`
- Perform advanced testing with `AdvancedTestAgent`

### 3.5 AI Analysis and Reporting
- Generate AI reports via `AnalyzerAgent`
- Provide AI status via `GET /api/ai/status`
- List AI reports via `GET /api/ai/reports`
- Download target report via `GET /api/targets/{target_id}/report/download`

### 3.6 Auth Lab and Login Testing
- Fetch detected auth surfaces via `GET /api/targets/{target_id}/auth_surfaces`
- Trigger page classification via `POST /api/targets/{target_id}/classify_pages`
- Trigger login testing via `POST /api/targets/{target_id}/login_test`
- Trigger advanced auth tests via `POST /api/targets/{target_id}/advanced_test`
- Retrieve auth test results via `GET /api/targets/{target_id}/auth_test_results`

### 3.7 Traffic Capture and Analysis
- Store traffic logs and expose them via `GET /api/traffic_logs`
- Support filtering by target, tag, status, keyword, and limit
- Clear traffic logs via `DELETE /api/traffic_logs`
- Retrieve single log entries via `GET /api/traffic_logs/{log_id}`

### 3.8 Payload Library
- View payload library using `GET /api/payload_library`
- Seed payloads with `POST /api/payload_library/seed`
- Evolve payloads with `POST /api/payload_library/evolve`

### 3.9 Risk Scoring and Intelligence
- Start risk scoring with `POST /api/targets/{target_id}/risk_score`
- Sync CWE intelligence using `POST /api/intel/sync`
- Read recent intelligence with `GET /api/intel/recent`
- Retrieve global platform statistics via `GET /api/stats`

---

## 4. Non-Functional Requirements

### 4.1 Performance
- Use async SQLAlchemy and FastAPI for scalable I/O-bound workloads
- Use Celery with Redis for distributed scan execution
- Support repeated scans with payload seeding and caching

### 4.2 Reliability
- Persist target state and findings in PostgreSQL
- Roll back failed database writes and return accurate HTTP responses
- Use `BackgroundTasks` to keep long-running scans decoupled from request lifecycle

### 4.3 Security
- Enforce unique target URLs in the `targets` table (`models.py`)
- Support secure API operation via controlled endpoints
- Use database models and Pydantic schemas to validate payloads

### 4.4 Maintainability
- Modular agent design under `agents/`
- Clear model definitions in `models.py`
- Schema definitions in `schemas.py`
- API routing and orchestration in `main.py`

### 4.5 Usability
- Frontend dashboard in `frontend/app.js` for target management, scanning, and reporting
- Auth Lab frontend in `frontend/auth_lab.js` for login/auth surface analysis
- Minimal UI flow for scan control and result inspection

---

## 5. System Architecture

### 5.1 Backend Architecture
- FastAPI service defined in `main.py`
- Async PostgreSQL engine and session management in `database.py`
- ORM models in `models.py`
- API response models in `schemas.py`
- Celery worker configuration in `core/celery_app.py`
- Orchestrator and agent pipeline in `agents/orchestrator.py`

### 5.2 Agent Pipeline
The orchestrator pipeline follows these phases:
1. Intelligence sync (`IntelligenceCollectorAgent`)
2. Payload library seeding (`PayloadEngine`)
3. Infrastructure scan (`PortScannerAgent`)
4. Recon and crawling (`ReconAgent`)
5. Login/admin surface detection (`PageClassifierAgent`)
6. Defensive probe (`WAFAgent`, `HoneypotAgent`)
7. Config audit and code review (`ConfigAgent`, `CodeReviewAgent`)
8. Vulnerability injection (`ScannerAgent`)
9. Validation (`ValidatorAgent`)
10. Specialized analysis (`JWTAnalyzerAgent`, `CloudAuditorAgent`, `GraphQLAnalyzerAgent`, `WebSocketAnalyzerAgent`, `RateLimitTesterAgent`)
11. Login/advanced auth testing (`LoginTesterAgent`, `LeakAnalyzerAgent`)
12. AI analysis (`AnalyzerAgent`)
13. Attack chain correlation (`ChainAnalyzerAgent`)
14. Brute force and OTP analysis (`BruteForceAgent`)
15. Red team simulation (`LateralMovementAgent`, `PersistenceAuditorAgent`)
16. Risk scoring (`RiskScorerAgent`)

### 5.3 Frontend Architecture
- `frontend/app.js` is the main dashboard controller
- `frontend/auth_lab.js` manages auth and traffic-focused interactions
- Frontend consumes `/api/*` endpoints and renders targets, statistics, vulnerability lists, auth surfaces, and logs

---

## 6. Data Model

### 6.1 Core Entities
- `Target` (`models.py`): Represents scan target URL, status, iteration count, created timestamp
- `ReconData`: Stores discovered paths, input types, methods, and details
- `Vulnerability`: Stores vulnerability metadata, severity, evidence, status, and AI report state
- `AuthSurface`: Stores detected auth/login/admin pages and classification metadata
- `AuthTestResult`: Stores login logic-flaw test outcomes and evidence
- `TrafficLog`: Stores captured request/response traffic records
- `PayloadLibrary`: Stores payloads, success rates, and usage context
- `CWEData`: Stores curated intelligence for weaknesses

### 6.2 Relationships
- `Target` has many: `recon_data`, `vulnerabilities`, `auth_surfaces`, `auth_test_results`, `traffic_logs`, `code_reviews`, `chain_findings`, `brute_findings`, `system_logs`
- `Vulnerability` may be linked to `ReconData`

---

## 7. API Requirements

### 7.1 Target API
- `POST /api/targets` - create target
- `GET /api/targets` - list targets
- `DELETE /api/targets/{target_id}` - remove target
- `POST /api/targets/{target_id}/stop` - stop scan
- `POST /api/targets/{target_id}/start_mythos` - begin orchestrated scan

### 7.2 Scan Control API
- `POST /api/targets/{target_id}/recon`
- `POST /api/targets/{target_id}/scan`
- `POST /api/targets/{target_id}/validate`
- `POST /api/targets/{target_id}/retest`
- `POST /api/targets/{target_id}/analyze`
- `GET /api/targets/{target_id}/report`
- `GET /api/targets/{target_id}/report/download`
- `GET /api/targets/{target_id}/logs`

### 7.3 Auth Lab API
- `GET /api/targets/{target_id}/auth_surfaces`
- `POST /api/targets/{target_id}/classify_pages`
- `POST /api/targets/{target_id}/login_test`
- `POST /api/targets/{target_id}/advanced_test`
- `GET /api/targets/{target_id}/auth_test_results`

### 7.4 Traffic and Payload API
- `GET /api/traffic_logs`
- `DELETE /api/traffic_logs`
- `GET /api/traffic_logs/{log_id}`
- `GET /api/payload_library`
- `POST /api/payload_library/seed`
- `POST /api/payload_library/evolve`

### 7.5 AI / Intelligence API
- `GET /api/ai/status`
- `GET /api/ai/reports`
- `POST /api/intel/sync`
- `GET /api/intel/recent`
- `GET /api/stats`

---

## 8. User Interface Requirements

### 8.1 Dashboard
- Display target list and statuses
- Allow creating and deleting targets
- Show scan control buttons and scan status
- Display summary statistics and real-time logs
- Visualize vulnerability, chain, and attack surface data

### 8.2 Auth Lab UI
- Select target for authentication testing
- View login/admin surface detections
- Trigger page classification, login test, and advanced test
- View traffic log analytics and leak counts

### 8.3 Reporting
- Provide target-level report download
- Summarize AI-analyzed vulnerabilities and code review results
- Show risk score generation actions

---

## 9. Deployment and Environment

### 9.1 Runtime Environment
- Python backend with FastAPI
- PostgreSQL database (`database.py`)
- Redis-backed Celery broker and backend (`core/celery_app.py`)
- Local LLM integration via Ollama (`GET /api/ai/status`)
- Frontend served as static HTML/JS

### 9.2 Key Configuration
- `DATABASE_URL` environment variable
- `REDIS_URL` environment variable
- `OLLAMA_BASE_URL` environment variable

---

## 10. File Mapping and Traceability

| SRS Section | Implementation Files |
|---|---|
| API and orchestration | `main.py` |
| Data model | `models.py` |
| Pydantic schemas | `schemas.py` |
| Database session and engine | `database.py` |
| Celery tasks | `core/celery_app.py` |
| Orchestrator pipeline | `agents/orchestrator.py` |
| Payload engine | `agents/payload_engine.py` |
| Login/auth tests | `agents/login_tester.py`, `agents/advanced_test_agent.py` |
| Page classification | `agents/page_classifier.py` |
| Traffic and attack analysis | `agents/traffic_proxy.py`, `agents/rate_limit_tester.py`, `agents/leak_analyzer.py` |
| Frontend dashboard | `frontend/app.js` |
| Auth Lab interface | `frontend/auth_lab.js` |
| Architecture overview | `PIPELINE_ARCHITECTURE.md` |
| Project introduction | `README.md` |

---

## 11. Future Enhancements

### 11.1 Distributed Scaling
- Expand Celery worker pool
- Add more task sharding and worker-specific agent services

### 11.2 UI Enhancements
- Add richer visual drilldown for vulnerabilities and attack chains
- Add progress indicators and real-time WebSocket updates

### 11.3 Security and Compliance
- Add authentication/authorization for the API
- Add audit logging for user actions
- Add export templates for compliance reports

### 11.4 AI and Intelligence Improvements
- Add model routing and fallback for local LLMs
- Add CWE / CVE auto-correlation and exploit trend analysis
- Add remediation code generation and fix tracking
