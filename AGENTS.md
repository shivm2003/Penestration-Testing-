# Agent Responsibilities and Roles

This document describes the purpose of each module in the `agents/` directory and explains what each agent is designed to do.

## Overview

The project uses a mix of reconnaissance, scanning, vulnerability validation, AI-powered analysis, and post-exploitation simulation agents. The `OrchestratorAgent` in `agents/orchestrator.py` coordinates many of these agents into a single end-to-end scanning pipeline.

## Agent Modules

### `agents/orchestrator.py`
- Main orchestration engine.
- Runs the full scanning pipeline for a target.
- Coordinates phases including reconnaissance, page classification, defensive audits, scanning, validation, AI analysis, attack chain correlation, brute force testing, post-exploitation simulation, and risk scoring.
- Uses many other agents as task-specific workers.

### `agents/recon.py`
- `ReconAgent`
- Performs web crawling and directory fuzzing against the target.
- Extracts endpoints, query parameters, and form structures.
- Stores discovered paths in `ReconData` for later scanning.

### `agents/page_classifier.py`
- `PageClassifierAgent`
- Classifies discovered pages into auth surfaces such as login, admin, or dashboard pages.
- Uses URL heuristics, HTML heuristics, and optional LLM confirmation to identify important entry points.
- Stores results in `AuthSurface` for downstream login and logic testing.

### `agents/port_scanner.py`
- `PortScannerAgent`
- Performs lightweight port scans on common ports.
- Identifies open services and saves port findings to `ReconData`.
- Helps map infrastructure before application-level scanning.

### `agents/waf_agent.py`
- `WAFAgent`
- Fingerprints web application firewalls by passive header analysis and active probing.
- Detects defensive layers that may block or filter scanning traffic.

### `agents/honeypot_agent.py`
- `HoneypotAgent`
- Detects honeypot or deception systems by probing login endpoints.
- Looks for fake credential acceptance, artificial latency, and honeypot-specific headers.

### `agents/config_agent.py`
- `ConfigAgent`
- Performs Nikto-style configuration and disclosure audits.
- Checks common sensitive paths and server header disclosures.

### `agents/code_review_agent.py`
- `CodeReviewAgent`
- Searches common code disclosure paths like `.git/config`, `.env`, and source files.
- If code is found, performs an AI-assisted security review and stores the analysis.

### `agents/scanner.py`
- `ScannerAgent`
- Core vulnerability scanner.
- Uses recon data to test endpoints and parameters for XSS, SQLi, open redirect, missing headers, directory exposure, blind SQLi, and more.
- Stores discovered vulnerabilities in `Vulnerability`.
- Uses `PayloadEngine` to obtain or evolve payloads.

### `agents/validator.py`
- `ValidatorAgent`
- Confirms or rejects pending vulnerability findings.
- Re-tests XSS and SQLi candidates to reduce false positives.
- Marks findings as confirmed or rejected.

### `agents/login_tester.py`
- `LoginTesterAgent`
- Targets login and authentication surfaces.
- Uses the login form structure to send safe login-related payloads and detect auth bypass, SQLi, verbose errors, and leaks.
- Logs test results and can store successful payloads.

### `agents/otp_bypass_agent.py`
- `OTPBypassAgent`
- Dedicated OTP/2FA bypass testing engine.
- Discovers OTP endpoints from common paths and auth test results.
- Tests for response manipulation, status code override, client-side validation bypass, parameter pollution, content-type switching, and referer/origin tampering.

### `agents/brute_agent.py`
- `BruteForceAgent`
- Performs brute-force credential testing against login forms discovered in recon.
- Also checks for OTP disclosures in form responses.
- Records successful or unsuccessful brute-force attempts.

### `agents/leak_analyzer.py`
- `LeakAnalyzer`
- Response exposure analyzer used by multiple agents.
- Detects secrets, JWTs, session IDs, API keys, stack traces, internal IPs, PII, and high-entropy strings with regex and entropy heuristics.
- Provides semantic diffing support for response comparison.

### `agents/analyzer.py`
- `AnalyzerAgent`
- AI-powered vulnerability analysis engine.
- Processes confirmed vulnerabilities to generate forensic summaries, attack vector descriptions, business impact, and mitigation strategies.
- Handles recursive AI actions and adversarial self-review.

### `agents/chain_analyzer.py`
- `ChainAnalyzerAgent`
- Builds attack chains from multiple confirmed findings.
- Uses AI reasoning to identify how vulnerabilities can combine into multi-step exploit paths.

### `agents/risk_scorer.py`
- `RiskScorerAgent`
- Computes custom risk scores for confirmed vulnerabilities.
- Uses severity, CVSS, CWE exploitability, and exposure factors to rank issues.
- Stores aggregated risk context in vulnerability records.

### `agents/jwt_analyzer.py`
- `JWTAnalyzerAgent`
- Analyzes JWT tokens discovered on the target.
- Detects insecure algorithms like `none`, weak HMAC secrets, and token exposure.
- Extracts tokens from authentication responses and headers.

### `agents/cloud_auditor.py`
- `CloudAuditorAgent`
- Scans for cloud leakage issues.
- Detects exposed cloud resource URLs, AWS keys, GCP buckets, Azure blobs, and SSRF access to metadata endpoints.

### `agents/graphql_analyzer.py`
- `GraphQLAnalyzerAgent`
- Tests common GraphQL endpoints for introspection and schema discovery.
- Detects field suggestion leaks and insecure GraphQL configuration.

### `agents/websocket_analyzer.py`
- `WebSocketAnalyzerAgent`
- Probes WebSocket endpoints for unauthenticated access.
- Detects unsolicited information disclosure on websocket connections.

### `agents/rate_limit_tester.py`
- `RateLimitTesterAgent`
- Tests sensitive endpoints for missing rate limiting.
- Sends burst requests and detects 429 throttling or the lack thereof.

### `agents/lateral_agent.py`
- `LateralMovementAgent`
- Post-exploitation simulation agent.
- Uses confirmed SSRF findings to simulate internal pivoting and cloud metadata access.
- Identifies lateral movement potential.

### `agents/persistence_agent.py`
- `PersistenceAuditorAgent`
- Post-exploitation persistence auditor.
- Looks for writable configuration and sensitive files discovered during recon.
- Flags persistence vectors such as exposed `.env` or config files.

### `agents/page_classifier.py`
- Already documented above, but it is important in the overall pipeline.

## Supporting Modules

### `agents/payload_engine.py`
- Manages payload storage and mutation.
- Seeds a payload library and evolves payloads using Gemma AI.
- Supports other agents by returning prioritized payloads for a given vulnerability type.

### `agents/traffic_proxy.py`
- `ProxyClient`
- HTTP client wrapper that logs traffic to the database.
- Captures request/response details and sensitive flags.
- Used by agents for traffic logging and analysis.

### `agents/utils.py`
- Shared helper functions for logging and event creation.
- Used by multiple agents to standardize audit/event entries.

### `agents/report.py`
- `ReportAgent`
- Generates a JSON report from collected findings.
- Summarizes executive risk, defensive profile, red-team impact, and detailed vulnerabilities.

### `agents/intelligence_collector.py`
- `IntelligenceCollectorAgent`
- Seeds and synchronizes CWE intelligence data.
- Provides a baseline for vulnerability classification and correlation.

## How Agents Fit Together

- `ReconAgent` finds targets and captures structure.
- `PageClassifierAgent` identifies important auth surfaces.
- `ScannerAgent`, `LoginTesterAgent`, `ConfigAgent`, `CodeReviewAgent`, and `JWTAnalyzerAgent` discover app-level vulnerabilities.
- `ValidatorAgent` confirms findings.
- `AnalyzerAgent` and `ChainAnalyzerAgent` enrich findings with AI-driven analysis and attack stories.
- `RiskScorerAgent` ranks the results.
- `LateralMovementAgent` and `PersistenceAuditorAgent` simulate post-exploitation impact.
- `ReportAgent` exports the final findings.

## Notes

- Some agents are run directly by the orchestrator while others can be invoked independently for more targeted testing.
- The pipeline is designed to combine traditional scanning methods with AI-assisted reasoning and post-compromise simulation.
