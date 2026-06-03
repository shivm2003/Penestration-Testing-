# Shivam OS: Agent Intelligence & Validation Architecture

This document provides a technical breakdown of the autonomous data flow, threat intelligence integration, and validation logic within the Shivam OS ecosystem.

---

## 🛰️ Data Flow & Validation Lifecycle

Shivam OS does not use linear, point-to-point data passing. Instead, it utilizes an **Event-Driven Shared State** model. The pipeline is enhanced by a continuous **Vulnerability Intelligence Feed** (CWE Patterns sync) that informs agents during the discovery phase.

```mermaid
graph TD
    subgraph "0. THREAT INTELLIGENCE"
        INTEL[Intelligence Collector] -->|Sync CWE Patterns| DB_TI[(Global Intel DB)]
    end

    subgraph "1. RECONNAISSANCE"
        REC[Recon Agent] -->|Endpoint Discovery| DB_R[(ReconData Table)]
        PORT[Port Scanner] -->|Service Mapping| DB_R
    end

    subgraph "2. VULNERABILITY DISCOVERY"
        DB_R -->|Read Paths| SCN[Scanner Agent]
        DB_TI -->|Enrich Context| SCN
        SCN -->|Identify Potential Vuln| DB_V1[(Vulnerabilities: Status='pending')]
    end

    subgraph "3. ADVERSARIAL VALIDATION"
        DB_V1 -->|Fetch Pending| VAL[Validator Agent]
        VAL -->|Active Payload Re-Exploit| TGT{Target Site}
        TGT -->|Successful Breach Evidence| VAL
        VAL -->|Verify & Sign| DB_V2[(Vulnerabilities: Status='confirmed')]
    end

    subgraph "4. AI DEEP REASONING"
        DB_V2 -->|Fetch Confirmed| AI[AI Analyzer: Gemma]
        AI -->|Chain of Thought Reasoning| AI
        AI -->|Generate Fix & Risk Report| DB_V3[(Vulnerabilities: Status='analyzed')]
    end

    subgraph "5. ATTACK CHAIN & RED TEAM"
        DB_V3 -->|Fetch Analyzed| CHN[Chain Analyzer]
        CHN -->|Correlate Multiple Vulns| DB_C[(AttackChains Table)]
        DB_V2 -->|Informed Action| RT[Red Team Agent]
        RT -->|Lateral/Persistence| DB_RT[(Post-Exploit Logs)]
    end

    style NVD fill:#ffcc00,stroke:#333,stroke-width:2px
    style VAL fill:#f96,stroke:#333,stroke-width:4px
    style AI fill:#b026ff,stroke:#fff,stroke-width:2px
    style DB_V2 fill:#00e676,stroke:#333,stroke-width:2px
    style RT fill:#ff4444,stroke:#fff,stroke-width:2px
```

---

## 🛠️ Detailed Component Roles

### 0. Vulnerability Intelligence (Foundation)
The **Intelligence Collector** periodically synchronizes the local database with curated CWE patterns and attack signatures. This provides:
- **CWE Context**: Matching discovered services and behaviors to known weakness patterns.
- **Remediation Intelligence**: Providing developer-centric fixes based on established CWE mitigations.
- **Description Parsing**: AI-driven extraction of product info from raw CVE descriptions to improve fingerprinting.

### 1. The Scanner (Discovery)
The Scanner reads discovery data from the `ReconData` table. It performs non-destructive probes to find indicators of vulnerabilities. Any hit is logged as **`pending`**. At this stage, the finding is treated as a "Suspect."

### 2. The Validator (Execution)
The Validator is a high-confidence agent. It takes **`pending`** findings and attempts to re-execute the exploit using more aggressive or refined payloads. 
- **If the exploit succeeds**: The status is updated to **`confirmed`**.
- **If the exploit fails**: The status is updated to **`rejected`**.
This phase ensures that the final report has a **0% False Positive** rate.

### 3. The AI Analyzer (Intelligence)
The Analyzer uses **Gemma (Local LLM)** to perform deep reasoning on **`confirmed`** findings. It doesn't just restate the vulnerability; it performs a **Chain of Thought (CoT)** analysis to explain the specific business impact and provides a custom remediation plan. Once analysis is complete, the status is **`analyzed`**.

### 4. The Chain Analyzer (Strategy)
The final layer correlates independent `analyzed` findings. For example, it might link an *Information Disclosure* finding with a *Weak Authentication* finding to demonstrate a complete **Attack Path** from unauthenticated visitor to administrative access.

### 5. Red Team Operations (Post-Exploitation)
Triggered by confirmed high-severity vulnerabilities, these agents simulate adversarial behavior:
- **Lateral Movement**: Testing for credential reuse or service misconfigurations to pivot.
- **Persistence Auditing**: Identifying areas where an attacker could maintain long-term access.

---

## 📋 Data State Transitions

| Agent | Input State | Output State | Action |
| :--- | :--- | :--- | :--- |
| **NVD Collector** | API Source | Global Intel | Continuous Synchronization |
| **Scanner** | ReconData | `pending` | Initial Discovery |
| **Validator** | `pending` | `confirmed` / `rejected` | Active Verification |
| **AI Analyzer** | `confirmed` | `analyzed` | Risk Assessment & Remediation |
| **Chain Analyzer**| `analyzed` | Attack Chain | Strategic Correlation |
| **Red Team** | `confirmed` | Post-Exploit Evidence | Adversarial Simulation |
