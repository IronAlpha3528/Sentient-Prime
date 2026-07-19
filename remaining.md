# Current Focus

The project has reached the stage where **most of the routing pipelines and SOAR integrations (Sprint 1) are complete**, but a deep cross-check against `ARCHITECTURE.md` reveals that a few critical core components are still missing.

The remaining work is primarily:
- Filling backend gaps (Meta-Classifier & Audit Ledger)
- Dashboard (Sprint 2)
- Infrastructure & APIs (Sprint 3)
- Production readiness (Sprint 4)

---

# 🔴 MUST COMPLETE BEFORE HACKATHON

---

## 1. Missing Core Architectural Components (Sprint 1.5 - Immediate Priority)

A review of the `ARCHITECTURE.md` against the codebase reveals that two major components are designed but missing their implementation files:

### LightGBM Meta-Classifier (`src/sentinel_prime/detection/correlation/meta_classifier.py`)
- **What it is:** Phase 3 of the architecture. It combines specialist detector scores, graph features, and deception evidence into a `unified_threat_score`.
- **Status:** The README in `correlation/` mentions it, but the file doesn't exist. The AI agents currently rely on hardcoded or pass-through scores instead of the meta-classifier's statistical correlation.
- **Requirement:** Build the LightGBM classifier that fuses evidence bands and graph centrality metrics.

### Tamper-Evident Audit Ledger (`src/sentinel_prime/core/telemetry/ledger/audit_ledger.py`)
- **What it is:** Phase 7 of the architecture. A SHA-256 hash chain that immutably logs every hypothesis, risk score, and SOAR action.
- **Status:** The `ledger/` directory has an `__init__.py` and a `README.md`, but `audit_ledger.py` is missing.
- **Requirement:** Build the hash-chain logging mechanism. We need this to satisfy the **Auditability** evaluation metric!

---

## 2. Dashboard (Sprint 2)

The backend is largely operational and seamlessly routes from ingestion to SOAR execution. However, judges will mostly evaluate the demonstration. The dashboard must make the AI's internal reasoning visible.

The dashboard should include:

### Live Monitoring
- Incoming telemetry
- Active incidents
- Evidence Bus throughput

### Cyber Graph Visualization
- Interactive view of the `NetworkX` Cyber Graph
- Nodes (Hosts, Users, PLCs) and their relationships
- Highlighting of suspicious entities

### Incident Timeline
- A chronological timeline of events leading to an incident

### AI Reasoning Panel
- Display the output of the 5 AI agents in real-time:
  - Correlation Story
  - Hypotheses (with confidence)
  - Predictions (MITRE techniques, likely target)
  - Deception strategy
  - Response recommendations

---

# 🟡 SHOULD COMPLETE

---

## 1.5 Codebase Technical Debt

### Resolve Frontend Split-Brain
The repository currently contains both `dashboard/app.py` (a Streamlit dashboard) and `dashboard/frontend/` (a React dashboard). This duplication creates confusion over which is the official interface and splits development efforts. The Streamlit app should be deleted.

### Migrate Flask API to FastAPI
The `README.md` and `ARCHITECTURE.md` explicitly mandate a "Unified FastAPI Backend". However, the `dashboard/api_server.py` is written in Flask. We must rewrite the API server in FastAPI to align with the documentation.

---

## 2. Infrastructure & APIs (Sprint 3)

### Unified FastAPI Backend
Instead of multiple services exposing independent endpoints, create a single FastAPI gateway:
`Frontend → FastAPI → Internal Services`

### Human Approval Queue
Currently, the AI automatically evaluates and routes through SOAR via the `policy_gate`. We need a manual validation UI where high-risk actions wait for a human to click "Approve" before execution.

### Secure Webhooks
Implement Authentication, TLS, API Keys, and Rate limiting for the honeypot webhook receiver.

---

## 3. Production Readiness (Sprint 4)

### Full Docker Support
Expand the `docker-compose.yml` to launch the entire platform (`API, SIEM, Database, ML Workers`) with a single command.

### Central Configuration Manager
Create a unified `ConfigManager` to load settings, rather than each module loading YAML independently.

### Fix Remaining Tests
Resolve ImportErrors in old tests and ensure `pytest` passes successfully across the entire codebase to validate evaluation metrics (Detection Rate, FPR, Attribution Accuracy, etc).

---

# 🟢 NICE TO HAVE

---

## 4. Advanced AI Features (Sprint 5)

### Incident Memory
Instead of AI agents passing information sequentially, have every AI agent read and update a shared persistent `Incident Memory` object to make reasoning significantly more coherent across multiple events.

### Feedback Loop
Feed the outcome of SOAR actions (e.g., "Host Isolated") back into the Evidence Bus so the AI is aware if its containment succeeded or failed, creating a true closed-loop defense.

### D3FEND Integration
Enhance the MITRE ATT&CK RAG with MITRE D3FEND for improved, standardized defensive recommendations.