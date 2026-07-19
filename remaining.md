# Current Focus

The project has reached the stage where **most of the routing pipelines and SOAR integrations (Sprint 1) are complete**, and the **Core Architectural Components (Meta-Classifier and Audit Ledger)** have been successfully implemented. 

However, a deep cross-check against `ARCHITECTURE.md` reveals that a few critical integrations and dashboard features are still missing.

The remaining work is primarily:
- Filling runtime pipeline gaps (Continuous Execution & Closed-Loop Verification)
- Dashboard Polish (Live Monitoring, Cyber Graph, Timeline)
- FastAPI Migration & Production Readiness
- Advanced AI Features

---

# 🔴 MUST COMPLETE BEFORE HACKATHON

---

## 1. Missing Runtime Pipeline Features

### Continuous Execution & Closed-Loop Verification
- **What it is:** The architecture requires an asynchronous task queue (Celery/APScheduler) or a Kafka/FastAPI streaming webhook to transition incidents to `VERIFICATION_PENDING` and check the SIEM 5 minutes after a SOAR action.
- **Status:** The system currently relies on a static, one-shot demonstration wrapper (`run_phase1.py`) and simple sync checks.
- **Requirement:** Implement the asynchronous deferred verification task loop.

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
**DONE:** Display the output of the 3 AI agents in real-time via WebSockets/SSE on the frontend `AIReasoning.tsx` page.

---

# 🟡 SHOULD COMPLETE

---

## 1.5 Codebase Technical Debt

### Resolve Frontend Split-Brain
**DONE:** `dashboard/app.py` (Streamlit) has been deleted. The React SPA at `dashboard/frontend/` is now the sole official interface.

### Migrate Flask API to FastAPI & Unified Backend
The `README.md` and `ARCHITECTURE.md` explicitly mandate a "Unified FastAPI Backend". However, the `dashboard/api_server.py` is written in Flask. We must rewrite the API server in FastAPI to align with the documentation.
Instead of multiple services exposing independent endpoints, create a single FastAPI gateway: `Frontend → FastAPI → Internal Services`

---

## 2. Infrastructure & APIs (Sprint 3)

### AI-Driven Adaptive Deception (Active Decoys)
**DONE:** Phase 5 of the architecture. The Action Agent actively selects a decoy, places it via a `decoy_deployer.py` and it is reflected on the frontend.

### Human Approval Queue
**DONE:** A manual validation UI where high-risk actions wait for a human operator to click "Approve" before execution exists on `/approval-queue`.

### Secure Webhooks
**DONE:** Authentication (API Keys) and Rate limiting for the honeypot webhook receiver have been implemented.

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
**DONE:** Incident memory has been injected into the context via `IncidentStateDB().get_recent_memory()`.

### Feedback Loop
**DONE:** Feed the outcome of SOAR actions back into the Evidence Bus so the AI is aware if its containment succeeded or failed, creating a true closed-loop defense.

### D3FEND Integration
Enhance the MITRE ATT&CK RAG with MITRE D3FEND for improved, standardized defensive recommendations.