# Sentinel-Prime — Build TODO List

Goal: a working lab-scale prototype demonstrating the full pipeline end-to-end (specialist ML detectors + LightGBM meta-correlation + Gemini AI agents + adaptive deception + deterministic execution).

## PHASE 1 — Offline Training Pipeline

- [x] **1.1 Define Common Evidence Object schema**
  Create `detectors/evidence_schema.py` defining the exact JSON structure that all 4 specialist detectors will output.
- [x] **1.2 Train Network LightGBM**
  Load CSE-CIC-IDS2018 (Parquet files). Train LightGBM on flow features. Upgraded to v2.1 Hierarchical Classifier with Evidence Bands.
- [x] **1.3 Train Identity / UEBA Isolation Forest**
  Load LANL Auth. Build behavioral windows. Upgraded to v2.1 User-Relative Timing and Traversal baselines to prevent low-activity anomaly dominance.
- [x] **1.4 Train Endpoint LightGBM + Sigma integration**
  Implemented OTRF ZIP crawlers, field mappers, 60s process windows, behavioral features, LightGBM classifier training, lightweight Sigma engine, and evidence fusion.
- [x] **1.5 Train OT / ICS Isolation Forest**
  Implemented HAI ZIP loading, timeseries normalizer, column classifier, 60s time-windows, rolling behavioral feature engineering, Isolation Forest model training, calibration scoring, and OTEvidence generation.
- [ ] **1.6 Train LightGBM Meta-Classifier**
  Generate scenarios. Run enabled detectors (Network, Identity) to get evidence objects. Train Meta-Classifier to correlate Network and Identity threat scores. Serialize to `data/models/meta_lightgbm.pkl`.
- [ ] **1.7 Build MITRE ATT&CK Hybrid Graph-RAG**
  Parse ATT&CK STIX 2.1. Embed using Sentence Transformer → FAISS index (`data/models/attack_faiss.index`). Build NetworkX Knowledge Graph from STIX relationships.

## PHASE 2 — Telemetry, SIEM, and Deception Setup

- [ ] **2.1 Configure SIEM**
  Set up Wazuh + Elasticsearch to receive logs from Windows/Linux VMs (Sysmon, auditd).
- [ ] **2.2 Baseline Store**
  Implement `ingestion/baseline_store.py` (SQLite-backed Welford's algorithm) to track rolling entity baselines.
- [ ] **2.3 Deploy Honeytokens (Passive)**
  Create and deploy bait files (using dot-prefix on Linux, `attrib +H` on Windows) and Conpot (OT). Wire webhook receiver (`honeypots/webhook_receiver.py`) to push events to SIEM.

## PHASE 3 — Runtime Pipeline Implementation (The 17 Stages)

- [ ] **3.1 Specialist Detectors (Stages 3-4)**
  Implement runtime wrappers for the 4 ML models to ingest live SIEM events and output Common Evidence Objects.
- [ ] **3.2 Cyber Entity Graph (Stage 5)**
  Implement `correlation/cyber_entity_graph.py` (NetworkX) updating from SIEM events.
- [ ] **3.3 Statistical Correlation (Stage 6)**
  Implement runtime execution of the LightGBM Meta-Classifier.
- [ ] **3.4 AI Correlation & Hypothesis Agents (Stages 7-9)**
  Connect Gemini Flash. Build `correlation_agent.py` and `hypothesis_agent.py` with prompts integrating FAISS+Graph RAG context.
- [ ] **3.5 AI Attack Prediction Agent (Stage 10)**
  Build `prediction_agent.py` to estimate next ATT&CK stage, technique, and target.
- [ ] **3.6 AI Adaptive Deception (Stages 11-12)**
  Implement logic for moderate scores (0.4–0.74). Build `deception_agent.py` to select testable uncertainties, deploy graph-guided decoys via `decoy_deployer.py`, and process feedback loops.
- [ ] **3.7 AI Response Planning (Stage 13)**
  Build `response_agent.py` to propose containment actions without executing them.
- [ ] **3.8 Risk & Dry-Run (Stage 14)**
  Implement `risk_scoring/scorer.py` (Composite score = α×Containment − β×Impact) and `orchestrator/dry_run.py`.
- [ ] **3.9 Policy Authorization & Orchestration (Stage 15)**
  Build `orchestrator/policy_gate.py` (confidence ≥0.75 + low blast radius) and wire dummy SOAR actions.
- [ ] **3.10 Outcome Monitoring (Stage 16)**
  Implement `monitoring/outcome_monitor.py` to re-check entities and feed back to baselines/escalation.
- [ ] **3.11 Audit Ledger (Stage 17)**
  Implement `ledger/audit_ledger.py` (SHA-256 hash chain) logging all decisions.

## PHASE 4 — Dashboard & Benchmarking

- [ ] **4.1 SOC Dashboard**
  Build React frontend showing hypothesis ladder, TTP map, alert feed, and action timeline.
- [ ] **4.2 Benchmarking**
  Run Caldera/Atomic Red Team. Measure TP/FP rates, ATT&CK attribution accuracy, MTTD/MTTR vs manual baseline, and automation coverage. Document in `docs/benchmarks/`.