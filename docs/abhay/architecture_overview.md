# Architecture Overview

## Core Design Principle
The Sentinel-Prime architecture is guided by a clear boundary between machine learning, artificial intelligence, and deterministic execution:
- **ML** detects measurable behavior from telemetry.
- **AI Agents** reason about the correlated context, generate hypotheses, predict attacks, and plan responses.
- **Deterministic logic** controls execution and enforces policy.
The LLM never directly executes containment actions.

## Pipeline Phases
1. **Telemetry & SIEM**: Data from network, endpoints, identities, and OT (e.g., Elasticsearch).
2. **Specialist ML Detectors**: Domain-specific anomaly detection models (e.g., LightGBM for Network, Isolation Forest for Identity/OT).
3. **Correlation & Threat Knowledge**: Normalization into a Common Evidence Object, integration into the Cyber Entity Graph, scoring via a Meta-Classifier, and enrichment with MITRE ATT&CK Graph-RAG.
4. **AI Reasoning**: 5 specialized Gemini Flash agents construct incident stories, hypotheses, predictions, and response plans.
5. **Adaptive Deception**: AI-driven deployment of honeypots to test uncertain hypotheses.
6. **Response & Orchestration**: Deterministic risk scoring and dry-run simulations before SOAR auto-execution or human approval.
7. **Monitoring & Ledger**: Outcomes feed back into the system to adjust baselines and maintain a tamper-evident audit trail.
