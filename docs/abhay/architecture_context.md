# Sentinel-Prime Architecture Context

This document provides a comprehensive overview of the Sentinel-Prime architecture, its structure, components, and data flows, based on the current implementation and documentation in the repository.

## 1. Folder Structure

The project follows a standard modern Python layout:

- `src/sentinel_prime/`: Main application source code.
  - `core/`: Fundamental framework components, including `EvidenceBus`, `Cyber Knowledge Graph`, and Unified Evidence schemas (Network, Endpoint, Identity, OT).
  - `ai/`: Implementations of the five constrained Gemini Flash agents (Correlation, Hypothesis, Prediction, Deception, Response), and the Graph-RAG components.
  - `detection/`: Specialist machine learning models (Isolation Forest, LightGBM) for domain-specific behavioral detection.
  - `simulation/`: Risk scoring engine and dry-run simulators to evaluate the impact of containment actions.
  - `soar/`: Orchestration logic, phase 1 pipelines, and deterministic policy gates that integrate with the evidence bus to execute responses.
- `docs/`: Extensive design documentation, covering the unified evidence framework, graphs, schemas, and ML specialist benchmarks.
- `config/`: Configuration files (e.g., `topology.yaml`, `risk_params.yaml`) defining the network structure, asset criticality, and risk parameters.
- `tests/`: Unit and integration test suites using `pytest`.
- `data/` & `models/`: Storage for datasets and trained ML models.

## 2. Major Components

The system is designed as a multi-stage pipeline separating detection, reasoning, and execution:

- **Specialist ML Detectors**: Domain-specific models handling individual telemetry streams:
  - Network: LightGBM
  - Identity / UEBA: Isolation Forest
  - Endpoint / SIEM: LightGBM + Sigma rules
  - OT / ICS: Isolation Forest
- **Unified Evidence Framework (UEF)**: A thread-safe `EvidenceBus` that validates, deduplicates (via SHA-256 caching), normalizes, and queues detector outputs into a single `BaseEvidence` schema.
- **Cyber Entity Graph**: An incremental graph storage (NetworkX) holding entities (Users, Hosts, IPs, Processes, PLCs) and interactions to calculate centrality, blast-radius, and connection features.
- **Threat Correlation**: A LightGBM Meta-Classifier that takes features from the Cyber Graph and individual evidence objects to generate a unified threat score.
- **MITRE ATT&CK Hybrid Graph-RAG**: Uses FAISS for semantic similarity search over ATT&CK techniques, and NetworkX to traverse structural relationships (Tactics → Techniques → Sub-techniques → Mitigations).
- **Constrained AI Reasoning Core**: 5 distinct Gemini Flash agents, each responsible for a specific reasoning step. They process JSON and output strictly structured JSON.
- **Adaptive Deception**: An agent that actively places honeytokens (hidden files) or decoys based on graph-predicted attack paths to test uncertain hypotheses.
- **Deterministic Policy Gate & SOAR**: Contains business-logic gates that use math (not LLMs) to decide whether to execute containment playbooks or require human approval.

## 3. Architecture

Sentinel-Prime is a hybrid AI-centric platform built on the principle that **ML detects measurable behavior**, while **AI agents reason about the context**, and **Deterministic rules execute actions**.

The architecture transitions from high-volume, low-context data (telemetry) to low-volume, high-context insights (AI hypotheses), ensuring that the LLM is only invoked when high-quality, pre-correlated evidence is available. AI output is heavily constrained and decoupled from live execution mechanisms.

## 4. Data Flow

1. **Telemetry & Sensing**: Sysmon, Zeek, AD logs, and Modbus telemetry are ingested and normalized (e.g., by Wazuh/Elasticsearch).
2. **ML Detection**: Specialist models generate anomaly scores and structured domain evidence.
3. **Evidence Normalization**: Data enters the `EvidenceBus`, forming the **Common Evidence Object**. Entities are extracted to update the Cyber Entity Graph.
4. **Statistical Correlation**: Graph features and evidence are scored by the Meta-Classifier.
5. **Graph-RAG Enrichment**: If the score exceeds a threshold, relevant MITRE ATT&CK context is retrieved using FAISS and NetworkX.
6. **AI Agent Reasoning**:
   - **Correlation Agent**: Generates an incident story.
   - **Hypothesis Agent**: Proposes malicious and benign hypotheses.
   - **Prediction Agent**: Predicts the next technique/target.
   - **Deception Agent**: (Optional) If uncertainty is high but the score is moderate, deploys a decoy to force a high-confidence signal.
   - **Response Agent**: Proposes containment strategies.
7. **Execution**: The Deterministic Risk Engine calculates business impact. The Policy Gate decides whether to auto-execute via SOAR or route to a Human Approval Queue.

## 5. APIs

- **Dashboard / API Layer**: Built using Flask (`flask` and `flask-socketio`) to serve the web dashboard and provide REST/WebSocket endpoints. This allows real-time visualization of evidence streams, AI hypotheses, graph updates, and system decisions.
- **Internal APIs**: The system uses a publish-subscribe pattern via the `EvidenceBus` internally.

## 6. Database Schema

- **SIEM / Event Storage**: Elasticsearch (`docker-compose.yml`) stores normalized telemetry and audit ledgers.
- **Vector Database**: FAISS (local/in-memory) stores semantic embeddings of MITRE ATT&CK STIX 2.1 data (via `sentence-transformers`).
- **Graph Databases**: NetworkX is used in memory for both the Cyber Entity Graph (dynamic incident topology) and the ATT&CK Knowledge Graph (static threat knowledge).
- **Cache**: In-memory SHA-256 deduplication cache used by the Evidence Bus to prevent processing redundant events.

## 7. External Services

- **Elasticsearch**: Runs locally via Docker Compose for SIEM capabilities.
- **Google Gemini API**: Utilizes `google-generativeai` SDK to interface with Gemini Flash models for the 5 reasoning agents.

## 8. Build Process

- Managed via standard Python packaging with `pyproject.toml` and `setuptools.build_meta`.
- Dependencies include `pandas`, `numpy`, `networkx`, `scikit-learn`, `xgboost`, `lightgbm`, `faiss-cpu`, `sentence-transformers`, `pySigma`, and web libraries like `flask`.
- Contains optional development dependencies (`pytest`, `pytest-cov`, `ruff`) for linting and testing.
- The project targets Python 3.10+.

## 9. Important Design Patterns

- **Pub/Sub Evidence Bus**: Decouples specialist detectors from downstream correlators and AI agents.
- **Constrained AI Output**: The LLM is restricted via structured JSON schemas, prompt engineering, and strict boundary scopes to prevent hallucinations.
- **AI-Driven Active Hypothesis Testing**: Instead of passively waiting, the system takes safe, graph-guided actions (deception) to confirm uncertain suspicions.
- **Dry-Run Simulation**: Proposed actions are simulated against a topological model to quantify blast radius before execution.
- **Deterministic Action Gate**: A hardcoded, math-based rule engine ensures the LLM never executes destructive containment autonomously.
