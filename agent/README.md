# Agent — 5 Constrained AI Agents (Gemini Flash)

Five logically separate AI agents, all powered by Gemini Flash with distinct prompts, restricted tasks, and structured JSON output schemas.

## Directory Structure

```
agent/
├── __init__.py
├── base_agent.py            # Shared Gemini Flash client, JSON schema enforcement
├── correlation_agent.py     # Cross-domain incident story generation
├── hypothesis_agent.py      # Competing malicious + benign hypothesis ranking
├── prediction_agent.py      # Next-stage, technique, target, and path prediction
├── deception_agent.py       # Testable uncertainty → decoy type + placement
├── response_agent.py        # ATT&CK-grounded containment candidate planning
├── tools.py                 # Callable tools for structured data retrieval
├── prompts.py               # System prompt templates per agent
└── README.md
```

## The 5 Agents

| Agent | Input | Output |
|---|---|---|
| **Correlation** | Evidence + graph + threat score + ATT&CK context | Cross-domain incident story linking identity, endpoint, network, OT |
| **Hypothesis** | Incident story + evidence + ATT&CK context | 2–4 ranked hypotheses (including benign) with confidence + evidence |
| **Prediction** | Hypotheses + ATT&CK RAG + graph + asset criticality | Current stage, next stage, next technique, likely target, attack path |
| **Deception** | Uncertain hypothesis + prediction + graph topology | Decoy type, placement location, observation window |
| **Response** | Hypotheses + prediction + ATT&CK mitigations + SOAR allowlist | Ranked containment candidates with reason + expected impact |

## Tools

| Tool | What it queries |
|---|---|
| `get_entity_baseline(entity_id)` | BaselineStore — rolling mean/std for entity |
| `query_attack_technique(description)` | FAISS + ATT&CK Knowledge Graph — semantic + structural retrieval |
| `check_honeypot_interactions(entity_id, window)` | Honeytoken registry — passive + adaptive events |
| `get_graph_context(entity_id, hops)` | Cyber Entity Graph — ego graph, centrality, paths |
| `get_asset_criticality(asset_id)` | Asset registry — criticality score + dependencies |

## Key Design Decision

Gemini Flash is **not the primary detector**. It receives pre-correlated evidence (from ML models) plus retrieved ATT&CK context (from Hybrid Graph-RAG). The AI reasons over structured evidence — it does not process raw logs.