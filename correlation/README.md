# Correlation — Signal Fusion, ATT&CK RAG, APT Attribution

Builds a graph of entity interactions, fuses detector signals into composite anomaly scores, maps hypotheses to MITRE ATT&CK via FAISS, and performs APT attribution with next-stage prediction.

## Directory Structure

```
correlation/
├── __init__.py
├── graph_builder.py         # NetworkX graph from SIEM events (sliding window)
├── correlator.py            # Threat Correlation Engine — signal fusion
├── attack_rag.py            # FAISS vector DB — embed/query ATT&CK techniques
├── apt_attribution.py       # TTP chain mapping + next-stage prediction
└── README.md
```

## Components

### Threat Correlation Engine (`correlator.py`)
Fuses raw detector signals into a composite anomaly score per entity:
- Anomaly scores (Isolation Forest)
- Attack class predictions (XGBoost)
- ATT&CK TTP matches (FAISS query)
- Co-occurrence analysis (multiple signals in a time window)
- Honeypot flags (passive/adaptive → max confidence boost)

Output: composite score → routes to adaptive deception (0.4–0.74) or hypothesis generation (≥0.75).

### Graph Builder (`graph_builder.py`)
- Nodes: users, hosts, processes, IPs
- Edges: observed interactions within a sliding time window
- Supports 2-hop `ego_graph` queries for lateral-movement context

### ATT&CK RAG (`attack_rag.py`)
- Loads the FAISS index built in Phase 1A
- Queries: signal description → top-k matching ATT&CK techniques
- Used by both the hypothesis agent and APT attribution

### APT Attribution (`apt_attribution.py`)
- Maps leading hypothesis to known threat actor TTP chains
- Predicts likely next technique based on observed progression
- Uses NetworkX 2-hop ego graph for lateral-movement context
