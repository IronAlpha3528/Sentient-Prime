# Correlation — Meta-Classifier, Cyber Entity Graph, ATT&CK Graph-RAG

Statistical signal correlation via LightGBM Meta-Classifier, live entity graph for attack-path analysis, and Hybrid ATT&CK Graph-RAG for threat knowledge retrieval.

## Directory Structure

```
correlation/
├── __init__.py
├── cyber_entity_graph.py    # NetworkX graph of users/hosts/processes/IPs/OT assets
├── graph_features.py        # Extract attack-path, centrality, blast-radius features
├── meta_classifier.py       # LightGBM meta-classifier — combines detector + graph + deception evidence
├── attack_rag.py            # FAISS semantic retrieval of ATT&CK techniques
├── attack_knowledge_graph.py # ATT&CK STIX → NetworkX knowledge graph (tactic→technique→software→group)
├── apt_attribution.py       # TTP chain mapping + next-stage prediction
└── README.md
```

## Components

### Cyber Entity Graph (`cyber_entity_graph.py`)
- **Nodes:** users, hosts, processes, IPs, critical OT assets
- **Edges:** observed interactions within a sliding time window
- Updated continuously from SIEM events
- Supports ego graph queries, shortest-path, centrality, community detection

### Graph Features (`graph_features.py`)
Extracted from the Cyber Entity Graph for each incident entity:
- `attack_path_length`, `hop_count_to_critical_asset`, `node_centrality`
- `community_crossing_count`, `blast_radius_estimate`
- `unique_host_count`, `ot_reachability`

### LightGBM Meta-Classifier (`meta_classifier.py`)
Combines all evidence into a unified threat score:
```
Inputs: network_score, identity_score, endpoint_score, ot_score,
        sigma_match_count, graph_features, honeypot_touched,
        event_velocity, asset_criticality
        ↓
Output: unified_threat_score (0.0 – 1.0), severity, evidence_contribution breakdown
```
Trained on synchronized scenarios from an isolated cyber range — NOT by row-wise merging the public datasets.

### ATT&CK Hybrid Graph-RAG (`attack_rag.py` + `attack_knowledge_graph.py`)
- **FAISS semantic**: "What ATT&CK knowledge is semantically similar to this evidence?"
- **Knowledge Graph structural**: "What tactics, techniques, software, and mitigations are structurally related?"
- Combined context bundle is attached to every AI agent's input

### APT Attribution (`apt_attribution.py`)
- Maps leading hypothesis to known TTP chains
- Predicts likely next technique and target
- Uses Cyber Entity Graph for lateral-movement context
