# Data — Datasets, Models, and Training Pipeline

Holds raw datasets, preprocessed data, trained model artifacts, and the offline training scripts.

## Directory Structure

```
data/
├── raw/                         # Original unmodified datasets (git-ignored)
│   ├── cse-cic-ids2018/         # Network flow CSVs (80 features)
│   ├── lanl-auth/               # LANL 708M+ authentication events
│   ├── splunk-bots/             # Splunk BOTS v3 export
│   ├── mordor/                  # OTRF Security Datasets / Mordor
│   ├── hai/                     # HAI ICS testbed dataset
│   └── attack-stix/             # MITRE ATT&CK STIX 2.1 JSON bundle
├── processed/                   # Preprocessed train/test splits (git-ignored)
├── models/                      # Trained model artifacts (git-ignored)
│   ├── network_lightgbm.pkl     # Network flow classifier
│   ├── identity_iforest.pkl     # Identity/UEBA anomaly scorer
│   ├── endpoint_lightgbm.pkl    # Endpoint behavior classifier
│   ├── ot_iforest.pkl           # OT/ICS process anomaly scorer
│   ├── meta_lightgbm.pkl        # Meta-classifier for signal correlation
│   ├── attack_faiss.index       # FAISS vector DB of ATT&CK TTPs
│   └── attack_metadata.json     # Technique IDs + descriptions for FAISS
├── training/                    # Offline training pipeline
│   ├── __init__.py
│   ├── evidence_schema.py       # Common Evidence Object definition
│   ├── train_network.py         # LightGBM on CIC-IDS2018
│   ├── train_identity.py        # Isolation Forest on LANL UEBA windows
│   ├── train_endpoint.py        # LightGBM on BOTS + Mordor features
│   ├── train_ot.py              # Isolation Forest on HAI sensor windows
│   ├── train_meta_classifier.py # LightGBM on synchronized cyber-range evidence
│   ├── build_faiss_index.py     # ATT&CK STIX → Sentence Transformer → FAISS
│   ├── build_attack_graph.py    # ATT&CK STIX → NetworkX Knowledge Graph
│   └── validate_models.py       # Run models against test sets, print metrics
├── scripts/                     # Utility scripts
│   ├── __init__.py
│   ├── verify_datasets.py       # Confirm row counts, column schemas, stats
│   └── download_attack_stix.py  # Pull latest ATT&CK STIX bundle
├── README.md
└── audit_ledger.jsonl           # Hash-chained audit log (runtime output)
```

## Datasets

| Dataset | Behaviour | Key details |
|---|---|---|
| **CSE-CIC-IDS2018** | Network | 80 CICFlowMeter features, labeled attacks |
| **LANL Auth** | Identity / UEBA | 708M+ auth events, 58 days, de-identified |
| **Splunk BOTS v3** | Endpoint | Multi-stage APT/ransomware SOC investigation |
| **OTRF Mordor** | Endpoint | Adversarial host/network telemetry |
| **HAI** | OT / ICS | Steam-turbine + hydropower ICS testbed |
| **ATT&CK STIX 2.1** | Threat knowledge | Enterprise + ICS matrices |

## Training Strategy

```
1. Train Network LightGBM (CIC-IDS2018)
2. Build LANL UEBA windows → train Identity Isolation Forest
3. Build endpoint features + Sigma → train Endpoint LightGBM (BOTS + Mordor)
4. Build HAI sensor windows → train OT Isolation Forest
5. Build cyber-range scenarios → train Meta-Classifier on synchronized evidence
6. ATT&CK STIX → Sentence Transformer → FAISS + Knowledge Graph
```
