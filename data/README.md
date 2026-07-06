# Data — Datasets, Models, and Training Pipeline

Holds raw datasets, preprocessed data, trained model artifacts, and the offline training scripts.

## Directory Structure

```
data/
├── raw/                         # Original unmodified datasets (git-ignored)
│   ├── cse-cic-ids2018/         # CSE-CIC-IDS2018 network flow CSVs
│   ├── splunk-bots/             # Splunk BOTS v2/v3 export
│   ├── lanl-auth/               # LANL Authentication dataset
│   ├── swat/                    # SWaT OT/ICS dataset
│   └── attack-stix/             # MITRE ATT&CK STIX JSON bundle
├── processed/                   # Preprocessed train/test splits (git-ignored)
│   ├── X_train.parquet
│   ├── X_test.parquet
│   ├── y_train.parquet
│   └── y_test.parquet
├── models/                      # Trained model artifacts (Phase 1A output)
│   ├── isolation_forest.pkl     # Unsupervised anomaly scorer
│   ├── xgboost_classifier.json  # Supervised attack classifier
│   ├── attack_faiss.index       # FAISS vector DB of ATT&CK TTPs
│   ├── attack_metadata.json     # Technique IDs + descriptions for FAISS index
│   └── baseline_thresholds.json # Entropy + z-score threshold configs
├── training/                    # Offline training pipeline scripts
│   ├── __init__.py
│   ├── preprocessing.py         # Load → clean → encode → SMOTE → scale → split
│   ├── train_isolation_forest.py
│   ├── train_xgboost.py
│   ├── build_faiss_index.py     # Embed ATT&CK STIX → FAISS index
│   └── validate_models.py       # Run trained models against test set, print metrics
├── scripts/                     # Utility scripts
│   ├── __init__.py
│   ├── verify_datasets.py       # Confirm row counts, column schemas, basic stats
│   └── download_attack_stix.py  # Pull latest ATT&CK STIX bundle
├── README.md
└── audit_ledger.jsonl           # Hash-chained audit log (runtime output)
```

## Datasets

| Dataset | Purpose | Key caveats |
|---|---|---|
| **CSE-CIC-IDS2018** | Network flows: normal + labeled attacks (80+ features) | ~7.5% label noise — use BOTS as primary benchmark |
| **Splunk BOTS v2/v3** | Multi-stage APT scenarios (ransomware, web attacks) | Human-verified ground truth — primary benchmark |
| **LANL Auth** | 58 days of authentication events, 5 sources | De-identified but consistently anonymized |
| **SWaT** | OT/ICS: 495K normal + 449K attack records, 51 attributes | Physical testbed data from iTrust/SUTD |
| **MITRE ATT&CK STIX** | TTP descriptions for FAISS vector DB | Enterprise + ICS matrices |

## Model Artifacts (Phase 1A output)

| File | Trained on | Used by |
|---|---|---|
| `isolation_forest.pkl` | Normal-only traffic from CIC-IDS2018 + LANL Auth | Auth anomaly detector (2.5a) |
| `xgboost_classifier.json` | Labeled CIC-IDS2018 + BOTS data | Process lineage detector (2.5b) |
| `attack_faiss.index` | ATT&CK STIX technique descriptions | Hypothesis agent + APT attribution |
| `baseline_thresholds.json` | Configured during Phase 1A | Entropy + z-score detectors |
