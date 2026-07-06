# Detectors — Detection Agents

Focused detection agents backed by trained ML models (from Phase 1A) and deterministic rules that continuously score SIEM events for specific threat categories.

## Directory Structure

```
detectors/
├── __init__.py
├── signal_schema.py             # Unified signal output dataclass/schema
├── sigma_detector.py            # pySigma rule engine for deterministic patterns
├── entropy_detector.py          # Shannon entropy on file content (before/after)
├── mass_activity_detector.py    # Write-rate anomaly via BaselineStore z-score
├── integrity_detector.py        # FIM hash comparison (SHA-256)
├── auth_anomaly_detector.py     # Isolation Forest on auth log features
├── process_lineage_detector.py  # XGBoost/RF for suspicious process chains
├── beaconing_detector.py        # FFT periodicity + DBSCAN on connection intervals
├── sigma_rules/                 # Compiled Sigma rule YAML definitions
│   ├── shadow_copy_deletion.yml
│   ├── encoded_powershell.yml
│   ├── ransomware_notes.yml
│   └── lolbin_chains.yml
└── README.md
```

## Detection Agents

| Agent | Model / Approach | What it detects |
|---|---|---|
| **Sigma Rules** | pySigma (deterministic) | Shadow copy deletion, encoded PowerShell, ransomware-note filenames, LOLBin chains |
| **File Entropy** | Shannon entropy (mathematical) | Entropy spikes indicating encryption (plaintext → ciphertext) |
| **Mass File Activity** | Z-score via BaselineStore (statistical) | Write-rate anomalies vs. entity baseline |
| **Corruption/Integrity** | SHA-256 hash comparison (deterministic) | Unexpected hash mismatches on watched files |
| **Auth Anomaly** | Isolation Forest (unsupervised ML) | Impossible-travel logins, odd-hour access |
| **Process Lineage** | XGBoost / Random Forest (supervised ML) | Suspicious process trees (Office → shell → network) |
| **Beaconing** | FFT + DBSCAN (signal processing + clustering) | Regular-interval outbound connections (C2 beaconing) |

## Unified Signal Schema

Every detector outputs:

```json
{
  "entity": "user@host",
  "signal_type": "sigma | entropy | mass_activity | integrity | auth_anomaly | process_lineage | beaconing",
  "confidence": 0.0 - 1.0,
  "evidence": { ... },
  "timestamp": "ISO-8601"
}
```

## Model Artifacts (loaded from `data/models/`)

| File | Used by |
|---|---|
| `isolation_forest.pkl` | `auth_anomaly_detector.py` |
| `xgboost_classifier.json` | `process_lineage_detector.py` |
| `baseline_thresholds.json` | `entropy_detector.py`, `mass_activity_detector.py` |
| `sigma_rules/*.yml` | `sigma_detector.py` |
