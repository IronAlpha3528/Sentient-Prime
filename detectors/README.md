# Detectors — Specialist Behavioral ML Models

Four specialist ML detectors, one per behavioral layer, each producing structured evidence for the Common Evidence Object.

## Directory Structure

```
detectors/
├── __init__.py
├── evidence_schema.py           # Common Evidence Object dataclass
├── network_detector.py          # LightGBM — network flow classification
├── identity_detector.py         # Isolation Forest — UEBA auth anomaly
├── endpoint_detector.py         # LightGBM + Sigma — endpoint behavior
├── ot_detector.py               # Isolation Forest — OT/ICS process anomaly
├── sigma_engine.py              # pySigma rule engine (used by endpoint detector)
├── sigma_rules/                 # Sigma rule YAML definitions
│   ├── shadow_copy_deletion.yml
│   ├── encoded_powershell.yml
│   ├── ransomware_notes.yml
│   └── lolbin_chains.yml
└── README.md
```

## Specialist Detectors

| Detector | Model | Dataset | Key Features |
|---|---|---|---|
| **Network** | LightGBM | CSE-CIC-IDS2018 | `flow_duration`, `total_fwd/bwd_packets`, `flow_bytes/packets_per_sec`, `flow_iat_mean/std`, `TCP_flag_counts`, `destination_port`, `protocol` |
| **Identity / UEBA** | Isolation Forest | LANL Auth | `login_hour_deviation`, `auth_frequency_1h/24h`, `unique_hosts_1h/24h`, `new_host_ratio`, `destination_fanout`, `peer_group_deviation` |
| **Endpoint / SIEM** | LightGBM + Sigma | BOTS v3 + Mordor | `powershell_execution`, `encoded_command`, `rare_process_score`, `process_tree_depth`, `office_child_process`, `sigma_match_count` |
| **OT / ICS** | Isolation Forest | HAI | `sensor_mean/std/rate_of_change`, `pressure_rate_change`, `setpoint_deviation`, `actuator/pump/valve_switch_count` |

## Evidence Output Examples

### Network
```json
{"network_score": 0.91, "attack_class": "infiltration", "attack_probabilities": {"benign": 0.03, "infiltration": 0.87}, "confidence": 0.94}
```

### Identity
```json
{"identity_score": 0.88, "user": "U101", "new_hosts": 12, "lateral_movement_signal": 0.79, "confidence": 0.90}
```

### Endpoint
```json
{"endpoint_score": 0.97, "process_chain": ["WINWORD.EXE", "powershell.exe", "rundll32.exe"], "sigma_matches": ["Encoded PowerShell"], "candidate_techniques": ["T1059.001", "T1218"], "confidence": 0.95}
```

### OT
```json
{"ot_score": 0.96, "affected_variables": ["pressure", "flow"], "process_deviation": {"pressure": 6.2, "flow": -37.0}, "confidence": 0.97}
```

## Model Artifacts (loaded from `data/models/`)

| File | Used by |
|---|---|
| `network_lightgbm.pkl` | `network_detector.py` |
| `identity_iforest.pkl` | `identity_detector.py` |
| `endpoint_lightgbm.pkl` | `endpoint_detector.py` |
| `ot_iforest.pkl` | `ot_detector.py` |
