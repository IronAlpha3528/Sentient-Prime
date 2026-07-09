# Phase 1 Implementation Added to the Existing Repository

This implementation deliberately follows the repository's existing module layout instead of introducing a second project structure.

## What existed before

The repository already had the architectural modules:

- `ingestion/`
- `detectors/`
- `correlation/`
- `agent/`
- `honeypots/`
- `orchestrator/`
- `risk_scoring/`
- `monitoring/`
- `ledger/`
- `dashboard/`
- `data/`

It also already contained the baseline store, honeypot webhook receiver, architecture documentation, configuration, and tests.

## What Phase 1 adds

- `detectors/evidence_schema.py` — unified specialist detector output
- `detectors/base_detector.py` — common detector interface
- `detectors/network_detector.py` — saved LightGBM runtime inference
- `ingestion/network_adapter.py` — network flow feature boundary
- `ingestion/telemetry_router.py` — telemetry type routing
- `correlation/evidence_stream.py` — JSONL AI/correlation input boundary
- `orchestrator/phase1_pipeline.py` — Phase-1 runtime coordinator
- `data/training/network_common.py`
- `data/training/inspect_network.py`
- `data/training/preprocess_network.py`
- `data/training/train_network.py`
- `data/training/evaluate_network.py`
- `data/training/aggregate_lanl.py`
- `run_phase1.py`

No existing team implementation file was deleted or overwritten except documentation/dependency metadata being extended.

## Current executable flow

```
CSE-CIC-IDS2018 CSVs
        |
        v
inspect_network.py
        |
        v
preprocess_network.py
        |
        +--> train.parquet
        +--> valid.parquet
        +--> test.parquet
        +--> metadata.json (feature contract)
        |
        v
train_network.py
        |
        +--> network_model.txt
        +--> label_encoder.pkl
        +--> feature_columns.json
        |
        v
run_phase1.py
        |
        v
Phase1Pipeline
        |
        v
TelemetryRouter
        |
        v
NetworkFlowAdapter
        |
        v
NetworkDetector
        |
        v
DetectorEvidence
        |
        v
data/runtime/evidence/events.jsonl
        |
        v
FUTURE: Cyber Entity Graph -> Meta LightGBM -> ATT&CK RAG -> AI Agents
```

## LANL flow currently added

```
lanl-auth-dataset-1-00.bz2
        |
        v
bz2 streaming reader
        |
        v
user + 1-hour window
        |
        v
auth_count / unique_computers / fanout / auth-gap features
        |
        v
lanl_user_hour_windows.parquet
```

The Isolation Forest is intentionally not trained yet. Historical novelty features such as `new_computer_ratio` must be added before freezing the identity model contract.

## Commands

Place CSE-CIC CSVs in `data/raw/cse-cic-ids2018/`.

Then:

```bash
python -m data.training.inspect_network
python -m data.training.preprocess_network
python -m data.training.train_network
python -m data.training.evaluate_network
python run_phase1.py
```

Place the compressed LANL chunk in `data/raw/lanl-auth/`.

Then:

```bash
python -m data.training.aggregate_lanl
```
