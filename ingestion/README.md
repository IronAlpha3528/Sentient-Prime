# Ingestion — Log Ingestion & Baseline Store

Handles SIEM event ingestion (webhook receiver) and maintains per-entity rolling baselines using Welford's online algorithm.

## Directory Structure

```
ingestion/
├── __init__.py
├── baseline_store.py        # SQLite-backed rolling mean/std per entity per metric
├── es_client.py             # Elasticsearch query helpers for SIEM events
└── README.md
```

## BaselineStore

SQLite-backed class with two core methods:
- `update(entity_id, metric, value)` — updates the rolling mean/std using Welford's algorithm
- `deviation(entity_id, metric, value)` — returns how many standard deviations the value is from the entity's baseline

Used by detection agents (mass file activity, auth anomaly) to detect behavior that deviates from an entity's established pattern.
