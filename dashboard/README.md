# Dashboard — SOC Dashboard

Real-time web interface for the full incident lifecycle, from raw alerts to final outcomes.

## Directory Structure

```
dashboard/
├── __init__.py
├── app.py                   # Main dashboard application (Streamlit or Flask)
├── api.py                   # API endpoints for data retrieval
├── views/                   # Dashboard view components
│   ├── alert_feed.py        # Live incoming signals + honeypot triggers
│   ├── hypothesis_ladder.py # 2-4 ranked hypotheses with confidence bars
│   ├── ttp_map.py           # ATT&CK matrix heatmap of observed techniques
│   ├── action_timeline.py   # Risk scores → dry-run → execution → outcome
│   ├── deception_status.py  # Active adaptive decoys, touch/decay status
│   ├── metrics.py           # MTTD/MTTR charts
│   ├── audit_trail.py       # Hash-chained ledger entries per incident
│   └── escalation_queue.py  # Pending actions awaiting human approval
└── README.md
```

## Dashboard Views

| View | Description |
|---|---|
| **Alert Feed** | Live stream of detection signals and honeypot triggers (passive + adaptive) |
| **Hypothesis Ladder** | 2–4 ranked hypotheses per entity with confidence bars |
| **TTP Map** | MITRE ATT&CK matrix heatmap of observed techniques |
| **Action Timeline** | Chronological: risk scores → dry-run → execution/escalation → outcome |
| **Deception Status** | Active adaptive decoys per entity, touch/decay status |
| **MTTD/MTTR Metrics** | Detection and response time charts |
| **Audit Trail** | Hash-chained ledger entries for any selected incident |
| **Escalation Queue** | Pending actions awaiting human manual approval |

## Data Source

- Elasticsearch (SIEM events, signals)
- SQLite (honeytoken registry, baseline store)
- JSON lines (audit ledger)

## Run

Install dependencies, then start the Streamlit app from the repository root:

```bash
streamlit run dashboard/app.py
```

The dashboard reads `data/audit_ledger.jsonl` without modifying it. Run a SOAR
dispatch to populate the incident feed, action timeline, escalation queue, and
audit trail.
