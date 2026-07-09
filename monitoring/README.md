# Monitoring - Closed-Loop Outcome Monitoring

Verifies whether containment actions worked and routes the result back into the pipeline.

## Directory Structure

```
monitoring/
├── __init__.py
├── monitor.py
├── status.py
└── README.md
```

## Monitoring

The Monitoring module validates whether the selected SOAR playbook successfully contained the incident.

Responsibilities

- Verify execution results
- Decide final incident status
- Send status to the Audit Ledger

Possible outcomes

- RESOLVED
- PERSISTING
- ESCALATED

## Outcome Classification

| Outcome | What happens |
|---|---|
| **Resolved** | Close incident, update baselines in BaselineStore, clean up adaptive decoys |
| **Persisted** | Re-enter detection pipeline with same priority, try alternative action |
| **Escalated** | Re-enter correlation engine with elevated priority, broader blast radius allowed |