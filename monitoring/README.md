# Monitoring — Closed-Loop Outcome Monitoring

Verifies whether containment actions worked and routes the result back into the pipeline.

## Directory Structure

```
monitoring/
├── __init__.py
├── outcome_monitor.py       # Re-run detectors over follow-up window
├── feedback.py              # Baseline update + confidence recalibration
└── README.md
```

## Outcome Classification

| Outcome | What happens |
|---|---|
| **Resolved** | Close incident, update baselines in BaselineStore, clean up adaptive decoys |
| **Persisted** | Re-enter detection pipeline with same priority, try alternative action |
| **Escalated** | Re-enter correlation engine with elevated priority, broader blast radius allowed |
