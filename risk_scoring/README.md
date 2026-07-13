# Risk Scoring — Risk Scoring & Action Ranking Module

Deterministic scoring function that ranks containment actions by weighing security benefit against operational cost.

## Directory Structure

```
risk_scoring/
├── __init__.py
├── scorer.py                # Composite score calculation
├── action_menu.py           # Fixed action definitions + impact estimates
└── README.md
```

## Formula

```
Composite Score = α × Containment Effectiveness − β × Business Impact
```

- `α`/`β` weights are configurable per organization/asset criticality
- Default: α = 0.7, β = 0.3

## Action Menu

| Action | Containment | Impact | Default Score |
|---|---|---|---|
| Isolate host | 0.90 | 0.20 | 0.57 |
| Revoke credential | 0.75 | 0.10 | 0.50 |
| Block IP/domain | 0.55 | 0.05 | 0.37 |
| Snapshot VM (forensic) | 0.10 | 0.02 | 0.06 |
| Monitor only | 0.05 | 0.00 | 0.04 |

---

## AI Reasoning Core (Hardik's Implementation)

- `scorer.py`: Fully implements the math formula dynamically. Instead of hardcoding the action menu and weights in Python, it pulls them directly from `config/risk_params.yaml`.
- Adjusts the containment weight automatically if the attacker has already spread (blast radius is high).
- Determines the final routing decision: SOAR (automation) or Human Escalation Gate based on confidence, blast score, and OT reachability.
