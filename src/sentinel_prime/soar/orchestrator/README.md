# Orchestrator - SOAR Playbook Dispatcher

Manages the dry-run -> policy gate -> execute/escalate pipeline for containment actions.

## Directory Structure

```
orchestrator/
├── __init__.py
├── dispatcher.py
├── dry_run.py
├── policy_gate.py
└── actions/
    ├── block_ip.py
    ├── isolate_host.py
    └── revoke_access.py
```

### actions/

This folder contains the SOAR response actions executed after the Policy Gate approves an incident.

- **block_ip.py** → Simulates blocking a malicious IP address.
- **isolate_host.py** → Simulates isolating an infected host from the network.
- **revoke_access.py** → Simulates revoking access for a compromised user account.

Each action returns a structured response indicating whether the simulated action succeeded or failed.

## Policy Gate Logic

```
IF dry_run.passes AND confidence >= 0.75 AND blast_radius <= max_auto:
    -> auto-execute via SOAR playbook
ELSE:
    -> escalate to human approval
```