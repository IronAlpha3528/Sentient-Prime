# Orchestrator — SOAR Playbook Dispatcher

Manages the dry-run → policy gate → execute/escalate pipeline for containment actions.

## Directory Structure

```
orchestrator/
├── __init__.py
├── dispatcher.py            # Main orchestration loop
├── dry_run.py               # Action effect simulation / prediction
├── policy_gate.py           # Confidence ≥ 0.75 + blast radius check
├── actions/                 # Pluggable containment action implementations
│   ├── __init__.py
│   ├── isolate_host.py      # iptables (Linux) / Windows Firewall
│   ├── revoke_credential.py # Disable-ADAccount or mocked equivalent
│   └── block_ip.py          # Firewall rule / DNS sinkhole
└── README.md
```

## Policy Gate Logic

```
IF dry_run.passes AND confidence ≥ 0.75 AND blast_radius ≤ max_auto:
    → auto-execute via SOAR playbook (isolate, revoke, block IP)
ELSE:
    → escalate to human-approval queue (surfaced in dashboard)
```

## SOAR Actions

| Action | Implementation |
|---|---|
| Isolate host | `iptables` (Linux) / Windows Firewall rule |
| Revoke credential | `Disable-ADAccount` or mocked equivalent |
| Block IP/domain | Firewall rule / DNS sinkhole |
| Snapshot VM | Forensic snapshot for evidence preservation |
| Monitor only | Continue observation, no active response |
