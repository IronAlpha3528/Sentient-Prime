# Honeypots — Deception Layer (Passive + Adaptive)

Custom file-based honeytokens monitored via the existing Sysmon/auditd → Wazuh → Elasticsearch pipeline, plus Conpot for OT/ICS deception.

## How It Works

1. **Passive bait files** are placed on production VMs during setup
2. **Adaptive decoys** are placed dynamically by the **AI Deception Agent** to test uncertain hypotheses
3. **Sysmon/auditd** log file access events and feed them to Wazuh → Elasticsearch
4. The **honeytoken detector** queries Elasticsearch for file-access events matching registered honeytokens
5. A match emits a **confidence: 1.0 ground-truth signal** to the Threat Correlation Engine

No external honeytoken service is needed — the SIEM does all detection.

## Bait File Visibility

Bait files use a **dot-prefix** on Linux (e.g., `.db_admin_creds.txt`) to appear hidden in normal directory listings but still visible to `ls -a` or programmatic file enumeration. On Windows, the deployer sets the **hidden file attribute** (`attrib +H`). This prevents legitimate users from accidentally opening them while keeping them discoverable to attacker tooling.

## Decoy Types

| Type | Template | Example deployed filename |
|---|---|---|
| Database credentials | `templates/db_credentials.template` | `.db_admin_creds.txt` |
| VPN configuration | `templates/vpn_config.template` | `.vpn_config.ovpn` |
| Recovery / SSH keys | `templates/recovery_key.template` | `.backup_recovery_key.pem` |
| Environment file | `templates/env_file.template` | `.env` |
| OT/ICS (Conpot) | Docker container | Modbus/S7comm endpoints |

## Directory Structure

```
honeypots/
├── __init__.py
├── webhook_receiver.py        # Flask app — receives Conpot webhooks, normalizes to ES
├── honeytoken_registry.py     # SQLite DB tracking all deployed honeytokens
├── honeytoken_detector.py     # Polls ES for file-access events matching registry
├── decoy_deployer.py          # Places/removes bait files on remote hosts via SSH/WinRM
├── adaptive_engine.py         # Orchestrates adaptive deception lifecycle (used by AI Deception Agent)
├── conpot_monitor.py          # Tails Conpot logs, forwards to ES
├── templates/                 # Bait file content templates
│   ├── db_credentials.template
│   ├── vpn_config.template
│   ├── recovery_key.template
│   └── env_file.template
└── README.md
```

## Passive vs. Adaptive

| Mode | When deployed | Triggered by | Lifetime |
|---|---|---|---|
| **Passive** | Once, at system setup | Always active | Permanent |
| **Adaptive** | Dynamically, on moderate anomaly (0.4–0.74) | AI Deception Agent | TTL (default 30 min) — auto-cleanup |

### AI-Driven Adaptive Deception
When a moderate threat score occurs, the AI Deception Agent decides **what uncertain hypothesis to test, what attacker behaviour would confirm it, which decoy matches that behaviour, and where the graph says the decoy can be safely placed.**

## Signal Output Schema

```json
{
  "entity": "user@host",
  "signal_type": "honeypot_passive | honeypot_adaptive | honeypot_ot",
  "confidence": 1.0,
  "evidence": {
    "decoy_type": "db_credentials",
    "file_path": "/path/to/.db_admin_creds.txt",
    "host": "host-A",
    "access_process": "cat",
    "access_timestamp": "ISO-8601"
  }
}
```
