# Attack Simulation

**Adversary emulation** — configurations and scripts for MITRE Caldera and Atomic Red Team to generate realistic attack traffic for testing and benchmarking.

## Purpose

- Provide repeatable attack scenarios with known ground-truth ATT&CK technique IDs
- Generate honeypot interaction events for demo/testing
- Create labeled attack data for detection accuracy benchmarks
- Support MTTD/MTTR measurement

## Planned Scenarios

| Scenario | ATT&CK Techniques | Description |
|---|---|---|
| Ransomware staging | T1486, T1490 | Mass file encryption + shadow copy deletion |
| Lateral movement | T1021, T1078 | Credential reuse across hosts |
| Data exfiltration | T1041, T1567 | Beaconing + data transfer to external host |
| Credential harvesting | T1003, T1555 | Credential dumping + browser password extraction |

## Key Files (future)

| File | Description |
|---|---|
| `caldera_profiles/` | Caldera adversary profiles |
| `atomic_tests/` | Atomic Red Team test definitions |
| `scenarios/` | End-to-end scenario scripts |
