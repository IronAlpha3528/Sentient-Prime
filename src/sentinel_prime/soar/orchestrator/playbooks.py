"""Simple predefined SOAR playbooks."""

from __future__ import annotations


PLAYBOOKS = {
    "Brute Force": [
        "block_ip",
        "revoke_access",
    ],
    "Credential Theft": [
        "revoke_access",
    ],
    "Malware": [
        "isolate_host",
    ],
    "Ransomware": [
        "isolate_host",
        "revoke_access",
    ],
    "DDoS": [
        "block_ip",
    ],
    "Port Scan": [
        "block_ip",
    ],
}

DEFAULT_PLAYBOOK = [
    "block_ip",
]


def get_playbook(attack_type: str) -> list[str]:
    return PLAYBOOKS.get(attack_type, DEFAULT_PLAYBOOK)