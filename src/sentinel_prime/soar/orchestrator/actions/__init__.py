"""Simple action registry for orchestrator actions."""

from __future__ import annotations

from typing import Any

from sentinel_prime.soar.orchestrator.actions.block_ip import execute as block_ip
from sentinel_prime.soar.orchestrator.actions.isolate_host import execute as isolate_host
from sentinel_prime.soar.orchestrator.actions.revoke_access import execute as revoke_access


ACTIONS = {
    "block_ip": block_ip,
    "isolate_host": isolate_host,
    "revoke_access": revoke_access,
}


def execute_action(action_name: str, incident: dict[str, Any]) -> dict[str, str]:
    action = ACTIONS.get(action_name)

    if action is None:
        return {
            "action": action_name,
            "status": "FAILED",
            "message": "Unknown action",
        }

    return action(incident)