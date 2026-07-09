"""Simple SOAR dispatcher for the orchestrator pipeline."""

from __future__ import annotations

import logging
from typing import Any

from orchestrator import dry_run, policy_gate

try:
    from playbooks import get_playbook
except ImportError:
    from orchestrator.playbooks import get_playbook

try:
    from orchestrator.actions import execute_action
except ImportError:
    execute_action = None


logger = logging.getLogger(__name__)


class SOARDispatcher:
    """Coordinates dry run, policy gate, and action execution."""

    def dispatch(self, incident: dict[str, Any]) -> dict[str, Any]:
        incident_id = incident.get("incident_id", "UNKNOWN")
        attack_type = incident["attack_type"]
        actions = get_playbook(attack_type)
        incident_with_actions = dict(incident)
        incident_with_actions["recommended_actions"] = actions

        logger.info("Dispatching incident %s", incident_id)

        dry_run_result = dry_run.simulate(incident_with_actions)
        logger.info("Dry run completed for incident %s", incident_id)

        if hasattr(dry_run_result, "to_dict"):
            dry_run_data = dry_run_result.to_dict()
        else:
            dry_run_data = dry_run_result

        decision_result = policy_gate.evaluate(incident_with_actions, dry_run_data)
        decision = decision_result.get("decision")
        logger.info("Policy decision for incident %s: %s", incident_id, decision)

        if decision == "ESCALATE":
            return {
                "incident_id": incident_id,
                "decision": "ESCALATE",
                "reason": decision_result.get("reason", "Manual approval required"),
            }

        action_results = []
        for action in actions:
            logger.info("Executing action %s for incident %s", action, incident_id)
            result = self._run_action(action, incident_with_actions)
            action_results.append(result)

        return {
            "incident_id": incident_id,
            "decision": "AUTO",
            "actions": action_results,
        }

    def _run_action(self, action: str, incident: dict[str, Any]) -> dict[str, str]:
        if execute_action is None:
            raise RuntimeError("execute_action is not available")

        result = execute_action(action, incident)

        if isinstance(result, dict):
            return {
                "action": result.get("action", action),
                "status": result.get("status", "SUCCESS"),
            }

        return {
            "action": action,
            "status": str(result or "SUCCESS"),
        }


def dispatch(incident: dict[str, Any]) -> dict[str, Any]:
    return SOARDispatcher().dispatch(incident)