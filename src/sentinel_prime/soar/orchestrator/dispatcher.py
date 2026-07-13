"""Simple SOAR dispatcher for the orchestrator pipeline."""

from __future__ import annotations

import logging
from typing import Any

from sentinel_prime.soar.orchestrator import dry_run, policy_gate

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
        incident_data = self._prepare_incident(incident)
        incident_id = incident_data.get("incident_id", "UNKNOWN")
        attack_type = incident_data.get("attack_type", "Unknown")
        actions = get_playbook(attack_type)
        incident_data["recommended_actions"] = actions

        logger.info("Dispatching incident %s", incident_id)

        dry_run_result = dry_run.simulate(incident_data, actions)
        logger.info("Dry run completed for incident %s", incident_id)

        decision_result = policy_gate.evaluate(incident_data, dry_run_result)
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
            result = self._run_action(action, incident_data)
            action_results.append(result)

        return {
            "incident_id": incident_id,
            "decision": "AUTO",
            "actions": action_results,
        }

    def _prepare_incident(self, incident: dict[str, Any]) -> dict[str, Any]:
        incident_data = dict(incident)
        entity_id = incident_data.get("entity_id", "UNKNOWN")
        score = float(incident_data.get("score", 0))

        incident_data.setdefault("incident_id", f"INC-{entity_id}")
        incident_data.setdefault("attack_type", incident_data.get("classification", "Unknown"))
        incident_data.setdefault("confidence", score)
        incident_data.setdefault("risk_score", 0)
        incident_data.setdefault("asset", entity_id)

        if incident_data.get("entity_type") == "user":
            incident_data.setdefault("username", entity_id)

        return incident_data

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