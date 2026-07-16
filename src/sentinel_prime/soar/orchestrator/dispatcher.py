"""Simple SOAR dispatcher for the orchestrator pipeline."""

from __future__ import annotations

import logging
from typing import Any

from sentinel_prime.soar.orchestrator import dry_run, policy_gate

from sentinel_prime.soar.orchestrator.playbooks import get_playbook
from sentinel_prime.soar.orchestrator.actions import execute_action
from sentinel_prime.core.telemetry.ledger import AuditLedger
from sentinel_prime.core.telemetry.monitoring.monitor import Monitor


logger = logging.getLogger(__name__)

ACTION_ALIASES = {
    "block_ip": "block_ip",
    "block_ip/domain": "block_ip",
    "block_source_ip": "block_ip",
    "isolate_host": "isolate_host",
    "isolate_endpoint": "isolate_host",
    "revoke_access": "revoke_access",
    "revoke_credential": "revoke_access",
    "revoke_credentials": "revoke_access",
    "deploy_decoy": "deploy_decoy",
}


class SOARDispatcher:
    """Coordinates dry run, policy gate, and action execution."""

    def __init__(self, ledger: AuditLedger | None = None, monitor: Monitor | None = None) -> None:
        self.ledger = ledger or AuditLedger()
        self.monitor = monitor or Monitor()

    def dispatch(self, incident: dict[str, Any]) -> dict[str, Any]:
        incident_data = self._prepare_incident(incident)
        incident_id = incident_data.get("incident_id", "UNKNOWN")
        attack_type = incident_data.get("attack_type", "Unknown")
        
        actions = []
        # Extract AI Deception Strategy
        deception = incident_data.get("deception_strategy", {})
        if deception.get("is_testable"):
            actions.append("deploy_decoy")
            
        # Extract AI Response Plan
        response_plan = incident_data.get("response_agent_plan", {})
        for rec_action in response_plan.get("recommended_actions", []):
            name = self._canonical_action(rec_action.get("action_name", ""))
            if name:
                actions.append(name)
                
        # Fallback to static playbook if AI provided no actions
        if not actions:
            actions = get_playbook(attack_type)
            
        actions = list(dict.fromkeys(actions))
        incident_data["recommended_actions"] = actions

        logger.info("Dispatching incident %s", incident_id)

        dry_run_result = dry_run.simulate(incident_data, actions)
        self._record("dry_run", dry_run_result, incident_id)
        logger.info("Dry run completed for incident %s", incident_id)

        decision_result = policy_gate.evaluate(incident_data, dry_run_result)
        self._record("policy_decision", decision_result, incident_id)
        decision = decision_result.get("decision")
        logger.info("Policy decision for incident %s: %s", incident_id, decision)

        if decision == "ESCALATE":
            result = {
                "incident_id": incident_id,
                "decision": "ESCALATE",
                "reason": decision_result.get("reason", "Manual approval required"),
            }
            result["outcome"] = {
                "status": "ESCALATED",
                "message": result["reason"],
            }
            self._record("escalation", result, incident_id)
            self._record("monitor_outcome", result["outcome"], incident_id)
            return result

        action_results = []
        for action in actions:
            logger.info("Executing action %s for incident %s", action, incident_id)
            result = self._run_action(action, incident_data)
            action_results.append(result)
            self._record("action_execution", result, incident_id)

        result = {
            "incident_id": incident_id,
            "decision": "AUTO",
            "actions": action_results,
        }
        result["outcome"] = self.monitor.check_status(incident_data, action_results)
        self._record("monitor_outcome", result["outcome"], incident_id)
        return result

    def _prepare_incident(self, incident: dict[str, Any]) -> dict[str, Any]:
        incident_data = dict(incident)
        entity_id = incident_data.get("entity_id", "UNKNOWN")
        score = float(incident_data.get("score", 0))
        top_hypothesis = incident_data.get("top_hypothesis_selected", {})
        response_plan = incident_data.get("response_plan", {})

        incident_data.setdefault("incident_id", f"INC-{entity_id}")
        incident_data.setdefault("attack_type", incident_data.get("classification", "Unknown"))
        incident_data.setdefault("confidence", top_hypothesis.get("confidence", score))
        ranked_actions = response_plan.get("ranked_actions", [])
        incident_data.setdefault(
            "risk_score",
            max((item.get("score", 0) for item in ranked_actions), default=0) * 100,
        )
        incident_data.setdefault("asset", entity_id)

        if incident_data.get("entity_type") == "user":
            incident_data.setdefault("username", entity_id)

        return incident_data

    @staticmethod
    def _canonical_action(action_name: str) -> str | None:
        normalized = action_name.lower().strip().replace(" ", "_")
        return ACTION_ALIASES.get(normalized)

    def _record(self, event_type: str, data: dict[str, Any], incident_id: str) -> None:
        try:
            self.ledger.append_entry(event_type, data, incident_id=incident_id)
        except OSError:
            logger.exception("Unable to record %s for incident %s", event_type, incident_id)

    def _run_action(self, action: str, incident: dict[str, Any]) -> dict[str, str]:
        if execute_action is None:
            raise RuntimeError("execute_action is not available")

        result = execute_action(action, incident)

        if isinstance(result, dict):
            return {
                "action": result.get("action", action),
                "status": str(result.get("status", "SUCCESS")).upper(),
            }

        return {
            "action": action,
            "status": str(result or "SUCCESS").upper(),
        }


def dispatch(incident: dict[str, Any]) -> dict[str, Any]:
    return SOARDispatcher().dispatch(incident)
