"""Simple dry-run simulator for SOAR action impact."""

from __future__ import annotations

import logging
from typing import Any


logger = logging.getLogger(__name__)

ACTION_RULES = {
    "block_ip": {
        "blast_radius": "LOW",
        "service_disruption": "No service interruption",
        "passes": True,
    },
    "revoke_access": {
        "blast_radius": "LOW",
        "service_disruption": "Compromised user's access removed",
        "passes": True,
    },
    "isolate_host": {
        "blast_radius": "HIGH",
        "service_disruption": "Host disconnected from network",
        "passes": False,
    },
}

UNKNOWN_ACTION_RULE = {
    "blast_radius": "LOW",
    "service_disruption": "Unknown action impact",
    "passes": True,
}


class DryRun:
    """Simulates impact of recommended SOAR actions."""

    def simulate(self, incident: dict[str, Any], actions: list[str]) -> dict[str, Any]:
        incident_id = incident.get("incident_id", "UNKNOWN")

        logger.info("Starting dry run for incident %s", incident_id)

        predictions = []
        overall_passes = True
        overall_blast_radius = "LOW"

        for action in actions:
            rule = ACTION_RULES.get(action, UNKNOWN_ACTION_RULE)

            predictions.append(
                {
                    "action": action,
                    "impact": rule["service_disruption"],
                }
            )

            if rule["passes"] is False:
                overall_passes = False

            if rule["blast_radius"] == "HIGH":
                overall_blast_radius = "HIGH"

            logger.info(
                "Dry run predicted impact for action %s in incident %s",
                action,
                incident_id,
            )

        result = {
            "passes": overall_passes,
            "blast_radius": overall_blast_radius,
            "predictions": predictions,
        }

        logger.info(
            "Dry run completed for incident %s with passes=%s",
            incident_id,
            overall_passes,
        )
        return result


def simulate(incident: dict[str, Any], actions: list[str]) -> dict[str, Any]:
    return DryRun().simulate(incident, actions)

def simulate_action(action: str, target: str, graph: dict[str, list[str]]) -> dict[str, Any]:
    """
    Simulates the impact of a specific action on a target node using the dependency graph.
    Computes reachable nodes (blast radius) and assigns an impact level.
    """
    reachable = set()
    queue = [target]
    while queue:
        curr = queue.pop(0)
        neighbors = graph.get(curr, [])
        for n in neighbors:
            if n not in reachable:
                reachable.add(n)
                queue.append(n)
    
    blast_radius_nodes = len(reachable)
    
    if blast_radius_nodes >= 3:
        impact_level = "High"
    elif blast_radius_nodes >= 1:
        impact_level = "Medium"
    else:
        impact_level = "Low"
        
    return {
        "simulated_impact_level": impact_level,
        "blast_radius_nodes": blast_radius_nodes,
        "action": action,
        "target": target
    }