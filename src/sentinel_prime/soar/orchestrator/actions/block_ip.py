"""Simulated block-IP action."""

from __future__ import annotations

import logging
from typing import Any


logger = logging.getLogger(__name__)


def execute(incident: dict[str, Any]) -> dict[str, str]:
    incident_id = incident.get("incident_id", "UNKNOWN")
    attacker_ip = incident.get("attacker_ip")

    logger.info("Starting block_ip simulation for incident %s", incident_id)
    
    # Try alternate fields just in case
    if not attacker_ip:
        attacker_ip = incident.get("src_ip") or incident.get("source_ip") or incident.get("remote_ip")

    if not attacker_ip:
        logger.warning(
            "block_ip prerequisites failed for incident %s: attacker IP not found. Falling back to isolate_host.",
            incident_id,
        )
        # Attempt fallback to isolate_host
        from sentinel_prime.soar.orchestrator.actions.isolate_host import execute as execute_isolate_host
        fallback_result = execute_isolate_host(incident)
        fallback_result["message"] = f"block_ip failed (missing IP). Fallback result: {fallback_result.get('message', '')}"
        return fallback_result

    logger.info(
        "Simulated block for attacker IP %s in incident %s",
        attacker_ip,
        incident_id,
    )

    return {
        "action": "block_ip",
        "target": str(attacker_ip),
        "status": "SUCCESS",
        "message": "Malicious IP blocked successfully (simulated)",
    }