"""Simulated block-IP action."""

from __future__ import annotations

import logging
from typing import Any


logger = logging.getLogger(__name__)


def execute(incident: dict[str, Any]) -> dict[str, str]:
    incident_id = incident.get("incident_id", "UNKNOWN")
    attacker_ip = incident.get("attacker_ip")

    logger.info("Starting block_ip simulation for incident %s", incident_id)

    if not attacker_ip:
        logger.warning(
            "block_ip failed for incident %s: attacker IP not found",
            incident_id,
        )
        return {
            "action": "block_ip",
            "status": "FAILED",
            "message": "Attacker IP not found",
        }

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