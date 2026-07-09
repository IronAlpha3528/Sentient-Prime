"""Simulated isolate-host action."""

from __future__ import annotations

import logging
from typing import Any


logger = logging.getLogger(__name__)


def execute(incident: dict[str, Any]) -> dict[str, str]:
    incident_id = incident.get("incident_id", "UNKNOWN")
    asset = incident.get("asset")

    logger.info("Starting isolate_host simulation for incident %s", incident_id)

    if not asset:
        logger.warning(
            "isolate_host failed for incident %s: asset not found",
            incident_id,
        )
        return {
            "action": "isolate_host",
            "status": "FAILED",
            "message": "Asset not found",
        }

    logger.info(
        "Simulated host isolation for asset %s in incident %s",
        asset,
        incident_id,
    )

    return {
        "action": "isolate_host",
        "target": str(asset),
        "status": "SUCCESS",
        "message": "Host isolated successfully (simulated)",
    }