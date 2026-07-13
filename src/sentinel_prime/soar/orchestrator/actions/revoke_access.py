"""Simulated revoke-access action."""

from __future__ import annotations

import logging
from typing import Any


logger = logging.getLogger(__name__)


def execute(incident: dict[str, Any]) -> dict[str, str]:
    incident_id = incident.get("incident_id", "UNKNOWN")
    username = incident.get("username")

    logger.info("Starting revoke_access simulation for incident %s", incident_id)

    if not username:
        logger.warning(
            "revoke_access failed for incident %s: username not found",
            incident_id,
        )
        return {
            "action": "revoke_access",
            "status": "FAILED",
            "message": "Username not found",
        }

    logger.info(
        "Simulated access revocation for user %s in incident %s",
        username,
        incident_id,
    )

    return {
        "action": "revoke_access",
        "target": str(username),
        "status": "SUCCESS",
        "message": "User access revoked successfully (simulated)",
    }