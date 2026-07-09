"""Simple monitoring checks for SOAR containment results."""

from __future__ import annotations

import logging
from typing import Any

from monitoring.status import ESCALATED, PERSISTING, RESOLVED


logger = logging.getLogger(__name__)


class Monitor:
    """Checks whether containment actions resolved an incident."""

    def check_status(
        self,
        incident: dict[str, Any],
        action_results: list[dict[str, Any]],
    ) -> dict[str, str]:
        incident_id = incident.get("incident_id", "UNKNOWN")
        risk_score = incident.get("risk_score", 0)

        logger.info("Checking containment status for incident %s", incident_id)

        if risk_score > 90:
            logger.warning(
                "Incident %s escalated because risk score is %s",
                incident_id,
                risk_score,
            )
            return {
                "status": ESCALATED,
                "message": "Critical incident requires analyst review",
            }

        for result in action_results:
            action = result.get("action", "unknown")
            status = result.get("status", "FAILED")

            if status != "SUCCESS":
                logger.warning(
                    "Incident %s still persisting because action %s failed",
                    incident_id,
                    action,
                )
                return {
                    "status": PERSISTING,
                    "message": "Some containment actions failed",
                }

        logger.info("Incident %s resolved successfully", incident_id)
        return {
            "status": RESOLVED,
            "message": "Threat contained successfully",
        }