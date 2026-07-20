"""Simple policy gate for SOAR automatic response decisions."""

from __future__ import annotations

import logging
from typing import Any


logger = logging.getLogger(__name__)

AUTO_CONFIDENCE_THRESHOLD = 0.75
AUTO_MAX_RISK_SCORE = 95  # raised from 70 — allows high-confidence mid-high risk incidents to auto-contain
PROTECTED_ASSETS = [
    "National Database",
    "Identity Provider",
    "Domain Controller",
    "Payment Gateway",
    "Hospital Core Server",
]


class PolicyGate:
    """Decides whether an incident can be handled automatically."""

    def evaluate(
        self,
        incident: dict[str, Any],
        dry_run_result: dict[str, Any],
    ) -> dict[str, str]:
        incident_id = incident.get("incident_id", "UNKNOWN")
        logger.info("Evaluating policy gate for incident %s", incident_id)

        asset = incident.get("asset", "")
        asset_type = incident.get("asset_type", "")

        if asset in PROTECTED_ASSETS or asset_type in PROTECTED_ASSETS:
            logger.warning("Incident %s escalated: protected asset", incident_id)
            return {
                "decision": "ESCALATE",
                "reason": "Protected asset",
            }

        if dry_run_result.get("passes") is False:
            logger.warning("Incident %s escalated: dry run failed", incident_id)
            return {
                "decision": "ESCALATE",
                "reason": "Dry run failed",
            }

        confidence = float(incident.get("confidence", 0))
        if confidence < AUTO_CONFIDENCE_THRESHOLD:
            logger.warning("Incident %s escalated: confidence too low", incident_id)
            return {
                "decision": "ESCALATE",
                "reason": "Confidence below threshold",
            }

        blast_radius = dry_run_result.get("blast_radius", "")
        if str(blast_radius).upper() == "HIGH":
            logger.warning("Incident %s escalated: high blast radius", incident_id)
            return {
                "decision": "ESCALATE",
                "reason": "High blast radius",
            }

        risk_score = float(incident.get("risk_score", 0))
        if risk_score > AUTO_MAX_RISK_SCORE:
            logger.warning("Incident %s escalated: risk score too high", incident_id)
            return {
                "decision": "ESCALATE",
                "reason": "Risk score too high",
            }

        logger.info("Incident %s approved for automatic response", incident_id)
        return {
            "decision": "AUTO",
            "reason": "Policy checks passed",
        }


def evaluate(incident: dict[str, Any], dry_run_result: dict[str, Any]) -> dict[str, str]:
    return PolicyGate().evaluate(incident, dry_run_result)