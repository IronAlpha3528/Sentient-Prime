from typing import Any, Dict
from sentinel_prime.core.evidence.severity import SeverityLevel

SEVERITY_ORDER = {
    SeverityLevel.INFO.value: 1,
    SeverityLevel.LOW.value: 2,
    SeverityLevel.MEDIUM.value: 3,
    SeverityLevel.HIGH.value: 4,
    SeverityLevel.CRITICAL.value: 5
}

class NodeBuilder:
    """Manages the creation and incremental merging of graph node attributes."""

    @staticmethod
    def build(node_data: Dict[str, Any]) -> Dict[str, Any]:
        """Formats the initial node attribute dictionary."""
        timestamp = node_data.get("timestamp")
        return {
            "node_id": node_data["node_id"],
            "entity_type": node_data["entity_type"],
            "display_name": node_data["display_name"],
            "risk_score": float(node_data.get("risk_score", 0.0)),
            "confidence": float(node_data.get("confidence", 1.0)),
            "severity": str(node_data.get("severity", "INFO")).upper(),
            "first_seen": timestamp,
            "last_seen": timestamp,
            "metadata": node_data.get("metadata", {}).copy()
        }

    @staticmethod
    def merge(existing: Dict[str, Any], updates: Dict[str, Any]) -> Dict[str, Any]:
        """Updates an existing node's state with incoming events incrementally

        by taking the max risk score, updating timestamps, and merging metadata.
        """
        new_ts = updates.get("timestamp")
        if new_ts:
            if not existing.get("first_seen") or new_ts < existing["first_seen"]:
                existing["first_seen"] = new_ts
            if not existing.get("last_seen") or new_ts > existing["last_seen"]:
                existing["last_seen"] = new_ts

        # Max risk score and confidence levels
        existing["risk_score"] = max(existing.get("risk_score", 0.0), float(updates.get("risk_score", 0.0)))
        existing["confidence"] = max(existing.get("confidence", 0.0), float(updates.get("confidence", 0.0)))

        # Take peak severity
        existing_sev = str(existing.get("severity", "INFO")).upper()
        new_sev = str(updates.get("severity", "INFO")).upper()
        existing_val = SEVERITY_ORDER.get(existing_sev, 1)
        new_val = SEVERITY_ORDER.get(new_sev, 1)
        if new_val > existing_val:
            existing["severity"] = new_sev

        # Merge metadata
        if "metadata" in existing and isinstance(existing["metadata"], dict):
            existing["metadata"].update(updates.get("metadata", {}))
        else:
            existing["metadata"] = updates.get("metadata", {}).copy()

        return existing
