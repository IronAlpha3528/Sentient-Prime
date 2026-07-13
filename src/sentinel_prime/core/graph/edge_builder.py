from typing import Any, Dict

class EdgeBuilder:
    """Manages the creation and incremental merging of graph edge attributes."""

    @staticmethod
    def build(edge_data: Dict[str, Any]) -> Dict[str, Any]:
        """Formats the initial edge attribute dictionary."""
        ts = edge_data.get("timestamp")
        return {
            "type": edge_data["type"],
            "first_seen": ts,
            "last_seen": ts,
            "occurrence_count": 1,
            "timestamp": ts,
            "confidence": float(edge_data.get("confidence", 1.0)),
            "source_detector": edge_data.get("metadata", {}).get("source_detector", "unknown"),
            "risk": float(edge_data.get("risk", 0.0)),
            "metadata": edge_data.get("metadata", {}).copy()
        }

    @staticmethod
    def merge(existing: Dict[str, Any], updates: Dict[str, Any]) -> Dict[str, Any]:
        """Merges new relationship occurrences into an existing edge in-place."""
        new_ts = updates.get("timestamp")
        if new_ts:
            if not existing.get("first_seen") or new_ts < existing["first_seen"]:
                existing["first_seen"] = new_ts
            if not existing.get("last_seen") or new_ts > existing["last_seen"]:
                existing["last_seen"] = new_ts
            existing["timestamp"] = new_ts

        # Increment occurrences
        existing["occurrence_count"] = existing.get("occurrence_count", 0) + 1

        # Max risk and confidence
        existing["risk"] = max(existing.get("risk", 0.0), float(updates.get("risk", 0.0)))
        existing["confidence"] = max(existing.get("confidence", 0.0), float(updates.get("confidence", 0.0)))

        # Merge metadata
        if "metadata" in existing and isinstance(existing["metadata"], dict):
            existing["metadata"].update(updates.get("metadata", {}))
        else:
            existing["metadata"] = updates.get("metadata", {}).copy()

        return existing
