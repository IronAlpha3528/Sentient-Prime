from typing import Any, Dict, List

class TimelineBuilder:
    """Sorts evidence events chronologically and compiles a structured timeline

    suitable for direct consumption by Gemini AI.
    """

    @staticmethod
    def build(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Sorts events chronologically and maps them to standard timeline entry dictionaries."""
        # Safely sort using timestamp keys from payload or base dictionary
        sorted_events = sorted(
            events,
            key=lambda x: x.get("timestamp", "") or x.get("payload", {}).get("timestamp", "")
        )

        timeline = []
        for ev in sorted_events:
            # Handle standard wrapper event vs raw payload dictionary
            is_wrapper = "payload" in ev
            payload = ev["payload"] if is_wrapper else ev
            
            ts = ev.get("timestamp") or payload.get("timestamp", "")
            detector = ev.get("detector") or payload.get("detector", "UNKNOWN")
            entity = ev.get("entity") or payload.get("entity", "unknown")
            risk = float(payload.get("risk_score", 0.0))
            confidence = float(payload.get("confidence", 1.0))

            # Compile explanation details
            reasons = payload.get("top_reasons", [])
            if reasons:
                desc = f"{detector} Specialist observed activity on '{entity}': {', '.join(reasons)}"
            else:
                desc = f"{detector} Specialist observed activity on '{entity}' with threat risk score {risk:.2f}"

            timeline.append({
                "timestamp": ts,
                "description": desc,
                "risk": risk,
                "confidence": confidence
            })
            
        return timeline
