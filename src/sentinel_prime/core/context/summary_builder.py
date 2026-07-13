from typing import Any, Dict, List

class SummaryBuilder:
    """Provides deterministic, rule-based text summarization of security events."""

    @staticmethod
    def summarize(events: List[Dict[str, Any]]) -> str:
        """Assembles a readable security narrative paragraph by aggregating specialist findings."""
        if not events:
            return "No suspicious activity detected."

        network_actions = []
        identity_actions = []
        endpoint_actions = []
        ot_actions = []

        for ev in events:
            is_wrapper = "payload" in ev
            payload = ev["payload"] if is_wrapper else ev
            detector = str(payload.get("detector", "")).upper()
            entity = payload.get("entity", "unknown")

            if detector == "NETWORK":
                src = payload.get("source_ip", entity)
                dst = payload.get("destination_ip", "unknown")
                family = payload.get("attack_family", "unknown")
                network_actions.append(f"network flow from {src} to {dst} ({family})")
            elif detector == "IDENTITY":
                user = payload.get("user", entity)
                targets = payload.get("metadata", {}).get("accessed_computers", [])
                if not isinstance(targets, list):
                    targets = [targets] if targets else []
                t_str = f" to targets {', '.join(targets)}" if targets else ""
                identity_actions.append(f"user {user} authenticated{t_str}")
            elif detector == "ENDPOINT":
                proc = payload.get("process", "unknown")
                endpoint_actions.append(f"executed process '{proc}' on host {entity}")
            elif detector == "OT":
                vars_shifted = payload.get("top_shifted_variables", [])
                v_str = f" affecting control loops {', '.join(vars_shifted)}" if vars_shifted else ""
                ot_actions.append(f"anomalous PLC changes on {entity}{v_str}")

        # Join the actions in chronological order categories
        narrative_parts = []
        if identity_actions:
            narrative_parts.append("; ".join(identity_actions))
        if endpoint_actions:
            narrative_parts.append("; ".join(endpoint_actions))
        if network_actions:
            narrative_parts.append("; ".join(network_actions))
        if ot_actions:
            narrative_parts.append("; ".join(ot_actions))

        narrative = ", which led to ".join(narrative_parts)
        if narrative:
            # Capitalize first letter and add period
            narrative = narrative[0].upper() + narrative[1:] + "."
        else:
            narrative = "Suspicious threat telemetry observed across detectors."
            
        return narrative
