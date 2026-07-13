from correlation.evidence_stream import EvidenceStream
from detectors.network_detector import NetworkDetector
from detectors.identity_detector import IdentityDetector
from ingestion.network_adapter import NetworkFlowAdapter
from ingestion.identity_adapter import IdentityAdapter
from ingestion.telemetry_router import TelemetryRouter


class Phase1Pipeline:
    """Current Phase-1 runtime pipeline.

    Only the network and identity routes are enabled, with endpoint and OT bypassed.
    """

    def __init__(self):
        self.stream = EvidenceStream()
        self.router = TelemetryRouter(
            {
                "network": (
                    NetworkFlowAdapter(),
                    NetworkDetector(),
                ),
                "identity": (
                    IdentityAdapter(),
                    IdentityDetector(),
                ),
            }
        )

    def process(self, event: dict) -> dict:
        evidence = self.router.route(event)
        self.stream.publish(evidence)

        # Publish to the new Evidence Bus
        try:
            from core.evidence import EvidenceBus, NetworkEvidence, IdentityEvidence
            from datetime import datetime, timezone
            
            detector_name = str(evidence.get("detector", "")).lower()
            if detector_name == "network":
                attack_family = "unknown"
                for item in evidence.get("evidence", []):
                    if item.get("type") == "predicted_attack_family":
                        attack_family = item.get("value", "unknown")
                
                net_ev = NetworkEvidence(
                    detector="NETWORK",
                    entity=evidence.get("entity_id", "unknown-host"),
                    entity_type="HOST",
                    timestamp=evidence.get("timestamp") or datetime.now(timezone.utc).isoformat(),
                    window_start=evidence.get("timestamp") or datetime.now(timezone.utc).isoformat(),
                    window_end=evidence.get("timestamp") or datetime.now(timezone.utc).isoformat(),
                    confidence=0.9,
                    risk_score=float(evidence.get("score", 0.0)),
                    severity="HIGH" if evidence.get("score", 0.0) >= 0.5 else ("MEDIUM" if evidence.get("score", 0.0) >= 0.3 else "LOW"),
                    top_reasons=[f"Predicted attack family: {attack_family}"],
                    metadata=evidence.get("features", {}),
                    attack_family=attack_family,
                    protocol=evidence.get("features", {}).get("protocol", "unknown"),
                    source_ip="unknown",
                    destination_ip="unknown",
                    flow_duration=float(evidence.get("features", {}).get("flow_duration", 0.0) or 0.0),
                    top_network_features=evidence.get("features", {})
                )
                EvidenceBus.get_instance().push(net_ev)
            elif detector_name == "identity":
                reasons = []
                for item in evidence.get("evidence", []):
                    if item.get("type") == "behavioural_reasons":
                        reasons = item.get("values", [])
                
                id_ev = IdentityEvidence(
                    detector="IDENTITY",
                    entity=evidence.get("entity_id", "unknown-user"),
                    entity_type="USER",
                    timestamp=evidence.get("timestamp") or datetime.now(timezone.utc).isoformat(),
                    window_start=evidence.get("timestamp") or datetime.now(timezone.utc).isoformat(),
                    window_end=evidence.get("timestamp") or datetime.now(timezone.utc).isoformat(),
                    confidence=0.9,
                    risk_score=float(evidence.get("score", 0.0)),
                    severity="HIGH" if evidence.get("score", 0.0) >= 0.5 else ("MEDIUM" if evidence.get("score", 0.0) >= 0.3 else "LOW"),
                    top_reasons=reasons,
                    metadata=evidence.get("features", {}),
                    user=evidence.get("entity_id", "unknown-user"),
                    auth_count=int(evidence.get("features", {}).get("auth_count", 0) or 0),
                    computer_fanout=int(evidence.get("features", {}).get("unique_computers", 0) or 0),
                    new_computer_ratio=float(evidence.get("features", {}).get("new_computer_ratio", 0.0) or 0.0),
                    off_hours=bool(int(evidence.get("features", {}).get("off_hours_flag", 0) or 0)),
                    identity_features=evidence.get("features", {})
                )
                EvidenceBus.get_instance().push(id_ev)
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(f"Error publishing to Evidence Bus in pipeline: {e}")

        return evidence
