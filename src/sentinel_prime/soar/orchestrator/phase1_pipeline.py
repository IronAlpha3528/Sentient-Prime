from sentinel_prime.detection.correlation.evidence_stream import EvidenceStream
from sentinel_prime.detection.detectors.network_detector import NetworkDetector
from sentinel_prime.detection.detectors.identity_detector import IdentityDetector
from sentinel_prime.detection.detectors.endpoint.endpoint_detector import EndpointDetector
from sentinel_prime.detection.detectors.ot.ot_detector import OTDetector
from sentinel_prime.core.ingestion.network_adapter import NetworkFlowAdapter
from sentinel_prime.core.ingestion.identity_adapter import IdentityAdapter
from sentinel_prime.core.ingestion.telemetry_router import TelemetryRouter


class PassThroughAdapter:
    def adapt(self, event: dict) -> dict:
        return event

class Phase1Pipeline:
    """Current Phase-1 runtime pipeline.

    Network, identity, endpoint, and OT routes are enabled.
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
                "endpoint": (
                    PassThroughAdapter(),
                    EndpointDetector(),
                ),
                "ot": (
                    PassThroughAdapter(),
                    OTDetector(),
                ),
            }
        )

    def process(self, event: dict) -> dict:
        evidence = self.router.route(event)
        self.stream.publish(evidence)

        # Publish to the new Evidence Bus
        try:
            from sentinel_prime.core.evidence import EvidenceBus, NetworkEvidence, IdentityEvidence, EndpointEvidence, OTEvidence
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
                    source_ip=evidence.get("features", {}).get("source_ip", evidence.get("features", {}).get("src_ip", "unknown")),
                    destination_ip=evidence.get("features", {}).get("destination_ip", evidence.get("features", {}).get("dst_ip", "unknown")),
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
            elif detector_name == "endpoint":
                endp_ev = EndpointEvidence(
                    detector="ENDPOINT",
                    entity=evidence.get("host", "unknown-host"),
                    entity_type="HOST",
                    timestamp=evidence.get("window_end") or datetime.now(timezone.utc).isoformat(),
                    window_start=evidence.get("window_start") or datetime.now(timezone.utc).isoformat(),
                    window_end=evidence.get("window_end") or datetime.now(timezone.utc).isoformat(),
                    confidence=0.85,
                    risk_score=float(evidence.get("risk_score", 0.0)),
                    severity="HIGH" if evidence.get("risk_score", 0.0) >= 0.75 else "MEDIUM",
                    top_reasons=[m.get("rule_name") for m in evidence.get("sigma_matches", [])][:3],
                    metadata=evidence.get("features", {}),
                    process=evidence.get("process", "unknown"),
                    sigma_hits=evidence.get("sigma_matches", []),
                    endpoint_features=evidence.get("features", {})
                )
                EvidenceBus.get_instance().push(endp_ev)
            elif detector_name == "ot":
                ot_ev = OTEvidence(
                    detector="OT",
                    entity=evidence.get("metadata", {}).get("host", "unknown-plc"),
                    entity_type="PLC",
                    timestamp=evidence.get("metadata", {}).get("end_time") or datetime.now(timezone.utc).isoformat(),
                    window_start=evidence.get("metadata", {}).get("start_time") or datetime.now(timezone.utc).isoformat(),
                    window_end=evidence.get("metadata", {}).get("end_time") or datetime.now(timezone.utc).isoformat(),
                    confidence=0.8,
                    risk_score=float(evidence.get("anomaly_score", 0.0)),
                    severity=evidence.get("severity", "LOW"),
                    top_reasons=[],
                    metadata=evidence.get("features", {}),
                    anomaly_score=float(evidence.get("anomaly_score", 0.0)),
                    attack_probability=float(evidence.get("attack_probability", 0.0)),
                    top_shifted_variables=[]
                )
                EvidenceBus.get_instance().push(ot_ev)
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(f"Error publishing to Evidence Bus in pipeline: {e}")

        # Link AI Reasoning Pipeline & SOAR Orchestrator
        try:
            from sentinel_prime.ai.agents.pipeline import run_pipeline
            ai_output = run_pipeline(evidence)
            
            # Forward AI decisions to SOAR Dispatcher
            from sentinel_prime.soar.orchestrator.dispatcher import SOARDispatcher
            dispatcher = SOARDispatcher()
            
            # Merge original evidence with AI output so dispatcher has full context
            combined_context = {**evidence, **ai_output}
            evidence["soar_result"] = dispatcher.dispatch(combined_context)
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(f"Error executing AI Reasoning Pipeline or Dispatcher: {e}")

        return evidence
