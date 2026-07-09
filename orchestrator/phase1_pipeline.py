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
        return evidence
