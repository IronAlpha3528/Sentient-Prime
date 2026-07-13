from concurrent.futures import ThreadPoolExecutor, Future
import logging
from typing import Any, List
from core.evidence.base_evidence import BaseEvidence

logger = logging.getLogger(__name__)

class Publisher:
    """Manages publishing of standardized BaseEvidence to the Evidence Bus.

    Supports synchronous, batch, asynchronous, and validation-first delivery modes.
    """

    def __init__(self, bus: Any, max_workers: int = 4):
        self.bus = bus
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="EvidencePublisher")

    def publish(self, evidence: BaseEvidence) -> bool:
        """Synchronously publishes a single evidence object to the bus."""
        try:
            return self.bus.push(evidence)
        except Exception as e:
            logger.error(f"Publisher exception during publish: {e}")
            return False

    def publish_batch(self, evidences: List[BaseEvidence]) -> List[bool]:
        """Synchronously publishes a list of evidence objects."""
        return [self.publish(ev) for ev in evidences]

    def publish_async(self, evidence: BaseEvidence) -> Future:
        """Publishes an evidence object asynchronously in a background thread."""
        return self._executor.submit(self.publish, evidence)

    def publish_if_valid(self, evidence: BaseEvidence) -> bool:
        """Performs validation first. Publishes and returns True only if validation passes."""
        val_res = evidence.validate()
        if not val_res.valid:
            logger.error(f"Validation failed prior to publishing. Errors: {val_res.errors}")
            return False
        return self.publish(evidence)

    def shutdown(self) -> None:
        """Cleanly shuts down the async thread pool executor."""
        self._executor.shutdown(wait=True)
