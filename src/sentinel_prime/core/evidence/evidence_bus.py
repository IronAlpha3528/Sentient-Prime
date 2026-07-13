import threading
from typing import Any, Dict, Optional
from sentinel_prime.core.evidence.base_evidence import BaseEvidence
from sentinel_prime.core.evidence.event import EvidenceEvent
from sentinel_prime.core.evidence.stream_manager import StreamManager
from sentinel_prime.core.evidence.subscriber import Subscriber

class EvidenceBus:
    """The central communication interface for Sentient-Prime.

    Uses a thread-safe Singleton pattern to share the underlying StreamManager.
    """
    _instance: Optional['EvidenceBus'] = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(EvidenceBus, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self, config_path: str = "config/evidence_bus.yaml"):
        if getattr(self, '_initialized', False):
            return
        self.stream_manager = StreamManager(config_path=config_path)
        self._initialized = True

    @classmethod
    def get_instance(cls) -> 'EvidenceBus':
        """Convenience method to retrieve the running EvidenceBus instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def push(self, evidence: BaseEvidence) -> bool:
        """Submit a new BaseEvidence object to the bus.

        Validates, normalizes, deduplicates, and enqueues the event.
        """
        return self.stream_manager.push(evidence)

    def pull(self) -> Optional[EvidenceEvent]:
        """Dequeues the highest priority event currently in the queue."""
        return self.stream_manager.pull()

    def register(self, subscriber: Subscriber) -> None:
        """Registers a subscriber to receive matching broadcasted events."""
        self.stream_manager.register(subscriber)

    def unregister(self, subscriber: Subscriber) -> None:
        """Unregisters a subscriber from the bus."""
        self.stream_manager.unregister(subscriber)

    def health(self) -> Dict[str, Any]:
        """Runs checks on the queue, cache, and subscriber list to diagnose system health."""
        return self.stream_manager.health()

    def metrics(self) -> Dict[str, Any]:
        """Retrieves real-time metrics of events, latency, queue depth, etc."""
        return self.stream_manager.metrics()

    def shutdown(self) -> None:
        """Cleanly halts background dispatch workers and exports metrics."""
        self.stream_manager.shutdown()
        with EvidenceBus._lock:
            EvidenceBus._instance = None
