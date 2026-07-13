import time
import pytest
from sentinel_prime.core.evidence import EvidenceBus, NetworkEvidence, OTEvidence, Subscriber, EvidenceEvent
from sentinel_prime.core.evidence.subscriber import SubscriberFilter

class DummySubscriber(Subscriber):
    """A test subscriber that accumulates received events in memory."""
    def __init__(self, name: str, filter_criteria=None):
        super().__init__(name, filter_criteria)
        self.received_events = []

    def receive(self, event: EvidenceEvent) -> None:
        self.received_events.append(event)

    def health(self) -> str:
        return "Healthy"

def test_subscriber_registration():
    bus = EvidenceBus.get_instance()
    sub = DummySubscriber("TestRegSub")
    bus.register(sub)
    assert sub.is_subscribed is True
    assert sub in bus.stream_manager.subscribers
    bus.unregister(sub)
    assert sub.is_subscribed is False
    assert sub not in bus.stream_manager.subscribers

def test_subscriber_filtering():
    # Fresh bus instance for test isolation
    bus = EvidenceBus()
    
    # 1. Filter: NETWORK only
    net_filter = SubscriberFilter(detectors=["NETWORK"])
    net_sub = DummySubscriber("NetworkSub", net_filter)
    bus.register(net_sub)

    # 2. Filter: HIGH or CRITICAL only
    high_filter = SubscriberFilter(severities=["HIGH", "CRITICAL"])
    high_sub = DummySubscriber("HighSub", high_filter)
    bus.register(high_sub)

    # Push a NETWORK evidence with MEDIUM severity
    net_ev = NetworkEvidence(
        detector="NETWORK",
        entity="192.168.1.1",
        entity_type="HOST",
        timestamp="2026-07-13T19:00:00+00:00",
        window_start="2026-07-13T19:00:00+00:00",
        window_end="2026-07-13T19:10:00+00:00",
        confidence=0.9,
        risk_score=0.4,
        severity="MEDIUM"
    )
    bus.push(net_ev)

    # Push an OT evidence with HIGH severity
    ot_ev = OTEvidence(
        detector="OT",
        entity="CNI-Process-PLC",
        entity_type="PLC",
        timestamp="2026-07-13T19:01:00+00:00",
        window_start="2026-07-13T19:00:00+00:00",
        window_end="2026-07-13T19:10:00+00:00",
        confidence=0.8,
        risk_score=0.75,
        severity="HIGH"
    )
    bus.push(ot_ev)

    # Allow time for background dispatcher thread to process events
    time.sleep(0.2)

    # NetworkSub should have received exactly 1 event (NETWORK)
    assert len(net_sub.received_events) == 1
    assert net_sub.received_events[0].detector == "NETWORK"

    # HighSub should have received exactly 1 event (OT with HIGH severity)
    assert len(high_sub.received_events) == 1
    assert high_sub.received_events[0].detector == "OT"
    assert high_sub.received_events[0].payload["severity"] == "HIGH"

    bus.unregister(net_sub)
    bus.unregister(high_sub)
    bus.shutdown()
