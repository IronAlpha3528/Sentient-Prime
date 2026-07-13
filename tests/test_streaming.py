import time
import pytest
from core.evidence import EvidenceBus, NetworkEvidence, EventPriority, EvidenceEvent, EventStatus
from core.evidence.event_queue import EventQueue

def test_priority_scheduling_order():
    """Directly tests the EventQueue class to ensure high-priority events are

    dequeued first, regardless of enqueue order.
    """
    queue = EventQueue(max_size=10)
    
    ev_low = EvidenceEvent(
        event_id="low-event",
        timestamp="2026-07-13T19:00:00+00:00",
        detector="NETWORK",
        entity="10.0.0.1",
        payload={"severity": "LOW"},
        priority=EventPriority.LOW,
        status=EventStatus.CREATED
    )
    
    ev_high = EvidenceEvent(
        event_id="high-event",
        timestamp="2026-07-13T19:01:00+00:00",
        detector="NETWORK",
        entity="10.0.0.2",
        payload={"severity": "HIGH"},
        priority=EventPriority.HIGH,
        status=EventStatus.CREATED
    )
    
    ev_critical = EvidenceEvent(
        event_id="critical-event",
        timestamp="2026-07-13T19:02:00+00:00",
        detector="NETWORK",
        entity="10.0.0.3",
        payload={"severity": "CRITICAL"},
        priority=EventPriority.CRITICAL,
        status=EventStatus.CREATED
    )

    # Enqueue low, then critical, then high
    assert queue.enqueue(ev_low) is True
    assert queue.enqueue(ev_critical) is True
    assert queue.enqueue(ev_high) is True

    # Dequeue order should be: critical, high, low
    first = queue.dequeue()
    assert first is not None
    assert first.event_id == "critical-event"
    assert first.status == EventStatus.PROCESSING

    second = queue.dequeue()
    assert second is not None
    assert second.event_id == "high-event"

    third = queue.dequeue()
    assert third is not None
    assert third.event_id == "low-event"

def test_duplicate_discard():
    """Tests hash-based and ID-based duplicate discarding inside the EvidenceBus."""
    bus = EvidenceBus()
    bus.stream_manager.cache.clear()

    net_ev = NetworkEvidence(
        detector="NETWORK",
        entity="192.168.1.1",
        entity_type="HOST",
        timestamp="2026-07-13T19:00:00+00:00",
        window_start="2026-07-13T19:00:00+00:00",
        window_end="2026-07-13T19:10:00+00:00",
        confidence=0.95,
        risk_score=0.45,
        severity="MEDIUM",
        attack_family="Trojan"
    )

    # First push: should be accepted
    assert bus.push(net_ev) is True

    # Second push (identical payload): should be discarded as a duplicate
    assert bus.push(net_ev) is False
    
    # Assert metrics capture duplicate discard count
    metrics = bus.metrics()
    assert metrics["duplicates_removed"] >= 1
    assert metrics["events_dropped"] >= 1

    # Clean shutdown
    bus.shutdown()
