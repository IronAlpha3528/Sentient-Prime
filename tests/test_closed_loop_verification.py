import os
import tempfile
import time
from pathlib import Path
from datetime import datetime, timezone
import pytest
import threading

from sentinel_prime.core.framework import Framework
from sentinel_prime.core.evidence import BaseEvidence, EvidenceBus
from sentinel_prime.core.telemetry.ledger import AuditLedger
from sentinel_prime.soar.orchestrator.dispatcher import SOARDispatcher
from sentinel_prime.soar.orchestrator.verification import VerificationEngine, IncidentState

def test_successful_containment(tmp_path):
    # Test that when no new telemetry is received, containment is marked successful.
    ledger_path = tmp_path / "audit_success.jsonl"
    ledger = AuditLedger(ledger_path)
    
    cfg_content = f"""
graph_radius: 2
max_nodes: 50
max_edges: 100
timeline_window: 30
export_directory: "{str(tmp_path).replace('\\', '/')}"
"""
    cfg_file = tmp_path / "framework_test.yaml"
    cfg_file.write_text(cfg_content)

    framework = Framework(config_path=str(cfg_file))
    framework.graph_manager.store.clear()

    dispatcher = SOARDispatcher(ledger=ledger)
    # Configure fast verification
    dispatcher.verification_engine.delay_seconds = 0.5
    dispatcher.verification_engine.retry_count = 2
    dispatcher.verification_engine.retry_interval_seconds = 0.2

    incident_id = "INC-TEST-SUCCESS"
    incident = {
        "incident_id": incident_id,
        "asset": "203.0.113.10",
        "entity_type": "HOST",
        "confidence": 0.9,
        "attacker_ip": "203.0.113.10",
        "response_agent_plan": {
            "recommended_actions": [{"action_name": "Block Source IP"}]
        }
    }

    # Dispatch executes actions and schedules async verification
    result = dispatcher.dispatch(incident)
    assert result["decision"] == "AUTO"
    assert result["outcome"]["status"] == "RESOLVED"

    # Wait for verification loop to complete
    time.sleep(1.2)

    # Verify final states
    final_state = dispatcher.verification_engine.get_incident_state(incident_id)
    assert final_state == IncidentState.RESOLVED
    assert ledger.verify_chain()

    framework.shutdown()

def test_failed_containment(tmp_path):
    # Test that if fresh high-risk telemetry persists, containment fails and escalates.
    ledger_path = tmp_path / "audit_fail.jsonl"
    ledger = AuditLedger(ledger_path)
    
    cfg_content = f"""
graph_radius: 2
max_nodes: 50
max_edges: 100
timeline_window: 30
export_directory: "{str(tmp_path).replace('\\', '/')}"
"""
    cfg_file = tmp_path / "framework_test.yaml"
    cfg_file.write_text(cfg_content)

    framework = Framework(config_path=str(cfg_file))
    framework.graph_manager.store.clear()

    dispatcher = SOARDispatcher(ledger=ledger)
    dispatcher.verification_engine.delay_seconds = 0.5
    dispatcher.verification_engine.retry_count = 2
    dispatcher.verification_engine.retry_interval_seconds = 0.2
    dispatcher.verification_engine.escalation_threshold = 0.7

    incident_id = "INC-TEST-FAIL"
    incident = {
        "incident_id": incident_id,
        "asset": "203.0.113.11",
        "entity_type": "HOST",
        "confidence": 0.95,
        "attacker_ip": "203.0.113.11",
        "response_agent_plan": {
            "recommended_actions": [{"action_name": "Block Source IP"}]
        }
    }

    result = dispatcher.dispatch(incident)
    assert result["decision"] == "AUTO"
    assert result["outcome"]["status"] == "RESOLVED"

    # Simulate fresh high-risk telemetry arriving during verification window
    time.sleep(0.2)
    ev = BaseEvidence(
        detector="NETWORK",
        entity="203.0.113.11",
        entity_type="HOST",
        timestamp=datetime.now(timezone.utc).isoformat(),
        window_start=datetime.now(timezone.utc).isoformat(),
        window_end=datetime.now(timezone.utc).isoformat(),
        confidence=0.9,
        risk_score=0.85, # High risk (> threshold 0.7)
        severity="HIGH",
        top_reasons=["Persistent scanning"]
    )
    framework.push(ev)

    time.sleep(1.0)

    final_state = dispatcher.verification_engine.get_incident_state(incident_id)
    assert final_state == IncidentState.ESCALATED
    assert ledger.verify_chain()

    framework.shutdown()

def test_partial_containment(tmp_path):
    # Test that if fresh low-risk telemetry persists, state is marked PARTIALLY_CONTAINED.
    ledger_path = tmp_path / "audit_partial.jsonl"
    ledger = AuditLedger(ledger_path)
    
    cfg_content = f"""
graph_radius: 2
max_nodes: 50
max_edges: 100
timeline_window: 30
export_directory: "{str(tmp_path).replace('\\', '/')}"
"""
    cfg_file = tmp_path / "framework_test.yaml"
    cfg_file.write_text(cfg_content)

    framework = Framework(config_path=str(cfg_file))
    framework.graph_manager.store.clear()

    dispatcher = SOARDispatcher(ledger=ledger)
    dispatcher.verification_engine.delay_seconds = 0.4
    dispatcher.verification_engine.retry_count = 2
    dispatcher.verification_engine.retry_interval_seconds = 0.2
    dispatcher.verification_engine.escalation_threshold = 0.7

    incident_id = "INC-TEST-PARTIAL"
    incident = {
        "incident_id": incident_id,
        "asset": "203.0.113.12",
        "entity_type": "HOST",
        "confidence": 0.9,
        "attacker_ip": "203.0.113.12",
        "response_agent_plan": {
            "recommended_actions": [{"action_name": "Block Source IP"}]
        }
    }

    result = dispatcher.dispatch(incident)
    assert result["decision"] == "AUTO"
    assert result["outcome"]["status"] == "RESOLVED"

    # Simulate fresh low-risk telemetry arriving
    time.sleep(0.1)
    ev = BaseEvidence(
        detector="NETWORK",
        entity="203.0.113.12",
        entity_type="HOST",
        timestamp=datetime.now(timezone.utc).isoformat(),
        window_start=datetime.now(timezone.utc).isoformat(),
        window_end=datetime.now(timezone.utc).isoformat(),
        confidence=0.8,
        risk_score=0.3, # Low risk (< threshold 0.7)
        severity="LOW",
        top_reasons=["Low priority noise"]
    )
    framework.push(ev)

    time.sleep(0.8)

    final_state = dispatcher.verification_engine.get_incident_state(incident_id)
    assert final_state == IncidentState.PARTIALLY_CONTAINED
    assert ledger.verify_chain()

    framework.shutdown()

def test_monitoring_unavailable(tmp_path):
    # Test that verification loops fails gracefully if GraphManager is unavailable.
    ledger_path = tmp_path / "audit_unavail.jsonl"
    ledger = AuditLedger(ledger_path)

    # Note: No Framework is instantiated in this test, so GraphManager subscriber is not registered.
    dispatcher = SOARDispatcher(ledger=ledger)
    dispatcher.verification_engine.delay_seconds = 0.2
    dispatcher.verification_engine.retry_count = 1

    incident_id = "INC-UNAVAILABLE"
    incident = {
        "incident_id": incident_id,
        "asset": "203.0.113.13",
        "entity_type": "HOST",
        "confidence": 0.9,
        "attacker_ip": "203.0.113.13",
        "response_agent_plan": {
            "recommended_actions": [{"action_name": "Block Source IP"}]
        }
    }

    dispatcher.dispatch(incident)
    time.sleep(0.4)

    final_state = dispatcher.verification_engine.get_incident_state(incident_id)
    assert final_state == IncidentState.ESCALATED
    assert ledger.verify_chain()

def test_multiple_incidents_concurrent(tmp_path):
    # Test handling multiple concurrent verifications in parallel
    ledger_path = tmp_path / "audit_multiple.jsonl"
    ledger = AuditLedger(ledger_path)
    
    cfg_content = f"""
graph_radius: 2
max_nodes: 50
max_edges: 100
timeline_window: 30
export_directory: "{str(tmp_path).replace('\\', '/')}"
"""
    cfg_file = tmp_path / "framework_test.yaml"
    cfg_file.write_text(cfg_content)

    framework = Framework(config_path=str(cfg_file))
    framework.graph_manager.store.clear()

    dispatcher = SOARDispatcher(ledger=ledger)
    dispatcher.verification_engine.delay_seconds = 0.5
    dispatcher.verification_engine.retry_count = 2
    dispatcher.verification_engine.retry_interval_seconds = 0.1

    # Start multiple incidents concurrently
    incidents = [
        {"incident_id": "INC-MULTIPLE-1", "asset": "203.0.113.14", "entity_type": "HOST", "confidence": 0.9, "attacker_ip": "203.0.113.14", "response_agent_plan": {"recommended_actions": [{"action_name": "Block Source IP"}]}},
        {"incident_id": "INC-MULTIPLE-2", "asset": "203.0.113.15", "entity_type": "HOST", "confidence": 0.9, "attacker_ip": "203.0.113.15", "response_agent_plan": {"recommended_actions": [{"action_name": "Block Source IP"}]}},
        {"incident_id": "INC-MULTIPLE-3", "asset": "203.0.113.16", "entity_type": "HOST", "confidence": 0.9, "attacker_ip": "203.0.113.16", "response_agent_plan": {"recommended_actions": [{"action_name": "Block Source IP"}]}}
    ]

    for inc in incidents:
        dispatcher.dispatch(inc)

    # Wait for all loops to complete
    time.sleep(1.2)

    for inc in incidents:
        state = dispatcher.verification_engine.get_incident_state(inc["incident_id"])
        assert state == IncidentState.RESOLVED

    framework.shutdown()

def test_race_conditions_thread_safety():
    # Test thread safety of state updates
    engine = VerificationEngine()
    
    def worker(incident_id, state):
        for i in range(10):
            engine.transition_state(incident_id, state, f"Worker loop {i}")
            time.sleep(0.01)

    threads = []
    for i in range(10):
        t = threading.Thread(target=worker, args=(f"INC-{i}", IncidentState.RESOLVED))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    # All should be RESOLVED
    for i in range(10):
        assert engine.get_incident_state(f"INC-{i}") == IncidentState.RESOLVED
