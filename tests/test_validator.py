import pytest
from sentinel_prime.core.evidence.network_evidence import NetworkEvidence
from sentinel_prime.core.evidence.validator import validate_evidence

def test_valid_evidence_passes():
    net_ev = NetworkEvidence(
        detector="NETWORK",
        entity="192.168.1.1",
        entity_type="HOST",
        timestamp="2026-07-13T19:00:00+00:00",
        window_start="2026-07-13T19:00:00+00:00",
        window_end="2026-07-13T19:10:00+00:00",
        confidence=0.9,
        risk_score=0.4,
        severity="MEDIUM",
        top_reasons=["Reason 1"]
    )
    result = validate_evidence(net_ev)
    assert result.valid is True
    assert len(result.errors) == 0

def test_missing_required_fields_contract_fails():
    # Missing detector and entity
    net_ev = NetworkEvidence(
        detector="",
        entity="",
        entity_type="HOST",
        timestamp="2026-07-13T19:00:00+00:00",
        window_start="2026-07-13T19:00:00+00:00",
        window_end="2026-07-13T19:10:00+00:00",
        confidence=0.9,
        risk_score=0.4,
        severity="MEDIUM"
    )
    result = validate_evidence(net_ev)
    assert result.valid is False
    assert any("detector" in e or "entity" in e for e in result.errors)

def test_invalid_ranges_fails():
    net_ev = NetworkEvidence(
        detector="NETWORK",
        entity="10.0.0.1",
        entity_type="HOST",
        timestamp="2026-07-13T19:00:00+00:00",
        window_start="2026-07-13T19:00:00+00:00",
        window_end="2026-07-13T19:10:00+00:00",
        confidence=1.5,      # Invalid range > 1.0
        risk_score=-0.2,     # Invalid range < 0.0
        severity="MEDIUM"
    )
    result = validate_evidence(net_ev)
    assert result.valid is False
    assert any("confidence" in e for e in result.errors)
    assert any("risk_score" in e for e in result.errors)

def test_invalid_enums_fails():
    net_ev = NetworkEvidence(
        detector="MALICIOUS_BOT",  # Invalid detector enum
        entity="10.0.0.1",
        entity_type="VULNERABILITY", # Invalid entity type
        timestamp="2026-07-13T19:00:00+00:00",
        window_start="2026-07-13T19:00:00+00:00",
        window_end="2026-07-13T19:10:00+00:00",
        confidence=0.5,
        risk_score=0.5,
        severity="UNKNOWN_SEVERITY" # Invalid severity enum
    )
    result = validate_evidence(net_ev)
    assert result.valid is False
    assert any("detector" in e for e in result.errors)
    assert any("entity_type" in e for e in result.errors)
    assert any("severity" in e for e in result.errors)

def test_invalid_timestamp_format_fails():
    net_ev = NetworkEvidence(
        detector="NETWORK",
        entity="192.168.1.1",
        entity_type="HOST",
        timestamp="not-a-timestamp",  # Invalid format
        window_start="2026-07-13T19:00:00+00:00",
        window_end="2026-07-13T19:10:00+00:00",
        confidence=0.5,
        risk_score=0.5,
        severity="INFO"
    )
    result = validate_evidence(net_ev)
    assert result.valid is False
    assert any("timestamp" in e for e in result.errors)
