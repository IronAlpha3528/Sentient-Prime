import os
import tempfile
import pytest
from core.evidence.network_evidence import NetworkEvidence
from core.evidence.serializer import EvidenceSerializer

def test_json_and_dict_serialization():
    net_ev = NetworkEvidence(
        detector="NETWORK",
        entity="192.168.1.1",
        entity_type="HOST",
        timestamp="2026-07-13T19:00:00+00:00",
        window_start="2026-07-13T19:00:00+00:00",
        window_end="2026-07-13T19:10:00+00:00",
        confidence=0.987654321,  # high precision
        risk_score=0.123456789,   # high precision
        severity="MEDIUM",
        attack_family="Spyware"
    )

    # 1. Dict serialize / deserialize
    d_data = EvidenceSerializer.serialize(net_ev, format="dict")
    assert isinstance(d_data, dict)
    assert d_data["confidence"] == 0.987654321
    assert d_data["attack_family"] == "Spyware"

    net_ev_d = EvidenceSerializer.deserialize(d_data, format="dict")
    assert isinstance(net_ev_d, NetworkEvidence)
    assert net_ev_d.confidence == 0.987654321
    assert net_ev_d.attack_family == "Spyware"

    # 2. JSON serialize / deserialize
    json_data = EvidenceSerializer.serialize(net_ev, format="json")
    assert isinstance(json_data, str)
    assert "Spyware" in json_data

    net_ev_j = EvidenceSerializer.deserialize(json_data, format="json")
    assert isinstance(net_ev_j, NetworkEvidence)
    assert net_ev_j.confidence == 0.987654321
    assert net_ev_j.attack_family == "Spyware"

def test_bytes_serialization():
    net_ev = NetworkEvidence(
        detector="NETWORK",
        entity="192.168.1.1",
        entity_type="HOST",
        timestamp="2026-07-13T19:00:00+00:00",
        window_start="2026-07-13T19:00:00+00:00",
        window_end="2026-07-13T19:10:00+00:00",
        confidence=0.5,
        risk_score=0.5,
        severity="INFO"
    )
    b_data = EvidenceSerializer.serialize(net_ev, format="bytes")
    assert isinstance(b_data, bytes)
    
    net_ev_b = EvidenceSerializer.deserialize(b_data, format="bytes")
    assert isinstance(net_ev_b, NetworkEvidence)
    assert net_ev_b.detector == "NETWORK"

def test_file_save_and_load():
    net_ev = NetworkEvidence(
        detector="NETWORK",
        entity="192.168.1.1",
        entity_type="HOST",
        timestamp="2026-07-13T19:00:00+00:00",
        window_start="2026-07-13T19:00:00+00:00",
        window_end="2026-07-13T19:10:00+00:00",
        confidence=0.75,
        risk_score=0.8,
        severity="HIGH",
        attack_family="Exfiltration"
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        temp_filepath = os.path.join(tmpdir, "evidence.json")
        EvidenceSerializer.save(net_ev, temp_filepath, format="json")
        
        # Load back
        loaded = EvidenceSerializer.load(temp_filepath, format="json")
        assert isinstance(loaded, NetworkEvidence)
        assert loaded.attack_family == "Exfiltration"
        assert loaded.risk_score == 0.8
        assert loaded.confidence == 0.75
