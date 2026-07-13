import pytest
from core.evidence.network_evidence import NetworkEvidence
from core.evidence.identity_evidence import IdentityEvidence
from core.evidence.endpoint_evidence import EndpointEvidence
from core.evidence.ot_evidence import OTEvidence
from core.evidence.schemas import DetectorType, EntityType
from core.evidence.severity import SeverityLevel

def test_network_evidence_schema():
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
        attack_family="DDoS",
        protocol="TCP",
        source_ip="192.168.1.1",
        destination_ip="10.0.0.1",
        flow_duration=15.6,
        top_network_features={"bytes_in": 1500}
    )
    
    assert net_ev.detector == "NETWORK"
    assert net_ev.entity == "192.168.1.1"
    assert net_ev.attack_family == "DDoS"
    assert net_ev.flow_duration == 15.6
    assert net_ev.top_network_features["bytes_in"] == 1500
    assert net_ev.schema_version == "v1"

def test_identity_evidence_schema():
    id_ev = IdentityEvidence(
        detector="IDENTITY",
        entity="adm_aanoush",
        entity_type="USER",
        timestamp="2026-07-13T19:00:00+00:00",
        window_start="2026-07-13T19:00:00+00:00",
        window_end="2026-07-13T19:10:00+00:00",
        confidence=0.85,
        risk_score=0.95,
        severity="CRITICAL",
        user="adm_aanoush",
        auth_count=52,
        computer_fanout=12,
        new_computer_ratio=0.75,
        off_hours=True
    )
    
    assert id_ev.detector == "IDENTITY"
    assert id_ev.auth_count == 52
    assert id_ev.computer_fanout == 12
    assert id_ev.new_computer_ratio == 0.75
    assert id_ev.off_hours is True

def test_endpoint_evidence_schema():
    ep_ev = EndpointEvidence(
        detector="ENDPOINT",
        entity="WORKSTATION-X",
        entity_type="HOST",
        timestamp="2026-07-13T19:00:00+00:00",
        window_start="2026-07-13T19:00:00+00:00",
        window_end="2026-07-13T19:10:00+00:00",
        confidence=1.0,
        risk_score=0.88,
        severity="HIGH",
        process="powershell.exe",
        sigma_hits=[{"rule_id": "sigma_01", "title": "Obfuscated Command"}],
        mitre_candidates=["T1059.001"]
    )
    
    assert ep_ev.detector == "ENDPOINT"
    assert ep_ev.process == "powershell.exe"
    assert len(ep_ev.sigma_hits) == 1
    assert ep_ev.mitre_candidates == ["T1059.001"]

def test_ot_evidence_schema():
    ot_ev = OTEvidence(
        detector="OT",
        entity="CNI-Process-PLC",
        entity_type="PLC",
        timestamp="2026-07-13T19:00:00+00:00",
        window_start="2026-07-13T19:00:00+00:00",
        window_end="2026-07-13T19:10:00+00:00",
        confidence=0.7,
        risk_score=0.35,
        severity="LOW",
        top_shifted_variables=["P1_V_A"],
        anomaly_score=0.8,
        attack_probability=0.22
    )
    
    assert ot_ev.detector == "OT"
    assert ot_ev.top_shifted_variables == ["P1_V_A"]
    assert ot_ev.anomaly_score == 0.8
    assert ot_ev.attack_probability == 0.22
