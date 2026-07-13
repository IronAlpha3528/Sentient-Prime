import os
import json
import pytest
from pathlib import Path

from sentinel_prime.detection.detectors.endpoint.schemas import EndpointEvent
from sentinel_prime.detection.detectors.endpoint.event_normalizer import normalize_event
from sentinel_prime.detection.detectors.endpoint.process_window_builder import build_process_windows
from sentinel_prime.detection.detectors.endpoint.feature_builder import build_features_for_window
from sentinel_prime.detection.detectors.endpoint.endpoint_model import EndpointModel
from sentinel_prime.detection.detectors.endpoint.sigma_loader import SigmaRule
from sentinel_prime.detection.detectors.endpoint.sigma_engine import SigmaEngine
from sentinel_prime.detection.detectors.endpoint.evidence_fusion import fuse_predictions_and_rules
from sentinel_prime.detection.detectors.endpoint.endpoint_detector import EndpointDetector

def test_endpoint_specialist_integration(tmp_path):
    # 1. Synthetic Endpoint Events
    raw_events = [
        {
            "EventID": 1,
            "UtcTime": "2026-07-09T12:00:00.000Z",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -enc abc",
            "ProcessId": 2048,
            "ParentProcessId": 1000,
            "ParentImage": "explorer.exe",
            "User": "SYSTEM",
            "Computer": "HOST-INTEGRATION-01",
            "ProviderName": "Microsoft-Windows-Sysmon"
        },
        {
            "EventID": 10,
            "UtcTime": "2026-07-09T12:00:15.000Z",
            "SourceProcessId": 2048,
            "SourceImage": "powershell.exe",
            "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "GrantedAccess": "0x1fffff",
            "User": "SYSTEM",
            "Computer": "HOST-INTEGRATION-01",
            "ProviderName": "Microsoft-Windows-Sysmon"
        }
    ]

    # 2. Event Normalization
    normalized = []
    for raw in raw_events:
        ev, discard = normalize_event(raw)
        assert ev is not None
        assert discard is None
        normalized.append(ev)

    assert len(normalized) == 2

    # 3. Process Window Builder
    windows = build_process_windows(normalized, window_duration_seconds=60)
    assert len(windows) == 1
    win = windows[0]
    assert win["process"] == "powershell.exe"
    assert win["event_count"] == 2

    # 4. Feature Builder
    features = build_features_for_window(win)
    assert features["powershell_flag"] == 1.0
    assert features["encoded_command_flag"] == 1.0
    assert features["lsass_access_count"] == 1.0

    # 5. Sigma Matching
    rule = SigmaRule(
        rule_id="rule-test-lsass",
        title="Access to LSASS memory",
        description="Detects processes accessing LSASS process memory",
        severity="high",
        tags=["attack.credential_access", "attack.t1003.001"],
        detection={
            "selection": {
                "TargetImage|contains": "lsass.exe",
                "GrantedAccess": "0x1fffff"
            },
            "condition": "selection"
        }
    )
    engine = SigmaEngine([rule])
    
    sigma_matches = []
    for ev in normalized:
        matches = engine.match_event(ev)
        for m in matches:
            sigma_matches.append(m)
            
    assert len(sigma_matches) == 1
    assert sigma_matches[0]["rule_name"] == "Access to LSASS memory"

    # 6. Evidence Fusion
    # We pass a mock raw probability
    evidence = fuse_predictions_and_rules(
        ml_risk_score=0.80,
        sigma_matches=sigma_matches,
        features=features,
        window=win
    )
    
    assert evidence.risk_score == 0.95  # Case 1: High ML + High Sigma -> Critical (Risk >= 0.95)
    assert evidence.severity == "critical"
    assert "LSASS memory access observed" in evidence.top_reasons
    assert "T1003.001" in evidence.mitre_candidates
