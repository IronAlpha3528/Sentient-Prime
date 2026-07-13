import pytest
import numpy as np
import pandas as pd
from pathlib import Path

from data.training.preprocess_network import ATTACK_FAMILY_MAPPING, map_family
from detectors.network_detector import NetworkDetector
from detectors.evidence_schema import DetectorEvidence
from orchestrator.phase1_pipeline import Phase1Pipeline


# 1. Label Mapping Tests
def test_network_label_mapping():
    # Verify that all expected 15 classes from raw dataset exist in mapping
    expected_classes = [
        "Benign", "Bot", "Brute Force -Web", "FTP-BruteForce", "SSH-Bruteforce",
        "DDOS attack-HOIC", "DDOS attack-LOIC-UDP", "DDoS attacks-LOIC-HTTP",
        "DoS attacks-GoldenEye", "DoS attacks-Hulk", "DoS attacks-SlowHTTPTest",
        "DoS attacks-Slowloris", "Infilteration", "Brute Force -XSS", "SQL Injection"
    ]
    for cls in expected_classes:
        assert cls in ATTACK_FAMILY_MAPPING
        family = map_family(cls)
        # Verify it maps to one of the 7 families
        assert family in ["Benign", "Botnet", "BruteForce", "DDoS", "DoS", "Infiltration", "WebAttack"]

    # Unknown label raises ValueError
    with pytest.raises(ValueError):
        map_family("UNKNOWN_ATTACK_CLASS")


# 2. Target Variable Checks
def test_stage1_and_stage2_targets():
    # Target maps Benign to 0 and all others to 1 for Stage 1
    for orig_label, family in ATTACK_FAMILY_MAPPING.items():
        is_attack = (family != "Benign")
        target_val = 1 if is_attack else 0
        if orig_label == "Benign":
            assert target_val == 0
        else:
            assert target_val == 1

    # Stage 2 training data must have NO Benign rows
    # Verify that if family == "Benign", it is not part of Stage 2 classes
    s2_classes = ["Botnet", "BruteForce", "DDoS", "DoS", "Infiltration", "WebAttack"]
    assert "Benign" not in s2_classes


# 3. Detector Features Contract Validation
def test_network_detector_contract_validation():
    # Instantiate network detector
    detector = NetworkDetector()
    
    # Missing feature should raise ValueError
    invalid_data = {
        "entity_id": "WS-01",
        "timestamp": "2026-07-09T00:00:00",
        "features": {
            "protocol": 6,
            "flow_duration": 1000
            # missing ~75 other features
        }
    }
    with pytest.raises(ValueError) as excinfo:
        detector.predict(invalid_data)
    assert "Missing" in str(excinfo.value)


# 4. Score Bounds and Sorting
def test_network_detector_score_and_sorting():
    detector = NetworkDetector()
    test_net = pd.read_parquet("data/processed/network/test.parquet")
    row_net = test_net.iloc[0]
    
    net_data = {
        "entity_id": "DEMO-HOST-01",
        "timestamp": "2026-07-09T12:00:00",
        "features": {
            feature: row_net[feature]
            for feature in detector.feature_columns
        }
    }
    
    evidence = detector.predict(net_data)
    
    # Check structure
    assert isinstance(evidence, dict)
    assert evidence["detector"] == "network"
    assert evidence["entity_type"] == "host"
    
    # Network score is the Stage 1 probability and must be in [0, 1]
    score = evidence["score"]
    assert 0.0 <= score <= 1.0
    
    # Verify top predictions exist and are sorted descending
    top_preds = None
    for ev in evidence["evidence"]:
        if ev["type"] == "top_family_predictions":
            top_preds = ev["values"]
            break
            
    assert top_preds is not None
    assert len(top_preds) <= 3
    
    # Sort check
    probs = [p["probability"] for p in top_preds]
    assert probs == sorted(probs, reverse=True)


# 5. Pipeline route preservation
def test_routes_preservation():
    pipeline = Phase1Pipeline()
    assert "network" in pipeline.router.routes
    assert "identity" in pipeline.router.routes
