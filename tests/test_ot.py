import os
import json
import pytest
from pathlib import Path
import numpy as np

from sentinel_prime.detection.detectors.ot.ot_evidence import OTEvidence
from sentinel_prime.detection.detectors.ot.anomaly_calibrator import AnomalyCalibrator
from sentinel_prime.detection.detectors.ot.evidence_generator import OTEvidenceGenerator, generate_top_shifted_variables
from sentinel_prime.detection.detectors.ot.ot_detector import OTDetector
from sentinel_prime.detection.detectors.ot.ot_model import OTModel

def test_anomaly_calibration():
    # Fit calibrator on simple sample raw scores (more negative is anomalous)
    raw_scores = np.array([-0.3, -0.32, -0.31, -0.35, -0.42, -0.30])
    
    calibrator = AnomalyCalibrator()
    calibrator.fit(raw_scores)
    
    # Check calibrated values
    score_norm, severity = calibrator.calibrate(-0.31)
    assert 0.0 <= score_norm <= 1.0
    assert severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

def test_evidence_generation():
    features = {
        "sensor_P1_PV01_mean": 10.0,
        "sensor_P1_PV01_range": 5.0,
        "sensor_P2_PV02_mean": 100.0,
        "sensor_P2_PV02_range": 20.0
    }
    window_meta = {
        "host": "PLC-01",
        "start_time": "12:00:00",
        "end_time": "12:01:00",
        "label": 0,
        "attack_ratio": 0.0
    }
    baseline_stats = {
        "sensor_P1_PV01": {"mean": 8.0, "std": 1.0},
        "sensor_P2_PV02": {"mean": 50.0, "std": 10.0}
    }
    
    gen = OTEvidenceGenerator(baseline_stats=baseline_stats)
    evidence = gen.create_evidence(
        anomaly_score=0.82,
        attack_probability=0.0,
        severity="HIGH",
        features=features,
        window_metadata=window_meta
    )
    
    assert evidence.detector == "ot"
    assert evidence.entity == "PLC-01"
    assert evidence.severity == "HIGH"
    assert evidence.anomaly_score == 0.82
    assert "P2_PV02" in evidence.top_shifted_variables # 100 vs 50 (dev = 5) is larger than 10 vs 8 (dev = 2)

def test_ot_detector_health_and_metadata():
    detector = OTDetector()
    health = detector.health()
    # It should be healthy since we trained models/ot/
    assert "Healthy" in health or "Degraded" in health
    
    meta = detector.metadata()
    assert meta["detector_id"] == "ot-specialist"
    assert meta["features_count"] == 461
