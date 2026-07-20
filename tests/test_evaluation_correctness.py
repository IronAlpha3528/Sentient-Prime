import json
import pytest
import sys
import importlib
from pathlib import Path

# Add scripts/eval to sys.path to allow standalone import
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "scripts" / "eval"))

eval_ml_detectors = importlib.import_module("eval_ml_detectors")

_load_dataset = eval_ml_detectors._load_dataset
_build_identity_features = eval_ml_detectors._build_identity_features
eval_network_detector = eval_ml_detectors.eval_network_detector
eval_identity_detector = eval_ml_detectors.eval_identity_detector
eval_endpoint_detector = eval_ml_detectors.eval_endpoint_detector
eval_ot_detector = eval_ml_detectors.eval_ot_detector

def test_load_dataset():
    dataset = _load_dataset()
    assert isinstance(dataset, list)
    assert len(dataset) > 0
    assert "network" in dataset[0]
    assert "identity" in dataset[0]
    assert "endpoint" in dataset[0]
    assert "ot" in dataset[0]

def test_network_detector_eval_run():
    dataset = _load_dataset()[:5]
    result = eval_network_detector(dataset)
    assert result["status"] == "OK"
    assert "recall_detection_rate" in result

def test_identity_detector_eval_run():
    dataset = _load_dataset()[:5]
    result = eval_identity_detector(dataset)
    assert result["status"] == "OK"
    assert "false_positive_rate" in result

def test_endpoint_detector_eval_run():
    dataset = _load_dataset()[:5]
    result = eval_endpoint_detector(dataset)
    assert result["status"] == "OK"
    assert "f1" in result

def test_ot_detector_eval_run():
    dataset = _load_dataset()[:5]
    result = eval_ot_detector(dataset)
    assert result["status"] == "OK"
    assert "roc_auc" in result

def test_identity_feature_generation():
    # Benign signature sample
    id_sig = {"auth_count": 4, "computer_fanout": 1, "off_hours": False}
    features = _build_identity_features(id_sig)
    
    # Expected aligned z-score output
    assert features["auth_count_zscore"] == 0.0
    assert features["unique_computers_zscore"] == 0.0
    assert features["mean_auth_gap_zscore"] == 0.0
    assert features["new_computer_ratio"] == 0.0
