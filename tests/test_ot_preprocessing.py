import os
import json
import pytest
import pandas as pd
import numpy as np
from pathlib import Path

from detectors.ot.dataset_discovery import discover_ot_datasets
from detectors.ot.hai_loader import load_ot_dataset_incremental
from detectors.ot.timeseries_normalizer import TimeseriesNormalizer, classify_columns, analyze_temporal_integrity, analyze_missing_values
from detectors.ot.window_builder import build_sliding_windows
from detectors.ot.feature_builder import build_features_for_window
from detectors.ot.feature_contract import generate_feature_contract

@pytest.fixture
def mock_ot_csv(tmp_path):
    # Create a mock timeseries dataset representing HAI process logs
    rows = 200
    timestamps = pd.date_range(start="2026-07-09 12:00:00", periods=rows, freq="1s")
    
    # Introduce some duplicates and a gap for testing
    ts_list = list(timestamps)
    ts_list[10] = ts_list[9]  # Duplicate
    # Introduce a gap of 5 seconds at index 100
    for idx in range(100, len(ts_list)):
        ts_list[idx] = ts_list[idx] + pd.Timedelta(seconds=5)
        
    data = {
        "timestamp": ts_list,
        "P1_FCV01D": np.random.choice([0.0, 1.0], size=rows), # Actuator (binary)
        "P1_PP01AR": np.random.choice([0.0, 1.0, 2.0], size=rows), # Actuator (low cardinality)
        "P1_PV01": np.random.normal(loc=50.0, scale=2.0, size=rows), # Sensor (continuous)
        "P2_PV02": np.random.normal(loc=10.0, scale=0.5, size=rows), # Sensor (continuous)
        "P3_PV03": np.random.normal(loc=100.0, scale=10.0, size=rows), # Sensor (continuous)
        "P4_PV04": np.random.normal(loc=5.0, scale=0.1, size=rows), # Sensor (continuous)
        "P5_PV05": np.random.normal(loc=0.0, scale=1.0, size=rows), # Sensor (continuous)
        "P6_PV06": np.random.normal(loc=30.0, scale=3.0, size=rows), # Sensor (continuous)
        "P1_SP01": np.full(rows, 50.0), # Setpoint (constant)
        "P1_PID01": np.random.normal(loc=40.0, scale=1.0, size=rows), # Controller
        "attack": np.zeros(rows, dtype=int)
    }
    # Set a portion of labels as attack
    data["attack"][50:60] = 1
    
    # Add some null values to check missing values analyzer
    data["P2_PV02"][20:25] = np.nan
    
    df = pd.DataFrame(data)
    csv_file = tmp_path / "mock_hai_train.csv"
    df.to_csv(csv_file, index=False)
    return csv_file

def test_dataset_discovery(tmp_path, mock_ot_csv):
    manifests = discover_ot_datasets(str(tmp_path))
    assert len(manifests) == 1
    m = manifests[0]
    assert m.timestamp_column == "timestamp"
    assert m.label_column == "attack"
    assert m.column_count == 12
    assert m.row_estimate > 100

def test_csv_loading_incremental(mock_ot_csv):
    loader = load_ot_dataset_incremental(str(mock_ot_csv), chunk_size=50, timestamp_col="timestamp")
    chunks = list(loader)
    assert len(chunks) == 4 # 200 rows / 50 chunk_size
    assert chunks[0].shape == (50, 12)
    assert pd.api.types.is_datetime64_any_dtype(chunks[0]["timestamp"])

def test_timeseries_normalization_and_classification(mock_ot_csv):
    df = pd.read_csv(mock_ot_csv)
    normalizer = TimeseriesNormalizer(timestamp_col="timestamp", label_col="attack")
    norm_df = normalizer.fit_normalize(df)
    
    # Verify classifications
    assert normalizer.classification["P1_PV01"] == "Sensor"
    assert normalizer.classification["P1_FCV01D"] == "Actuator"
    assert normalizer.classification["P1_SP01"] == "Setpoint"
    assert normalizer.classification["P1_PID01"] == "Controller"
    
    # Check temporal reports
    assert normalizer.temporal_report["duplicate_count"] == 1
    assert normalizer.temporal_report["gap_count"] >= 1
    assert isinstance(normalizer.temporal_report["is_monotonic"], bool)

    # Check missing report
    assert normalizer.missing_report["P2_PV02"]["missing_percentage"] > 0
    assert normalizer.missing_report["P1_SP01"]["status"] == "constant"

def test_window_builder_and_labeling(mock_ot_csv):
    df = pd.read_csv(mock_ot_csv)
    normalizer = TimeseriesNormalizer(timestamp_col="timestamp", label_col="attack")
    norm_df = normalizer.fit_normalize(df)
    
    # Build windows (60 samples, stride 10)
    windows = list(build_sliding_windows(norm_df, window_length=60, stride=10))
    
    # Check first window
    assert len(windows) > 0
    win0 = windows[0]
    meta = win0["metadata"]
    assert meta.row_count == 60
    assert meta.duration_seconds == 60.0
    
    # Verify attack label propagation (indices 50:60 were attack)
    # The first window (0 to 60) should contain attack events, so label should be 1
    assert meta.label == 1
    assert meta.attack_ratio > 0.0

def test_feature_generation_and_contract(mock_ot_csv, tmp_path):
    df = pd.read_csv(mock_ot_csv)
    normalizer = TimeseriesNormalizer(timestamp_col="timestamp", label_col="attack")
    norm_df = normalizer.fit_normalize(df)
    
    windows = list(build_sliding_windows(norm_df, window_length=60, stride=10))
    win = windows[0]
    
    feats = build_features_for_window(win)
    
    # Verify rolling stats exist
    assert "sensor_P1_PV01_mean" in feats
    assert "sensor_P1_PV01_std" in feats
    assert "sensor_P1_PV01_flatline_duration" in feats
    assert "actuator_P1_FCV01D_state_changes" in feats
    assert "cross_corr_sensor_P1_PV01_vs_sensor_P2_PV02" in feats
    
    # Verify contract generation
    contract_file = tmp_path / "feature_contract.json"
    generate_feature_contract(feats, str(contract_file))
    
    assert contract_file.exists()
    with open(contract_file, "r") as f:
        contract = json.load(f)
    assert "sensor_P1_PV01_mean" in contract
    assert contract["sensor_P1_PV01_mean"]["dtype"] == "float64"
