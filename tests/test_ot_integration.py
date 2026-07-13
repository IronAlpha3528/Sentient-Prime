import os
import json
import pytest
import pandas as pd
import numpy as np

from detectors.ot.timeseries_normalizer import TimeseriesNormalizer
from detectors.ot.window_builder import build_sliding_windows
from detectors.ot.feature_builder import build_features_for_window
from detectors.ot.ot_detector import OTDetector

def test_ot_pipeline_integration():
    # 1. Generate synthetic raw timeseries data representing HAI logs
    rows = 70
    timestamps = pd.date_range(start="2026-07-09 12:00:00", periods=rows, freq="1s")
    
    raw_data = {
        "timestamp": timestamps,
        "P1_FCV01D": np.random.choice([0.0, 1.0], size=rows), # Actuator (binary)
        "P1_PV01": np.random.normal(loc=50.0, scale=2.0, size=rows), # Sensor (continuous)
        "P2_PV02": np.random.normal(loc=10.0, scale=0.5, size=rows), # Sensor
        "attack": np.zeros(rows, dtype=int)
    }
    
    df_raw = pd.DataFrame(raw_data)
    
    # 2. Ingestion & Normalization
    normalizer = TimeseriesNormalizer(timestamp_col="timestamp", label_col="attack")
    norm_df = normalizer.fit_normalize(df_raw)
    assert len(norm_df) == rows
    assert "sensor_P1_PV01" in norm_df.columns
    assert "actuator_P1_FCV01D" in norm_df.columns

    # 3. Time-window segmentation (60 seconds length)
    windows = list(build_sliding_windows(norm_df, window_length=60, stride=10, host_name="PLC-MOCK"))
    assert len(windows) == 2 # (70 - 60) // 10 + 1 = 2 windows
    win = windows[0]
    
    # 4. Feature Extraction
    features = build_features_for_window(win)
    assert "sensor_P1_PV01_mean" in features
    assert "actuator_P1_FCV01D_state_changes" in features

    # 5. Model Inference, Anomaly Calibration & Evidence Generation
    # We test it through the OTDetector prediction pipeline
    detector = OTDetector()
    
    # We inject baseline stats so that Z-score deviation works
    detector.evidence_gen.baseline_stats = {
        "sensor_P1_PV01": {"mean": 50.0, "std": 2.0},
        "sensor_P2_PV02": {"mean": 10.0, "std": 0.5}
    }
    
    evidence = detector.predict(win)
    
    assert evidence["detector"] == "ot"
    assert evidence["entity"] == "PLC-MOCK"
    assert "anomaly_score" in evidence
    assert 0.0 <= evidence["risk_score"] <= 1.0
    assert isinstance(evidence["top_shifted_variables"], list)
    assert len(evidence["top_shifted_variables"]) <= 5
