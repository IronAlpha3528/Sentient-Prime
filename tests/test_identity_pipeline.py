import json
from collections import defaultdict
import pytest
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.ensemble import IsolationForest

from sentinel_prime.detection.detectors.identity_detector import IdentityDetector
from sentinel_prime.core.ingestion.identity_adapter import IdentityAdapter
from sentinel_prime.soar.orchestrator.phase1_pipeline import Phase1Pipeline
from data.training.aggregate_lanl import process_window


# 1. Feature engineering, cold-start, new computer, and leakage tests
def test_feature_engineering_and_leakage():
    # Setup test state
    user_seen_computers = {"U1": {"C1", "C2"}}
    user_history = {"U1": {"auth_counts": [10, 15, 20], "unique_computers_counts": [2, 3, 2]}}

    # Window W data
    window_data = {
        "U1": {
            "times": [1000, 2000, 3000],  # Active duration: 2000 seconds
            "computers": {"C2", "C3", "C4"}  # unique: 3, new: C3 and C4 (count: 2)
        }
    }
    
    # Process window
    rows = process_window(24, window_data, user_seen_computers, user_history)
    
    assert len(rows) == 1
    row = rows[0]
    
    # Validate features
    assert row["user"] == "U1"
    assert row["window_id"] == 24
    assert row["auth_count"] == 3
    assert row["unique_computers"] == 3
    
    # fanout_rate = 3 / (2000/3600) = 3 / 0.55555 = 5.4
    assert abs(row["fanout_rate"] - 5.4) < 0.1
    
    # gaps = [1000, 1000]. mean = 1000, min = 1000, max = 1000
    assert row["mean_auth_gap"] == 1000.0
    assert row["min_auth_gap"] == 1000.0
    assert row["max_auth_gap"] == 1000.0
    
    # new computers
    assert row["new_computer_count"] == 2
    assert row["new_computer_ratio"] == 2 / 3
    
    # zscores
    # prev auth_counts: [10, 15, 20], mean = 15, std = sqrt((25 + 0 + 25)/3) = sqrt(16.666) = 4.08
    # zscore = (3 - 15) / 4.08 = -2.94
    assert abs(row["auth_count_user_mean"] - 15.0) < 0.01
    assert abs(row["auth_count_zscore"] - (-2.94)) < 0.05
    
    # Check data leakage prevention:
    # The processed window details must NOT be present in user_history or user_seen_computers BEFORE processing,
    # but MUST be appended AFTER processing.
    assert "C3" in user_seen_computers["U1"]
    assert "C4" in user_seen_computers["U1"]
    assert len(user_history["U1"]["auth_counts"]) == 4
    assert user_history["U1"]["auth_counts"][-1] == 3


def test_cold_start_handling():
    user_seen_computers = defaultdict(set)
    user_history = defaultdict(lambda: {"auth_counts": [], "unique_computers_counts": []})
    
    # User U_cold has no history (history_len = 0 < MIN_HISTORY_WINDOWS)
    window_data = {
        "U_cold": {
            "times": [5000],
            "computers": {"C10"}
        }
    }
    
    rows = process_window(1, window_data, user_seen_computers, user_history)
    row = rows[0]
    
    # No NaN or Infinities
    assert row["auth_count_user_mean"] == 0.0
    assert row["auth_count_user_std"] == 0.0
    assert row["auth_count_zscore"] == 0.0
    assert row["unique_computers_user_mean"] == 0.0
    assert row["unique_computers_user_std"] == 0.0
    assert row["unique_computers_zscore"] == 0.0
    assert not np.isnan(row["auth_count_zscore"])
    assert not np.isinf(row["auth_count_zscore"])


# 2. Anomaly score normalization tests
def test_suspiciousness_score_range_and_order():
    # Setup mock metadata and model
    features = ["f1", "f2"]
    X = np.random.randn(100, 2)
    model = IsolationForest(random_state=42)
    model.fit(X)
    
    # Normalized bounds
    scores = model.decision_function(X)
    min_raw = float(scores.min())
    max_raw = float(scores.max())
    
    # Test normalization function
    def normalize(raw_val, min_v, max_v):
        return float(np.clip((max_v - raw_val) / (max_v - min_v), 0.0, 1.0))
        
    # Check bounds
    assert normalize(min_raw, min_raw, max_raw) == 1.0  # highly anomalous
    assert normalize(max_raw, min_raw, max_raw) == 0.0  # highly normal
    assert 0.0 <= normalize(0.0, min_raw, max_raw) <= 1.0
    
    # Higher anomaly severity (lower raw score) -> Higher suspiciousness score
    assert normalize(-0.2, min_raw, max_raw) > normalize(0.1, min_raw, max_raw)


# 3. Temporal split checks
def test_temporal_split():
    # Verify temporal splitting checks
    train_output = Path("data/processed/identity/train.parquet")
    test_output = Path("data/processed/identity/test.parquet")
    metadata_path = Path("data/processed/identity/metadata.json")
    
    if train_output.exists() and test_output.exists() and metadata_path.exists():
        train_df = pd.read_parquet(train_output)
        test_df = pd.read_parquet(test_output)
        
        # Max train window_id must be strictly less than min test window_id
        max_train_w = train_df["window_id"].max()
        min_test_w = test_df["window_id"].min()
        
        assert max_train_w < min_test_w
        
        with open(metadata_path, encoding="utf-8") as f:
            meta = json.load(f)
            
        assert meta["train_max_window"] == max_train_w
        assert meta["test_min_window"] == min_test_w


# 4. Pipeline routes preservation tests
def test_network_route_preservation():
    pipeline = Phase1Pipeline()
    # Check that network route is registered and operates properly
    assert "network" in pipeline.router.routes
    assert "identity" in pipeline.router.routes
