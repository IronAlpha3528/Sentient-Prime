import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

TRAIN_PATH = Path("data/processed/identity/train.parquet")
MODEL_DIR_V2_1 = Path("data/models/identity/v2_1")


def main() -> None:
    if not TRAIN_PATH.exists():
        raise FileNotFoundError(
            f"Training dataset not found at: {TRAIN_PATH}. "
            "Please run 'python -m data.training.aggregate_lanl' first."
        )

    print("Loading training aggregated user windows from:", TRAIN_PATH)
    df = pd.read_parquet(TRAIN_PATH)

    # ML Features Contract (Relative / Deviation features only - Task I4)
    features_v2_1 = [
        "auth_count_zscore",
        "unique_computers_zscore",
        "mean_auth_gap_zscore",
        "has_auth_gap",
        "fanout_rate_zscore",
        "new_computer_ratio",
        "off_hours_flag"
    ]

    context_features = [
        "auth_count",
        "unique_computers",
        "fanout_rate",
        "mean_auth_gap",
        "min_auth_gap",
        "max_auth_gap",
        "new_computer_count",
        "hour_of_day",
        "raw_auth_count_zscore",
        "raw_unique_computers_zscore",
        "raw_mean_auth_gap_zscore",
        "raw_fanout_rate_zscore"
    ]

    print("Training data shape:", df[features_v2_1].shape)
    print("ML Features used:", features_v2_1)

    # Train Isolation Forest (Task I5)
    random_state = 42
    contamination = "auto"
    
    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1,
    )
    model.fit(df[features_v2_1])

    # Calculate raw score normalization params on training set to prevent leakage
    train_raw_scores = model.decision_function(df[features_v2_1])
    min_raw_score = float(train_raw_scores.min())
    max_raw_score = float(train_raw_scores.max())

    MODEL_DIR_V2_1.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_DIR_V2_1 / "identity_model.pkl")
    
    (MODEL_DIR_V2_1 / "feature_columns.json").write_text(
        json.dumps(features_v2_1, indent=2),
        encoding="utf-8",
    )

    model_metadata = {
        "model_version": "identity-relative-isolation-forest-v2.1",
        "model_type": "IsolationForest",
        "feature_columns": features_v2_1,
        "context_feature_columns": context_features,
        "training_rows": len(df),
        "training_window_range": {
            "min_window": int(df["window_id"].min()),
            "max_window": int(df["window_id"].max())
        },
        "contamination": contamination,
        "random_state": random_state,
        "zscore_clip_min": -10.0,
        "zscore_clip_max": 10.0,
        "min_std_epsilon": 0.0001,
        "score_normalization_strategy": "robust min-max scaling based on training scores",
        "score_normalization_parameters": {
            "min_raw_score": min_raw_score,
            "max_raw_score": max_raw_score
        }
    }

    (MODEL_DIR_V2_1 / "model_metadata.json").write_text(
        json.dumps(model_metadata, indent=2),
        encoding="utf-8",
    )

    print(f"Successfully saved identity model to: {MODEL_DIR_V2_1 / 'identity_model.pkl'}")
    print(f"Successfully saved model metadata and normalization params to: {MODEL_DIR_V2_1 / 'model_metadata.json'}")


if __name__ == "__main__":
    main()
