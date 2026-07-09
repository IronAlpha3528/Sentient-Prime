import json
from pathlib import Path
import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

PROCESSED_PATH = Path("data/processed/identity/lanl_user_hour_windows.parquet")
MODEL_DIR = Path("data/models/identity")


def main() -> None:
    if not PROCESSED_PATH.exists():
        raise FileNotFoundError(
            f"Processed identity dataset not found at: {PROCESSED_PATH}. "
            "Please run 'python -m data.training.aggregate_lanl' first."
        )

    print("Loading aggregated user windows from:", PROCESSED_PATH)
    df = pd.read_parquet(PROCESSED_PATH)

    features = [
        "auth_count",
        "unique_computers",
        "computer_fanout",
        "mean_auth_gap",
        "min_auth_gap",
        "max_auth_gap",
    ]

    print("Training data shape:", df[features].shape)
    print("Features used:", features)

    # Train Isolation Forest (unsupervised anomaly detection)
    model = IsolationForest(
        n_estimators=100,
        contamination="auto",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(df[features])

    # Save artifacts
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_DIR / "identity_iforest.pkl")
    
    (MODEL_DIR / "feature_columns.json").write_text(
        json.dumps(features, indent=2),
        encoding="utf-8",
    )

    print(f"Successfully saved identity model and feature contract to {MODEL_DIR}")


if __name__ == "__main__":
    main()
