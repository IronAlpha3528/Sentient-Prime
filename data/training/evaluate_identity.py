import json
from pathlib import Path
import joblib
import pandas as pd

PROCESSED_PATH = Path("data/processed/identity/lanl_user_hour_windows.parquet")
MODEL_DIR = Path("data/models/identity")


def main() -> None:
    model_path = MODEL_DIR / "identity_iforest.pkl"
    features_path = MODEL_DIR / "feature_columns.json"

    if not model_path.exists() or not features_path.exists():
        raise FileNotFoundError(
            "Trained identity model or feature config not found. "
            "Please run 'python -m data.training.train_identity' first."
        )

    model = joblib.load(model_path)
    features = json.loads(features_path.read_text(encoding="utf-8"))

    print("Loading test data from:", PROCESSED_PATH)
    df = pd.read_parquet(PROCESSED_PATH)

    # Score anomalies
    # decision_function: lower means more anomalous (negative values are anomalies)
    df["anomaly_score"] = model.decision_function(df[features])
    # predict: -1 for anomalies, 1 for normal
    df["prediction"] = model.predict(df[features])

    anomalies_df = df[df["prediction"] == -1]
    normal_df = df[df["prediction"] == 1]

    print("\n--- Evaluation Results ---")
    print(f"Total rows evaluated: {len(df)}")
    print(f"Normal windows: {len(normal_df)} ({len(normal_df)/len(df)*100:.2f}%)")
    print(f"Anomalous windows: {len(anomalies_df)} ({len(anomalies_df)/len(df)*100:.2f}%)")
    print(f"Min anomaly score: {df['anomaly_score'].min():.4f}")
    print(f"Max anomaly score: {df['anomaly_score'].max():.4f}")

    print("\n--- Example Anomalies Detected ---")
    cols_to_show = ["user", "window_id", "auth_count", "unique_computers", "mean_auth_gap", "anomaly_score"]
    print(anomalies_df[cols_to_show].sort_values("anomaly_score").head(10))


if __name__ == "__main__":
    main()
