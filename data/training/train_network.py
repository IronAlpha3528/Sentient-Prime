import json

import joblib
import lightgbm as lgb
import pandas as pd
from sklearn.preprocessing import LabelEncoder

from data.training.network_common import MODEL_DIR, PROCESSED_DIR


def main() -> None:
    metadata = json.loads(
        (PROCESSED_DIR / "metadata.json").read_text(encoding="utf-8")
    )
    label_column = metadata["label_column"]
    features = metadata["feature_columns"]

    train = pd.read_parquet(PROCESSED_DIR / "train.parquet")
    valid = pd.read_parquet(PROCESSED_DIR / "valid.parquet")

    encoder = LabelEncoder()
    y_train = encoder.fit_transform(train[label_column])
    y_valid = encoder.transform(valid[label_column])

    train_set = lgb.Dataset(train[features], label=y_train)
    valid_set = lgb.Dataset(valid[features], label=y_valid)

    params = {
        "objective": "multiclass",
        "num_class": len(encoder.classes_),
        "metric": "multi_logloss",
        "learning_rate": 0.05,
        "num_leaves": 63,
        "feature_fraction": 0.9,
        "bagging_fraction": 0.9,
        "bagging_freq": 1,
        "verbosity": -1,
        "seed": 42,
    }

    model = lgb.train(
        params,
        train_set,
        num_boost_round=1000,
        valid_sets=[valid_set],
        callbacks=[
            lgb.early_stopping(50),
            lgb.log_evaluation(25),
        ],
    )

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    model.save_model(str(MODEL_DIR / "network_model.txt"))
    joblib.dump(encoder, MODEL_DIR / "label_encoder.pkl")
    (MODEL_DIR / "feature_columns.json").write_text(
        json.dumps(features, indent=2),
        encoding="utf-8",
    )

    print("Classes:", list(encoder.classes_))
    print("Saved network artifacts to:", MODEL_DIR)


if __name__ == "__main__":
    main()
