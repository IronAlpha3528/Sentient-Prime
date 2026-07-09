import json

import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix

from data.training.network_common import MODEL_DIR, PROCESSED_DIR


def main() -> None:
    metadata = json.loads(
        (PROCESSED_DIR / "metadata.json").read_text(encoding="utf-8")
    )
    label_column = metadata["label_column"]
    features = metadata["feature_columns"]

    test = pd.read_parquet(PROCESSED_DIR / "test.parquet")
    encoder = joblib.load(MODEL_DIR / "label_encoder.pkl")
    model = lgb.Booster(
        model_file=str(MODEL_DIR / "network_model.txt")
    )

    y_true = encoder.transform(test[label_column])
    y_pred = np.argmax(model.predict(test[features]), axis=1)

    print(
        classification_report(
            y_true,
            y_pred,
            target_names=encoder.classes_,
            zero_division=0,
        )
    )
    print("Confusion matrix:")
    print(confusion_matrix(y_true, y_pred))


if __name__ == "__main__":
    main()
