import json
from pathlib import Path

import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd

from detectors.base_detector import BaseDetector
from detectors.evidence_schema import DetectorEvidence


class NetworkDetector(BaseDetector):
    """Runtime wrapper for the CSE-CIC-IDS2018 LightGBM model."""

    def __init__(self, model_dir: str = "data/models/network"):
        self.model_dir = Path(model_dir)
        self.load_model()

    def load_model(self) -> None:
        self.model = lgb.Booster(
            model_file=str(self.model_dir / "network_model.txt")
        )
        self.label_encoder = joblib.load(
            self.model_dir / "label_encoder.pkl"
        )
        self.feature_columns = json.loads(
            (self.model_dir / "feature_columns.json").read_text(encoding="utf-8")
        )

    def predict(self, data: dict) -> dict:
        raw_features = data["features"]
        missing = [c for c in self.feature_columns if c not in raw_features]
        if missing:
            raise ValueError(
                f"Missing {len(missing)} network features. "
                f"First missing features: {missing[:10]}"
            )

        frame = pd.DataFrame(
            [[raw_features[c] for c in self.feature_columns]],
            columns=self.feature_columns,
        )
        frame = (
            frame.apply(pd.to_numeric, errors="coerce")
            .replace([np.inf, -np.inf], np.nan)
            .fillna(0)
        )

        probabilities = np.asarray(self.model.predict(frame))
        class_index = int(np.argmax(probabilities[0]))
        score = float(np.max(probabilities[0]))
        classification = str(
            self.label_encoder.inverse_transform([class_index])[0]
        )

        top_indices = np.argsort(probabilities[0])[::-1][:3]
        top_predictions = [
            {
                "class": str(self.label_encoder.inverse_transform([int(i)])[0]),
                "probability": float(probabilities[0][i]),
            }
            for i in top_indices
        ]

        return DetectorEvidence(
            detector="network",
            entity_type="host",
            entity_id=data.get("entity_id", "unknown-host"),
            timestamp=data.get("timestamp", ""),
            score=score,
            classification=classification,
            features=raw_features,
            evidence=[{"type": "top_predictions", "values": top_predictions}],
            model_version="network-lightgbm-v1",
        ).to_dict()
