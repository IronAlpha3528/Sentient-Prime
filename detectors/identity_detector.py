import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd

from detectors.base_detector import BaseDetector
from detectors.evidence_schema import DetectorEvidence


class IdentityDetector(BaseDetector):
    """Runtime wrapper for the LANL Authentication Isolation Forest model."""

    def __init__(self, model_dir: str = "data/models/identity"):
        self.model_dir = Path(model_dir)
        self.load_model()

    def load_model(self) -> None:
        self.model = joblib.load(self.model_dir / "identity_iforest.pkl")
        self.feature_columns = json.loads(
            (self.model_dir / "feature_columns.json").read_text(encoding="utf-8")
        )

    def predict(self, data: dict) -> dict:
        raw_features = data["features"]
        missing = [c for c in self.feature_columns if c not in raw_features]
        if missing:
            raise ValueError(
                f"Missing {len(missing)} identity features. "
                f"First missing features: {missing[:10]}"
            )

        frame = pd.DataFrame(
            [[raw_features[c] for c in self.feature_columns]],
            columns=self.feature_columns,
        )
        frame = frame.fillna(0)

        # Sklearn Isolation Forest predictions
        # decision_function returns negative for anomalies, positive for normal
        raw_score = float(self.model.decision_function(frame)[0])
        prediction = int(self.model.predict(frame)[0])

        # Map to anomaly probability (0.0 to 1.0) using sigmoid scaling
        # raw_score < 0 means anomaly, which maps to score > 0.5
        score = float(1.0 / (1.0 + np.exp(raw_score * 8.0)))
        classification = "anomaly" if prediction == -1 else "normal"

        return DetectorEvidence(
            detector="identity",
            entity_type="user",
            entity_id=data.get("entity_id", "unknown-user"),
            timestamp=data.get("timestamp", ""),
            score=score,
            classification=classification,
            features=raw_features,
            evidence=[
                {
                    "type": "anomaly_check",
                    "values": {
                        "raw_score": raw_score,
                        "prediction": prediction,
                    },
                }
            ],
            model_version="identity-iforest-v1",
        ).to_dict()
