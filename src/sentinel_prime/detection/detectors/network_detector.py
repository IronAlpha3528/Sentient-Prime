import json
from pathlib import Path

import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd

from sentinel_prime.detection.detectors.base_detector import BaseDetector
from sentinel_prime.detection.detectors.evidence_schema import DetectorEvidence

# Evidence Band Name Constants (Task N3)
MINIMAL_NETWORK_EVIDENCE = "minimal_network_evidence"
WEAK_NETWORK_EVIDENCE = "weak_network_evidence"
MODERATE_NETWORK_EVIDENCE = "moderate_network_evidence"
STRONG_NETWORK_EVIDENCE = "strong_network_evidence"


class NetworkDetector(BaseDetector):
    """Runtime wrapper for the Hierarchical CSE-CIC-IDS2018 LightGBM v2.1 model."""

    def __init__(self, model_dir: str = "data/models/network/v2"):
        self.model_dir = Path(model_dir)
        self.load_model()

    def load_model(self) -> None:
        self.model_s1 = lgb.Booster(
            model_file=str(self.model_dir / "stage1_binary_model.txt")
        )
        self.model_s2 = lgb.Booster(
            model_file=str(self.model_dir / "stage2_family_model.txt")
        )
        self.family_encoder = joblib.load(
            self.model_dir / "family_label_encoder.pkl"
        )
        self.feature_columns = json.loads(
            (self.model_dir / "feature_columns.json").read_text(encoding="utf-8")
        )
        self.metadata = json.loads(
            (self.model_dir / "model_metadata.json").read_text(encoding="utf-8")
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

        # Stage 1 prediction: binary attack probability
        attack_probability = float(self.model_s1.predict(frame)[0])
        
        # Stage 2 prediction: attack family probabilities
        probabilities_s2 = np.asarray(self.model_s2.predict(frame))
        
        # Sort family predictions descending
        top_indices = np.argsort(probabilities_s2[0])[::-1]
        top_family_predictions = [
            {
                "family": str(self.family_encoder.inverse_transform([int(i)])[0]),
                "probability": float(probabilities_s2[0][i]),
            }
            for i in top_indices
        ]
        
        predicted_family = top_family_predictions[0]["family"]
        family_probability = top_family_predictions[0]["probability"]

        # Classification maps based on conservative evidence bands (Task N3)
        if attack_probability < 0.10:
            classification = MINIMAL_NETWORK_EVIDENCE
        elif attack_probability < 0.30:
            classification = WEAK_NETWORK_EVIDENCE
        elif attack_probability < 0.50:
            classification = MODERATE_NETWORK_EVIDENCE
        else:
            classification = STRONG_NETWORK_EVIDENCE

        return DetectorEvidence(
            detector="network",
            entity_type="host",
            entity_id=data.get("entity_id", "unknown-host"),
            timestamp=data.get("timestamp", ""),
            score=attack_probability,
            classification=classification,
            features=raw_features,
            evidence=[
                {
                    "type": "stage1_attack_probability",
                    "value": attack_probability
                },
                {
                    "type": "predicted_attack_family",
                    "value": predicted_family
                },
                {
                    "type": "family_probability",
                    "value": family_probability
                },
                {
                    "type": "top_family_predictions",
                    "values": top_family_predictions[:3]
                }
            ],
            model_version="network-hierarchical-lightgbm-v2.1",
        ).to_dict()
