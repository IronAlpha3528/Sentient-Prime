import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sentinel_prime.detection.detectors.base_detector import BaseDetector
from sentinel_prime.detection.detectors.evidence_schema import DetectorEvidence


def explain_anomaly(row) -> list[str]:
    reasons = []
    
    # 1. New destination access ratio
    new_ratio = float(row.get("new_computer_ratio", 0.0))
    if new_ratio > 0.5:
        reasons.append(f"{new_ratio * 100:.1f}% of accessed computers are new for this user")
        
    # 2. Authentication volume deviation (using RAW z-score if available, else clipped)
    auth_z = float(row.get("raw_auth_count_zscore", row.get("auth_count_zscore", 0.0)))
    if auth_z > 3.0:
        reasons.append(f"authentication volume is {auth_z:.1f} standard deviations above user baseline")
        
    # 3. Computer fanout deviation
    comp_z = float(row.get("raw_unique_computers_zscore", row.get("unique_computers_zscore", 0.0)))
    if comp_z > 3.0:
        reasons.append(f"computer traversal is {comp_z:.1f} standard deviations above user baseline")
        
    # 4. Off hours activity
    if int(row.get("off_hours_flag", 0)) == 1:
        reasons.append("activity occurred outside configured normal hours")
        
    # 5. Fast traversal
    fanout = float(row.get("fanout_rate", 0.0))
    if fanout > 10.0:
        reasons.append(f"high host traversal velocity: {fanout:.1f} computers/hour")

    # 6. Timing deviation (Task I6)
    gap_z = float(row.get("raw_mean_auth_gap_zscore", row.get("mean_auth_gap_zscore", 0.0)))
    if gap_z > 3.0:
        reasons.append(f"authentication timing gap is {gap_z:.1f} standard deviations above user baseline")
    elif gap_z < -3.0:
        reasons.append(f"authentication timing gap is {abs(gap_z):.1f} standard deviations below user baseline")

    # 7. Fanout rate deviation (Task I6)
    fanout_z = float(row.get("raw_fanout_rate_zscore", row.get("fanout_rate_zscore", 0.0)))
    if fanout_z > 3.0:
        reasons.append(f"host traversal velocity is {fanout_z:.1f} standard deviations above user baseline")
        
    return reasons


class IdentityDetector(BaseDetector):
    """Runtime wrapper for the LANL Authentication Isolation Forest v2.1 model."""

    def __init__(self, model_dir: str = "data/models/identity/v2_1"):
        self.model_dir = Path(model_dir)
        self.load_model()

    _shared_model = None
    _shared_feature_columns = None
    _shared_metadata = None

    def load_model(self) -> None:
        cls = self.__class__
        if cls._shared_model is None:
            cls._shared_model = joblib.load(self.model_dir / "identity_model.pkl")
            cls._shared_feature_columns = json.loads(
                (self.model_dir / "feature_columns.json").read_text(encoding="utf-8")
            )
            cls._shared_metadata = json.loads(
                (self.model_dir / "model_metadata.json").read_text(encoding="utf-8")
            )
            
        self.model = cls._shared_model
        self.feature_columns = cls._shared_feature_columns
        self.metadata = cls._shared_metadata

    def predict(self, data: dict) -> dict:
        raw_features = data["features"].copy()
        
        # Enforce z-score clipping constraints at runtime if raw values are present
        z_min = self.metadata.get("zscore_clip_min", -10.0)
        z_max = self.metadata.get("zscore_clip_max", 10.0)
        
        if "raw_auth_count_zscore" in raw_features:
            raw_features["auth_count_zscore"] = float(
                np.clip(raw_features["raw_auth_count_zscore"], z_min, z_max)
            )
        if "raw_unique_computers_zscore" in raw_features:
            raw_features["unique_computers_zscore"] = float(
                np.clip(raw_features["raw_unique_computers_zscore"], z_min, z_max)
            )
        if "raw_mean_auth_gap_zscore" in raw_features:
            raw_features["mean_auth_gap_zscore"] = float(
                np.clip(raw_features["raw_mean_auth_gap_zscore"], z_min, z_max)
            )
        if "raw_fanout_rate_zscore" in raw_features:
            raw_features["fanout_rate_zscore"] = float(
                np.clip(raw_features["raw_fanout_rate_zscore"], z_min, z_max)
            )

        # Fallback for has_auth_gap
        if "has_auth_gap" not in raw_features:
            auth_cnt = int(raw_features.get("auth_count", 0))
            raw_features["has_auth_gap"] = 1 if auth_cnt >= 2 else 0

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
        raw_score = float(self.model.decision_function(frame)[0])
        prediction = int(self.model.predict(frame)[0])

        # Normalize score using training bounds
        norm_params = self.metadata["score_normalization_parameters"]
        min_raw_score = norm_params["min_raw_score"]
        max_raw_score = norm_params["max_raw_score"]

        suspiciousness_score = float(np.clip(
            (max_raw_score - raw_score) / (max_raw_score - min_raw_score),
            0.0,
            1.0
        ))

        # conservative classification
        classification = "behavioural_deviation" if prediction == -1 else "normal_behaviour"

        return DetectorEvidence(
            detector="identity",
            entity_type="user",
            entity_id=data.get("entity_id", "unknown-user"),
            timestamp=data.get("timestamp", ""),
            score=suspiciousness_score,
            classification=classification,
            features=raw_features,
            evidence=[
                {
                    "type": "behavioural_reasons",
                    "values": explain_anomaly(raw_features)
                },
                {
                    "type": "raw_isolation_forest_score",
                    "value": raw_score
                }
            ],
            model_version="identity-relative-isolation-forest-v2.1",
        ).to_dict()
