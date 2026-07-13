import os
import json
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
import pandas as pd

from sentinel_prime.detection.detectors.base_detector import BaseDetector
from sentinel_prime.detection.detectors.ot.ot_model import OTModel
from sentinel_prime.detection.detectors.ot.anomaly_calibrator import AnomalyCalibrator
from sentinel_prime.detection.detectors.ot.evidence_generator import OTEvidenceGenerator
from sentinel_prime.detection.detectors.ot.timeseries_normalizer import TimeseriesNormalizer
from sentinel_prime.detection.detectors.ot.window_builder import build_sliding_windows
from sentinel_prime.detection.detectors.ot.feature_builder import build_features_for_window

logger = logging.getLogger(__name__)

class OTDetector(BaseDetector):
    """
    Unified OT Specialist Detector for Sentient-Prime.
    Combines unsupervised Isolation Forest process anomaly detection with LightGBM refinement.
    """
    def __init__(self, config_path: str = "config/ot.yaml"):
        self.config_path = Path(config_path)
        self.config: Dict[str, Any] = {}
        self.model: Optional[OTModel] = None
        self.calibrator: Optional[AnomalyCalibrator] = None
        self.evidence_gen: Optional[OTEvidenceGenerator] = None
        self.normalizer: Optional[TimeseriesNormalizer] = None

        self.initialize()

    def initialize(self) -> None:
        """Loads config, models, baseline stats, and calibrator params."""
        # Load configuration
        if self.config_path.exists():
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    self.config = yaml.safe_load(f) or {}
            except Exception as e:
                logger.error(f"Failed to parse config file at {self.config_path}: {e}")
                self.config = {}
        else:
            logger.warning(f"Config file not found at {self.config_path}, using default settings.")
            self.config = {}

        self.model_dir = self.config.get("model_directory", "models/ot")
        self.contract_path = self.config.get("feature_contract", "models/ot/feature_contract.json")
        self.risk_threshold = self.config.get("risk_threshold", 0.75)

        # Load normalizer
        self.normalizer = TimeseriesNormalizer()

        # Load models
        try:
            self.load_model()
        except Exception as e:
            logger.warning(f"Model initialization bypassed: {e}")

    def load_model(self) -> None:
        """Loads trained Isolation Forest, optional LightGBM, and baseline stats."""
        # 1. Initialize Model Wrapper
        self.model = OTModel(model_dir=self.model_dir, contract_path=self.contract_path)
        self.model.load_model()

        # 2. Initialize Anomaly Calibrator
        meta = self.model.metadata
        cal_stats = meta.get("calibrator_stats", {})
        self.calibrator = AnomalyCalibrator(
            mean=cal_stats.get("mean", 0.0),
            std=cal_stats.get("std", 1.0),
            threshold_medium=cal_stats.get("threshold_medium", 0.45),
            threshold_high=cal_stats.get("threshold_high", 0.70),
            threshold_critical=cal_stats.get("threshold_critical", 0.85)
        )

        # 3. Load baseline stats for shifted variable rankings
        stats_path = Path(self.model_dir) / "baseline_stats.json"
        baseline_stats = {}
        if stats_path.exists():
            with open(stats_path, "r", encoding="utf-8") as f:
                baseline_stats = json_load_stats(stats_path)
                
        self.evidence_gen = OTEvidenceGenerator(baseline_stats=baseline_stats)

    def health(self) -> str:
        """
        Health status validation.
        """
        problems = []
        if not self.model or not self.model.iforest:
            problems.append("Isolation Forest model not loaded")
        if not Path(self.contract_path).exists():
            problems.append(f"Feature contract not found at {self.contract_path}")
        if not self.calibrator:
            problems.append("Calibrator not initialized")
        if not self.evidence_gen:
            problems.append("Evidence generator not initialized")

        if problems:
            return f"Degraded: {', '.join(problems)}"
        return "Healthy"

    def metadata(self) -> Dict[str, Any]:
        """Returns metadata about versioning and calibrator statistics."""
        model_meta = self.model.metadata if self.model else {}
        return {
            "detector_id": "ot-specialist",
            "model_version": model_meta.get("model_version", "unknown"),
            "training_date": model_meta.get("training_date", "unknown"),
            "features_count": len(self.model.features) if self.model else 0,
            "has_supervised_model": self.model.lightgbm is not None if self.model else False
        }

    def shutdown(self) -> None:
        """Shuts down and releases resources."""
        self.model = None
        self.calibrator = None
        self.evidence_gen = None
        self.normalizer = None

    def predict(self, window_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Predicts process anomalies for a single window dictionary.
        Accepts window_data containing:
          - metadata (Dict[str, Any] or WindowMetadata)
          - data (DataFrame or Dict representing features directly)
        """
        # If the input is already a flat feature vector with metadata:
        if "window_id" in window_data and "attack_label" in window_data:
            # Simple direct calculation
            features = window_data
            meta = {
                "window_id": window_data.get("window_id"),
                "start_time": window_data.get("start_time"),
                "end_time": window_data.get("end_time"),
                "host": window_data.get("host"),
                "label": window_data.get("attack_label"),
                "attack_ratio": window_data.get("attack_ratio", 0.0)
            }
        else:
            # Normal structure with metadata and window DataFrame
            meta_obj = window_data["metadata"]
            if hasattr(meta_obj, "window_id"):
                meta = {
                    "window_id": meta_obj.window_id,
                    "start_time": meta_obj.start_time,
                    "end_time": meta_obj.end_time,
                    "host": meta_obj.host,
                    "label": meta_obj.label,
                    "attack_ratio": meta_obj.attack_ratio
                }
            else:
                meta = meta_obj

            # Compute features for window
            features = build_features_for_window(window_data)

        # 1. Isolation Forest predict (Raw Score)
        raw_score = 0.0
        if self.model:
            raw_score = self.model.predict_anomaly_score(features)

        # 2. Calibrate score to 0-1
        normalized_score = 0.5
        severity = "LOW"
        if self.calibrator:
            normalized_score, severity = self.calibrator.calibrate(raw_score)

        # 3. LightGBM predict (Optional Attack Probability)
        attack_prob = 0.0
        if self.model and self.model.lightgbm:
            attack_prob = self.model.predict_attack_probability(features)

        # 4. Generate fused evidence
        evidence_dict = {}
        if self.evidence_gen:
            evidence = self.evidence_gen.create_evidence(
                anomaly_score=normalized_score,
                attack_probability=attack_prob,
                severity=severity,
                features=features,
                window_metadata=meta
            )
            evidence_dict = evidence.to_dict()
            
        return evidence_dict

    def predict_batch(self, windows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Executes prediction on a batch of process windows."""
        results = []
        for win in windows:
            results.append(self.predict(win))
        return results

def json_load_stats(stats_path: Path) -> dict:
    with open(stats_path, "r", encoding="utf-8") as f:
        return json.load(f)

if __name__ == "__main__":
    detector = OTDetector()
    print(f"Health check: {detector.health()}")
    print(f"Metadata: {detector.metadata()}")
