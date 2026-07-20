import os
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
import pandas as pd

from sentinel_prime.detection.detectors.base_detector import BaseDetector
from sentinel_prime.detection.detectors.endpoint.schemas import EndpointEvent
from sentinel_prime.detection.detectors.endpoint.endpoint_model import EndpointModel
from sentinel_prime.detection.detectors.endpoint.sigma_loader import load_sigma_rules, SigmaRule
from sentinel_prime.detection.detectors.endpoint.sigma_engine import SigmaEngine
from sentinel_prime.detection.detectors.endpoint.evidence_fusion import fuse_predictions_and_rules
from sentinel_prime.detection.detectors.endpoint.event_normalizer import normalize_event
from sentinel_prime.detection.detectors.endpoint.process_window_builder import build_process_windows, create_window_dict
from sentinel_prime.detection.detectors.endpoint.feature_builder import build_features_for_window

logger = logging.getLogger(__name__)

class EndpointDetector(BaseDetector):
    """
    Unified Endpoint Specialist Detector for Sentient-Prime.
    Combines behavioral anomaly classification (LightGBM) and Sigma rules matcher.
    """
    def __init__(self, config_path: str = "config/endpoint.yaml"):
        self.config_path = Path(config_path)
        self.config: Dict[str, Any] = {}
        self.model: Optional[EndpointModel] = None
        self.sigma_engine: Optional[SigmaEngine] = None
        self.sigma_rules: List[SigmaRule] = []

        self.initialize()

    def initialize(self) -> None:
        """Loads configuration, LightGBM model, and Sigma rules."""
        # Load configuration
        if self.config_path.exists():
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    self.config = yaml.safe_load(f) or {}
            except Exception as e:
                logger.error(f"Failed to parse config file at {self.config_path}: {e}")
                self.config = {}
        else:
            logger.warning(f"Config file not found at {self.config_path}, using defaults.")
            self.config = {}

        # Fallback defaults
        self.model_dir = self.config.get("model_directory", "models/endpoint")
        # Ensure sigma rules path resolves correctly from project root or this file
        default_sigma = str(Path(__file__).parent.parent / "sigma_rules")
        self.sigma_dir = self.config.get("sigma_directory", default_sigma)
        self.contract_path = self.config.get("feature_contract", "data/processed/endpoint/features/feature_contract.json")
        self.risk_threshold = self.config.get("risk_threshold", 0.75)

        # Load models
        try:
            self.load_model()
        except Exception as e:
            logger.warning(f"Model initialization bypassed: {e}")

        # Load Sigma rules
        try:
            self.load_sigma(self.sigma_dir)
        except Exception as e:
            logger.warning(f"Sigma initialization bypassed: {e}")

    def load_model(self) -> None:
        """Loads trained LightGBM model."""
        self.model = EndpointModel(model_dir=self.model_dir, contract_path=self.contract_path)
        self.model.load_model()

    def load_sigma(self, sigma_dir: str) -> None:
        """Loads Sigma rules and configures the rule engine."""
        self.sigma_rules = load_sigma_rules(sigma_dir)
        self.sigma_engine = SigmaEngine(self.sigma_rules)

    def health(self) -> str:
        """
        Health check to verify model status, feature contracts, and Sigma rules.
        """
        problems = []
        
        # Check model
        if not self.model or not self.model.model:
            problems.append("LightGBM model not loaded")
        
        # Check contract
        if not Path(self.contract_path).exists():
            problems.append(f"Feature contract not found at {self.contract_path}")

        # Check Sigma
        if not self.sigma_engine or not self.sigma_rules:
            problems.append(f"No Sigma rules loaded from {self.sigma_dir}")

        if problems:
            return f"Degraded: {', '.join(problems)}"
        return "Healthy"

    def metadata(self) -> Dict[str, Any]:
        """Returns detector metadata, versioning, and feature details."""
        model_meta = self.model.metadata if self.model else {}
        return {
            "detector_id": "endpoint-specialist",
            "model_version": model_meta.get("model_version", "unknown"),
            "python_version": model_meta.get("python_version", "unknown"),
            "features_count": len(self.model.features) if self.model else 0,
            "sigma_rules_count": len(self.sigma_rules)
        }

    def shutdown(self) -> None:
        """Shuts down and releases resources."""
        self.model = None
        self.sigma_engine = None
        self.sigma_rules.clear()

    def predict(self, window_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Predicts threat score and severity for a single window dictionary.
        Accepts window_data containing:
          - host (str)
          - process (str)
          - window_start (str)
          - window_end (str)
          - events (List[Dict[str, Any]]) - raw or normalized event dicts
        """
        events_raw = window_data.get("events", [])
        
        # 1. Normalize events in the window
        normalized_events: List[EndpointEvent] = []
        for raw_ev in events_raw:
            if isinstance(raw_ev, EndpointEvent):
                normalized_events.append(raw_ev)
            elif isinstance(raw_ev, dict):
                ev, _ = normalize_event(raw_ev)
                if ev:
                    normalized_events.append(ev)

        # Re-create window structured representation
        window_events = normalized_events if normalized_events else []
        
        # Assemble temporal start/end
        window_start = window_data.get("window_start")
        window_end = window_data.get("window_end")
        
        # 2. Extract features
        temp_win = {
            "window_id": window_data.get("window_id", "predict_win"),
            "host": window_data.get("host", "unknown"),
            "process": window_data.get("process", "unknown"),
            "parent_process": window_data.get("parent_process"),
            "window_start": window_start,
            "window_end": window_end,
            "event_count": len(window_events),
            "events": window_events
        }
        
        features = build_features_for_window(temp_win)
        
        # 3. Model predict (Risk Score)
        ml_risk_score = 0.0
        if self.model and self.model.model:
            ml_risk_score = self.model.predict(features)

        # 4. Sigma rule matching
        sigma_matches = []
        if self.sigma_engine:
            # Match rules against individual events inside the window
            matched_ids = set()
            for ev in window_events:
                ev_matches = self.sigma_engine.match_event(ev)
                for m in ev_matches:
                    # Deduplicate matches within the window by rule_id
                    if m["rule_id"] not in matched_ids:
                        sigma_matches.append(m)
                        matched_ids.add(m["rule_id"])

        # 5. Evidence Fusion
        evidence = fuse_predictions_and_rules(ml_risk_score, sigma_matches, features, temp_win)
        
        return evidence.to_dict()

    def predict_batch(self, windows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Executes prediction on a batch of process windows.
        """
        results = []
        for win in windows:
            results.append(self.predict(win))
        return results

if __name__ == "__main__":
    # Test loading and health if executed directly
    detector = EndpointDetector()
    print(f"Health Status: {detector.health()}")
    print(f"Detector Metadata: {detector.metadata()}")
