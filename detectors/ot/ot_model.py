import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
import pandas as pd
import numpy as np
import joblib

logger = logging.getLogger(__name__)

class OTModel:
    """
    Model wrapper managing Isolation Forest and LightGBM model executions.
    Ensures input alignment against the feature contract.
    """
    def __init__(self, model_dir: str = "models/ot", contract_path: Optional[str] = None):
        self.model_dir = Path(model_dir)
        self.contract_path = Path(contract_path) if contract_path else self.model_dir / "feature_contract.json"
        
        self.iforest: Optional[Any] = None
        self.lightgbm: Optional[Any] = None
        self.features: List[str] = []
        self.metadata: Dict[str, Any] = {}

    def load_model(self) -> None:
        """
        Loads the Isolation Forest, optional LightGBM, and feature contract schema.
        """
        # Load feature contract
        if not self.contract_path.exists():
            raise FileNotFoundError(f"Feature contract not found at {self.contract_path}")
            
        with open(self.contract_path, "r", encoding="utf-8") as f:
            contract = json.load(f)
        self.features = list(contract.keys())
        logger.info(f"Loaded feature contract containing {len(self.features)} features.")

        # Load Isolation Forest
        iforest_path = self.model_dir / "isolation_forest.pkl"
        if not iforest_path.exists():
            raise FileNotFoundError(f"Isolation Forest model not found at {iforest_path}")
        self.iforest = joblib.load(iforest_path)
        logger.info("Loaded Isolation Forest model successfully.")

        # Load LightGBM (Optional)
        lgb_path = self.model_dir / "lightgbm.pkl"
        if lgb_path.exists():
            self.lightgbm = joblib.load(lgb_path)
            logger.info("Loaded LightGBM model successfully.")
        else:
            logger.warning("LightGBM model not found, running in anomaly-only mode.")

        # Load Metadata
        meta_path = self.model_dir / "training_metadata.json"
        if meta_path.exists():
            with open(meta_path, "r", encoding="utf-8") as f:
                self.metadata = json.load(f)

    def _align_features(self, features_dict: Dict[str, Any]) -> pd.DataFrame:
        """
        Aligns incoming features with the exact contract ordering.
        Fills missing values with zero or default values.
        """
        # Align features: build dictionary of values first to avoid fragmentation
        aligned_data = {}
        for col in self.features:
            val = features_dict.get(col)
            # handle pandas NaN values safely if present
            aligned_data[col] = float(val) if (val is not None and pd.notna(val)) else 0.0
            
        # Reorder and slice columns to match the exact contract
        return pd.DataFrame([aligned_data])[self.features]

    def predict_anomaly_score(self, features_dict: Dict[str, Any]) -> float:
        """
        Computes Isolation Forest raw anomaly score.
        score_samples() returns negative float; lower is more anomalous.
        """
        if not self.iforest:
            raise RuntimeError("Isolation Forest model is not loaded.")
            
        aligned_df = self._align_features(features_dict)
        # score_samples returns an array of scores
        raw_score = self.iforest.score_samples(aligned_df)[0]
        return float(raw_score)

    def predict_attack_probability(self, features_dict: Dict[str, Any]) -> float:
        """
        Computes LightGBM attack probability (0.0 to 1.0).
        """
        if not self.lightgbm:
            return 0.0
            
        aligned_df = self._align_features(features_dict)
        prob = self.lightgbm.predict_proba(aligned_df)[0, 1]
        return float(prob)
