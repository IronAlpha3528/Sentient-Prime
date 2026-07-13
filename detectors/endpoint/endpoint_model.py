import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
import joblib
import pandas as pd
import numpy as np

logger = logging.getLogger(__name__)

class EndpointModel:
    def __init__(self, model_dir: Optional[str] = None, contract_path: Optional[str] = None):
        self.model_dir = Path(model_dir) if model_dir else Path("models/endpoint")
        self.contract_path = Path(contract_path) if contract_path else Path("data/processed/endpoint/features/feature_contract.json")
        self.model = None
        self.features: List[str] = []
        self.metadata: Dict[str, Any] = {}

    def load_model(self) -> None:
        """
        Loads the trained LightGBM model and its associated metadata/contracts.
        """
        model_file = self.model_dir / "lightgbm_model.pkl"
        if not model_file.exists():
            raise FileNotFoundError(
                f"Trained LightGBM model not found at: {model_file}. Please run train_endpoint first."
            )
        
        # Load pickle
        self.model = joblib.load(model_file)
        logger.info(f"Loaded LightGBM model from {model_file}")

        # Load feature contract
        if self.contract_path.exists():
            with open(self.contract_path, "r", encoding="utf-8") as f:
                contract = json.load(f)
                self.features = list(contract.keys())
        else:
            # Fallback to model's feature names if contract file is not present
            if hasattr(self.model, "feature_name_"):
                self.features = list(self.model.feature_name_)
            else:
                raise FileNotFoundError(f"Feature contract not found at: {self.contract_path}")

        # Load metadata
        meta_file = self.model_dir / "training_metadata.json"
        if meta_file.exists():
            with open(meta_file, "r", encoding="utf-8") as f:
                self.metadata = json.load(f)
        else:
            self.metadata = {}

    def predict(self, feature_row: Dict[str, Any]) -> float:
        """
        Predict probability of malicious behaviour for a single window dict of features.
        """
        if self.model is None:
            self.load_model()

        # Build single row dataframe matching feature contract columns
        df = pd.DataFrame([feature_row])
        return float(self.predict_batch(df)[0])

    def predict_batch(self, df: pd.DataFrame) -> np.ndarray:
        """
        Predict probabilities for a batch of window features.
        """
        if self.model is None:
            self.load_model()

        # Check and align columns based on feature contract
        aligned_df = pd.DataFrame(index=df.index)
        for col in self.features:
            if col in df.columns:
                aligned_df[col] = df[col]
            else:
                # Fill missing columns with 0.0 or default
                aligned_df[col] = 0.0

        # Fill NaNs with 0.0 to prevent LightGBM errors
        aligned_df = aligned_df.fillna(0.0)

        # Run LightGBM model predict_proba
        try:
            probs = self.model.predict_proba(aligned_df)[:, 1]
        except Exception as e:
            logger.error(f"Prediction failed: {e}")
            raise e

        return probs
