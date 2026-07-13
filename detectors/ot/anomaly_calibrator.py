import logging
import numpy as np
from typing import Dict, Any, Tuple

logger = logging.getLogger(__name__)

class AnomalyCalibrator:
    """
    Calibrates raw Isolation Forest anomaly scores to a normalized 0 to 1 range,
    estimating statistical significance (mean, std, percentiles) and assigning severity bands.
    """
    def __init__(
        self,
        mean: float = 0.0,
        std: float = 1.0,
        threshold_medium: float = 0.45,
        threshold_high: float = 0.70,
        threshold_critical: float = 0.85
    ):
        self.mean = mean
        self.std = std
        self.threshold_medium = threshold_medium
        self.threshold_high = threshold_high
        self.threshold_critical = threshold_critical

    def fit(self, raw_scores: np.ndarray) -> None:
        """
        Fits calibration baseline statistics from reference (normal) raw scores.
        Isolation Forest raw scores (score_samples) are typically negative.
        """
        # Convert raw scores to absolute positive anomaly indicators
        # score_samples: more negative = more anomalous. Let's make it positive:
        pos_scores = -raw_scores
        
        self.mean = float(np.mean(pos_scores))
        self.std = float(np.std(pos_scores)) if len(pos_scores) > 1 else 1.0
        
        logger.info(f"Anomaly Calibrator fitted: mean={self.mean:.4f}, std={self.std:.4f}")

    def calibrate(self, raw_score: float) -> Tuple[float, str]:
        """
        Normalizes a raw score and assigns a severity band:
        - LOW (< threshold_medium)
        - MEDIUM (threshold_medium <= score < threshold_high)
        - HIGH (threshold_high <= score < threshold_critical)
        - CRITICAL (>= threshold_critical)
        """
        # Convert raw score (more negative = more anomalous) to positive space
        pos_score = -raw_score
        
        # Calculate standard normal scaling (Z-score sigmas)
        # Clip between 0 and 1 using Sigmoid or MinMax. Let's use a Sigmoid-like scaling
        # based on standard normal deviation from mean.
        if self.std > 0:
            z_score = (pos_score - self.mean) / self.std
        else:
            z_score = 0.0
            
        # Map Z-score to 0-1 range using sigmoid function: 1 / (1 + exp(-z))
        # Center at z=0 (mean) and adjust scale
        normalized = 1.0 / (1.0 + np.exp(-z_score))
        
        # Assign severity
        if normalized >= self.threshold_critical:
            severity = "CRITICAL"
        elif normalized >= self.threshold_high:
            severity = "HIGH"
        elif normalized >= self.threshold_medium:
            severity = "MEDIUM"
        else:
            severity = "LOW"
            
        return normalized, severity
