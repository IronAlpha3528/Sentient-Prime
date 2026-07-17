import datetime
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import joblib
import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# Severity mapping to convert categorical severities to numeric features
SEVERITY_MAP = {
    "INFO": 0.1,
    "LOW": 0.3,
    "MEDIUM": 0.5,
    "HIGH": 0.8,
    "CRITICAL": 1.0
}

# Standard feature columns list for the Meta-Classifier
FEATURE_COLUMNS = [
    "network_score",
    "network_confidence",
    "network_severity",
    "identity_score",
    "identity_confidence",
    "identity_severity",
    "endpoint_score",
    "endpoint_confidence",
    "endpoint_severity",
    "ot_score",
    "ot_confidence",
    "ot_severity",
    "honeypot_touched",
    "degree_centrality",
    "betweenness_centrality",
    "closeness_centrality",
    "pagerank",
    "weakly_connected_components_count",
    "communities_count",
    "community_size",
    "node_degree",
    "threat_intel_match_count",
    "max_threat_intel_score",
    "evidence_diversity",
    "evidence_count",
    "sigma_match_count",
    "historical_incident_frequency",
    "temporal_activity",
    "monitoring_queue_size",
    "monitoring_latency"
]

class MetaClassifier:
    """Combines specialist detector scores, graph topological features,

    deception indicators, and threat intelligence into a Unified Threat Score.
    """

    def __init__(self, model_path: str = "data/models/meta_lightgbm.pkl"):
        self.model_path = Path(model_path)
        self.model: Optional[Any] = None
        self.feature_columns: List[str] = FEATURE_COLUMNS
        self.model_version: str = "meta-lightgbm-correlation-v1.0"
        self.fallback_mode: bool = True
        
        self.load_model()

    def load_model(self) -> None:
        """Loads the serialized LightGBM model from disk."""
        if self.model_path.exists():
            try:
                self.model = joblib.load(self.model_path)
                self.fallback_mode = False
                logger.info(f"Loaded Meta-Classifier model from {self.model_path}")
            except Exception as e:
                logger.error(f"Failed to load Meta-Classifier model from {self.model_path}: {e}")
                self.fallback_mode = True
        else:
            logger.warning(f"Meta-Classifier model not found at {self.model_path}. Running in rule-based fallback mode.")
            self.fallback_mode = True

    def save_model(self) -> None:
        """Saves the current model to the configured model path."""
        try:
            self.model_path.parent.mkdir(parents=True, exist_ok=True)
            joblib.dump(self.model, self.model_path)
            logger.info(f"Saved Meta-Classifier model to {self.model_path}")
        except Exception as e:
            logger.error(f"Failed to save Meta-Classifier model to {self.model_path}: {e}")

    def train(self, X: pd.DataFrame, y: pd.Series, hyperparams: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Trains the LightGBM classifier on scenario datasets."""
        import lightgbm as lgb
        from sklearn.metrics import accuracy_score, classification_report, roc_auc_score

        logger.info(f"Starting Meta-Classifier training. Data shape: {X.shape}")
        
        # Verify feature columns contract
        missing = [col for col in self.feature_columns if col not in X.columns]
        if missing:
            raise ValueError(f"Training DataFrame is missing feature columns: {missing}")

        X_train = X[self.feature_columns].fillna(0.0)

        # Base hyperparameter configuration
        params = {
            "n_estimators": 50,
            "max_depth": 5,
            "learning_rate": 0.05,
            "num_leaves": 31,
            "random_state": 42,
            "n_jobs": -1
        }
        if hyperparams:
            params.update(hyperparams)

        model = lgb.LGBMClassifier(**params)
        model.fit(X_train, y)

        self.model = model
        self.fallback_mode = False
        self.save_model()

        # Save feature column contract for runtime sanity check
        contract_path = self.model_path.parent / "meta_feature_columns.json"
        try:
            with open(contract_path, "w", encoding="utf-8") as f:
                json.dump(self.feature_columns, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to write features contract: {e}")

        # Compute training performance metrics
        preds = model.predict(X_train)
        probs = model.predict_proba(X_train)[:, 1]
        
        acc = accuracy_score(y, preds)
        auc = roc_auc_score(y, probs) if len(np.unique(y)) > 1 else 1.0
        
        # Calculate feature importances
        importances = dict(zip(self.feature_columns, [float(v) for v in model.feature_importances_]))
        
        logger.info(f"Meta-Classifier training completed. Accuracy: {acc:.4f}, AUC: {auc:.4f}")

        return {
            "accuracy": acc,
            "auc": auc,
            "feature_importances": importances,
            "classification_report": classification_report(y, preds, output_dict=True)
        }

    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Fuses input features into a unified threat score and explanation.

        Handles missing/NaN features robustly, computes local explanations,
        and logs performance/errors.
        """
        start_time = time.time()
        
        try:
            # 1. Clean and normalize input feature dictionary
            cleaned_feats = {}
            for col in self.feature_columns:
                val = features.get(col)
                if val is None or (isinstance(val, float) and np.isnan(val)):
                    # Assign sensible defaults based on feature type
                    if "confidence" in col:
                        cleaned_feats[col] = 1.0
                    else:
                        cleaned_feats[col] = 0.0
                elif isinstance(val, str) and col in ["network_severity", "identity_severity", "endpoint_severity", "ot_severity"]:
                    cleaned_feats[col] = SEVERITY_MAP.get(val.upper(), 0.0)
                else:
                    try:
                        cleaned_feats[col] = float(val)
                    except ValueError:
                        cleaned_feats[col] = 0.0

            # 2. Prediction execution
            if self.fallback_mode or self.model is None:
                # Rule-based fallback calculation
                unified_score, confidence_score = self._predict_fallback(cleaned_feats)
                # Fallback feature importance mapping
                global_importances = {col: 1.0 / len(self.feature_columns) for col in self.feature_columns}
            else:
                # Model-based inference
                df = pd.DataFrame([cleaned_feats], columns=self.feature_columns)
                probs = self.model.predict_proba(df)[0]
                unified_score = float(probs[1]) # probability of malicious class
                
                # Confidence estimation: 0.5 * model probability certainty + 0.5 * input confidence
                model_certainty = 2.0 * abs(unified_score - 0.5)
                
                detector_confs = [
                    cleaned_feats["network_confidence"],
                    cleaned_feats["identity_confidence"],
                    cleaned_feats["endpoint_confidence"],
                    cleaned_feats["ot_confidence"]
                ]
                mean_detector_conf = sum(detector_confs) / len(detector_confs) if detector_confs else 1.0
                confidence_score = 0.5 * model_certainty + 0.5 * mean_detector_conf
                
                # Extract model global importances
                raw_importances = self.model.feature_importances_
                total_importance = sum(raw_importances) if sum(raw_importances) > 0 else 1.0
                global_importances = {col: float(raw_importances[i]) / total_importance for i, col in enumerate(self.feature_columns)}

            # 3. Categorize risk level
            if unified_score < 0.40:
                risk_level = "LOW"
            elif unified_score < 0.75:
                risk_level = "HIGH" if unified_score >= 0.60 else "MEDIUM"
            else:
                risk_level = "CRITICAL"

            # 4. Calculate local instance-level feature contributions
            # Local contribution = absolute feature value * global importance weight
            contributions = {}
            for col in self.feature_columns:
                val = cleaned_feats[col]
                # Scale severity and scores directly, log transform centralities/counts for balance
                if "centrality" in col or "pagerank" in col or "count" in col or "degree" in col or "activity" in col:
                    weight_val = np.log1p(abs(val))
                else:
                    weight_val = abs(val)
                contributions[col] = weight_val * global_importances.get(col, 0.0)

            total_contrib = sum(contributions.values())
            if total_contrib > 0:
                contributions = {col: (v / total_contrib) for col, v in contributions.items()}
            else:
                contributions = {col: 1.0 / len(self.feature_columns) for col in self.feature_columns}

            # 5. Group contributions by detector categories
            detector_breakdown = {
                "network": contributions.get("network_score", 0.0) + contributions.get("network_confidence", 0.0) + contributions.get("network_severity", 0.0),
                "identity": contributions.get("identity_score", 0.0) + contributions.get("identity_confidence", 0.0) + contributions.get("identity_severity", 0.0),
                "endpoint": contributions.get("endpoint_score", 0.0) + contributions.get("endpoint_confidence", 0.0) + contributions.get("endpoint_severity", 0.0) + contributions.get("sigma_match_count", 0.0),
                "ot": contributions.get("ot_score", 0.0) + contributions.get("ot_confidence", 0.0) + contributions.get("ot_severity", 0.0),
                "graph": (
                    contributions.get("degree_centrality", 0.0) +
                    contributions.get("betweenness_centrality", 0.0) +
                    contributions.get("closeness_centrality", 0.0) +
                    contributions.get("pagerank", 0.0) +
                    contributions.get("weakly_connected_components_count", 0.0) +
                    contributions.get("communities_count", 0.0) +
                    contributions.get("community_size", 0.0) +
                    contributions.get("node_degree", 0.0)
                ),
                "threat_intel": contributions.get("threat_intel_match_count", 0.0) + contributions.get("max_threat_intel_score", 0.0),
                "deception": contributions.get("honeypot_touched", 0.0),
                "other": contributions.get("evidence_diversity", 0.0) + contributions.get("evidence_count", 0.0) + contributions.get("historical_incident_frequency", 0.0) + contributions.get("temporal_activity", 0.0) + contributions.get("monitoring_queue_size", 0.0) + contributions.get("monitoring_latency", 0.0)
            }

            # Normalize detector breakdown to sum to 1.0
            sum_breakdown = sum(detector_breakdown.values())
            if sum_breakdown > 0:
                detector_breakdown = {k: (v / sum_breakdown) for k, v in detector_breakdown.items()}

            # Extract top 5 contributing features
            sorted_contribs = sorted(contributions.items(), key=lambda item: item[1], reverse=True)
            top_features = [col for col, _ in sorted_contribs[:5]]

            latency_ms = (time.time() - start_time) * 1000.0
            
            result = {
                "unified_threat_score": round(unified_score, 4),
                "confidence_score": round(confidence_score, 4),
                "risk_level": risk_level,
                "top_features": top_features,
                "detector_contributions": {k: round(v, 4) for k, v in detector_breakdown.items()},
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "model_version": self.model_version + ("-fallback" if self.fallback_mode else "")
            }

            # 6. Performance Logging
            logger.info(
                f"Meta-Classifier prediction complete | "
                f"Score: {result['unified_threat_score']:.4f} | "
                f"Confidence: {result['confidence_score']:.4f} | "
                f"Risk: {result['risk_level']} | "
                f"Mode: {'Fallback' if self.fallback_mode else 'Model'} | "
                f"Latency: {latency_ms:.2f}ms"
            )

            return result

        except Exception as e:
            logger.error(f"Critical error in Meta-Classifier prediction: {e}", exc_info=True)
            return {
                "unified_threat_score": 0.5,
                "confidence_score": 0.1,
                "risk_level": "MEDIUM",
                "top_features": [],
                "detector_contributions": {},
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "model_version": self.model_version + "-error"
            }

    def _predict_fallback(self, cleaned_feats: Dict[str, float]) -> tuple[float, float]:
        """Provides a high-fidelity deterministic threat score fallback calculation."""
        # 1. Override signal: Honeypot / Deception triggered
        if cleaned_feats["honeypot_touched"] > 0.5:
            return 0.95, 0.99

        # 2. Weighted average of detector risk scores
        # We give slightly higher weights to Endpoint and OT scores, as they directly indicate impact
        scores = [
            (cleaned_feats["network_score"], 0.25),
            (cleaned_feats["identity_score"], 0.25),
            (cleaned_feats["endpoint_score"], 0.30),
            (cleaned_feats["ot_score"], 0.20)
        ]
        
        active_scores = [val for val, _ in scores if val > 0.0]
        max_active = max(active_scores) if active_scores else 0.0
        
        weighted_sum = sum(val * weight for val, weight in scores)
        weight_normalizer = sum(weight for val, weight in scores if val > 0.0)
        
        base_score = weighted_sum / weight_normalizer if weight_normalizer > 0 else 0.0

        # Adjust score upwards if there is evidence diversity (multi-stage attack indicators)
        diversity = cleaned_feats["evidence_diversity"]
        if diversity > 1:
            base_score += 0.05 * (diversity - 1)

        # Incorporate graph metrics (blast-radius / reachability multiplier)
        pagerank = cleaned_feats["pagerank"]
        deg_centrality = cleaned_feats["degree_centrality"]
        if pagerank > 0.1 or deg_centrality > 0.1:
            base_score += 0.05

        # Incorporate Threat Intel matches
        ti_score = cleaned_feats["max_threat_intel_score"]
        if ti_score > 0.5:
            base_score += 0.05

        unified_score = float(np.clip(max(base_score, max_active * 0.9), 0.0, 1.0))

        # Fallback confidence calculation based on mean detector confidence
        detector_confs = [
            cleaned_feats["network_confidence"],
            cleaned_feats["identity_confidence"],
            cleaned_feats["endpoint_confidence"],
            cleaned_feats["ot_confidence"]
        ]
        mean_conf = sum(detector_confs) / len(detector_confs) if detector_confs else 1.0

        return unified_score, float(np.clip(mean_conf, 0.0, 1.0))
