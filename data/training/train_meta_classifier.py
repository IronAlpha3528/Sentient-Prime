import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from sentinel_prime.detection.correlation.meta_classifier import MetaClassifier, FEATURE_COLUMNS, SEVERITY_MAP

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("train_meta_classifier")

MODEL_PATH = Path("data/models/meta_lightgbm.pkl")
SEED = 42

def generate_benign_scenarios(n: int) -> pd.DataFrame:
    """Generates benign scenarios representing normal noise."""
    np.random.seed(SEED)
    data = []
    for _ in range(n):
        row = {
            "network_score": np.random.uniform(0.0, 0.25),
            "network_confidence": np.random.uniform(0.8, 1.0),
            "network_severity": np.random.choice(["INFO", "LOW", "MEDIUM"], p=[0.6, 0.3, 0.1]),
            
            "identity_score": np.random.uniform(0.0, 0.28),
            "identity_confidence": np.random.uniform(0.8, 1.0),
            "identity_severity": np.random.choice(["INFO", "LOW", "MEDIUM"], p=[0.7, 0.2, 0.1]),
            
            "endpoint_score": np.random.uniform(0.0, 0.25),
            "endpoint_confidence": np.random.uniform(0.8, 1.0),
            "endpoint_severity": np.random.choice(["INFO", "LOW", "MEDIUM"], p=[0.7, 0.2, 0.1]),
            
            "ot_score": np.random.uniform(0.0, 0.20),
            "ot_confidence": np.random.uniform(0.8, 1.0),
            "ot_severity": np.random.choice(["INFO", "LOW"], p=[0.8, 0.2]),
            
            "honeypot_touched": 0.0,
            
            "degree_centrality": np.random.uniform(0.0, 0.05),
            "betweenness_centrality": np.random.uniform(0.0, 0.02),
            "closeness_centrality": np.random.uniform(0.0, 0.05),
            "pagerank": np.random.uniform(0.0, 0.03),
            
            "weakly_connected_components_count": np.random.randint(1, 6),
            "communities_count": np.random.randint(1, 4),
            "community_size": np.random.randint(1, 5),
            "node_degree": np.random.randint(0, 3),
            
            "threat_intel_match_count": np.random.randint(0, 2),
            "max_threat_intel_score": np.random.uniform(0.0, 0.20),
            
            "evidence_diversity": np.random.randint(0, 2),
            "evidence_count": np.random.randint(0, 3),
            "sigma_match_count": np.random.randint(0, 2),
            "historical_incident_frequency": np.random.randint(0, 2),
            "temporal_activity": np.random.uniform(0.0, 60.0),
            
            "monitoring_queue_size": np.random.uniform(0.0, 5.0),
            "monitoring_latency": np.random.uniform(0.1, 3.0),
            "label": 0
        }
        data.append(row)
        
    return pd.DataFrame(data)

def generate_malicious_scenarios(n: int) -> pd.DataFrame:
    """Generates diverse malicious scenario variations: single-domain, multi-stage, honeypots."""
    np.random.seed(SEED + 1)
    data = []
    
    # 1. Network-only attack (20% of malicious)
    n_net = int(n * 0.20)
    for _ in range(n_net):
        row = {
            "network_score": np.random.uniform(0.65, 0.95),
            "network_confidence": np.random.uniform(0.85, 1.0),
            "network_severity": np.random.choice(["HIGH", "CRITICAL"], p=[0.7, 0.3]),
            
            "identity_score": np.random.uniform(0.0, 0.25),
            "identity_confidence": np.random.uniform(0.8, 1.0),
            "identity_severity": "INFO",
            
            "endpoint_score": np.random.uniform(0.0, 0.25),
            "endpoint_confidence": np.random.uniform(0.8, 1.0),
            "endpoint_severity": "INFO",
            
            "ot_score": np.random.uniform(0.0, 0.20),
            "ot_confidence": np.random.uniform(0.8, 1.0),
            "ot_severity": "INFO",
            
            "honeypot_touched": 0.0,
            
            "degree_centrality": np.random.uniform(0.04, 0.12),
            "betweenness_centrality": np.random.uniform(0.01, 0.08),
            "closeness_centrality": np.random.uniform(0.04, 0.12),
            "pagerank": np.random.uniform(0.02, 0.08),
            
            "weakly_connected_components_count": np.random.randint(1, 4),
            "communities_count": np.random.randint(1, 3),
            "community_size": np.random.randint(1, 5),
            "node_degree": np.random.randint(1, 4),
            
            "threat_intel_match_count": np.random.randint(1, 4),
            "max_threat_intel_score": np.random.uniform(0.40, 0.85),
            
            "evidence_diversity": 1,
            "evidence_count": np.random.randint(1, 4),
            "sigma_match_count": 0,
            "historical_incident_frequency": np.random.randint(0, 2),
            "temporal_activity": np.random.uniform(5.0, 180.0),
            
            "monitoring_queue_size": np.random.uniform(0.0, 8.0),
            "monitoring_latency": np.random.uniform(0.1, 4.0),
            "label": 1
        }
        data.append(row)

    # 2. Identity-only attack (20% of malicious)
    n_id = int(n * 0.20)
    for _ in range(n_id):
        row = {
            "network_score": np.random.uniform(0.0, 0.25),
            "network_confidence": np.random.uniform(0.8, 1.0),
            "network_severity": "INFO",
            
            "identity_score": np.random.uniform(0.68, 0.94),
            "identity_confidence": np.random.uniform(0.80, 1.0),
            "identity_severity": np.random.choice(["HIGH", "CRITICAL"]),
            
            "endpoint_score": np.random.uniform(0.0, 0.25),
            "endpoint_confidence": np.random.uniform(0.8, 1.0),
            "endpoint_severity": "INFO",
            
            "ot_score": np.random.uniform(0.0, 0.20),
            "ot_confidence": np.random.uniform(0.8, 1.0),
            "ot_severity": "INFO",
            
            "honeypot_touched": 0.0,
            
            "degree_centrality": np.random.uniform(0.04, 0.10),
            "betweenness_centrality": np.random.uniform(0.01, 0.06),
            "closeness_centrality": np.random.uniform(0.04, 0.10),
            "pagerank": np.random.uniform(0.02, 0.07),
            
            "weakly_connected_components_count": np.random.randint(1, 3),
            "communities_count": np.random.randint(1, 3),
            "community_size": np.random.randint(1, 4),
            "node_degree": np.random.randint(1, 4),
            
            "threat_intel_match_count": np.random.randint(0, 3),
            "max_threat_intel_score": np.random.uniform(0.10, 0.60),
            
            "evidence_diversity": 1,
            "evidence_count": np.random.randint(1, 3),
            "sigma_match_count": 0,
            "historical_incident_frequency": np.random.randint(0, 3),
            "temporal_activity": np.random.uniform(10.0, 240.0),
            
            "monitoring_queue_size": np.random.uniform(0.0, 5.0),
            "monitoring_latency": np.random.uniform(0.1, 3.0),
            "label": 1
        }
        data.append(row)

    # 3. Endpoint attack (20% of malicious)
    n_ep = int(n * 0.20)
    for _ in range(n_ep):
        row = {
            "network_score": np.random.uniform(0.0, 0.25),
            "network_confidence": np.random.uniform(0.8, 1.0),
            "network_severity": "INFO",
            
            "identity_score": np.random.uniform(0.0, 0.25),
            "identity_confidence": np.random.uniform(0.8, 1.0),
            "identity_severity": "INFO",
            
            "endpoint_score": np.random.uniform(0.72, 0.98),
            "endpoint_confidence": np.random.uniform(0.90, 1.0),
            "endpoint_severity": np.random.choice(["HIGH", "CRITICAL"]),
            
            "ot_score": np.random.uniform(0.0, 0.20),
            "ot_confidence": np.random.uniform(0.8, 1.0),
            "ot_severity": "INFO",
            
            "honeypot_touched": 0.0,
            
            "degree_centrality": np.random.uniform(0.05, 0.15),
            "betweenness_centrality": np.random.uniform(0.02, 0.09),
            "closeness_centrality": np.random.uniform(0.05, 0.15),
            "pagerank": np.random.uniform(0.03, 0.09),
            
            "weakly_connected_components_count": np.random.randint(1, 4),
            "communities_count": np.random.randint(1, 3),
            "community_size": np.random.randint(1, 5),
            "node_degree": np.random.randint(1, 5),
            
            "threat_intel_match_count": np.random.randint(1, 4),
            "max_threat_intel_score": np.random.uniform(0.50, 0.90),
            
            "evidence_diversity": 1,
            "evidence_count": np.random.randint(1, 5),
            "sigma_match_count": np.random.randint(1, 4),
            "historical_incident_frequency": np.random.randint(0, 3),
            "temporal_activity": np.random.uniform(5.0, 120.0),
            
            "monitoring_queue_size": np.random.uniform(0.0, 8.0),
            "monitoring_latency": np.random.uniform(0.1, 4.0),
            "label": 1
        }
        data.append(row)

    # 4. OT attack (15% of malicious)
    n_ot = int(n * 0.15)
    for _ in range(n_ot):
        row = {
            "network_score": np.random.uniform(0.0, 0.25),
            "network_confidence": np.random.uniform(0.8, 1.0),
            "network_severity": "INFO",
            
            "identity_score": np.random.uniform(0.0, 0.25),
            "identity_confidence": np.random.uniform(0.8, 1.0),
            "identity_severity": "INFO",
            
            "endpoint_score": np.random.uniform(0.0, 0.25),
            "endpoint_confidence": np.random.uniform(0.8, 1.0),
            "endpoint_severity": "INFO",
            
            "ot_score": np.random.uniform(0.70, 0.97),
            "ot_confidence": np.random.uniform(0.85, 1.0),
            "ot_severity": np.random.choice(["HIGH", "CRITICAL"]),
            
            "honeypot_touched": 0.0,
            
            "degree_centrality": np.random.uniform(0.02, 0.08),
            "betweenness_centrality": np.random.uniform(0.0, 0.04),
            "closeness_centrality": np.random.uniform(0.02, 0.08),
            "pagerank": np.random.uniform(0.01, 0.05),
            
            "weakly_connected_components_count": np.random.randint(1, 3),
            "communities_count": np.random.randint(1, 3),
            "community_size": np.random.randint(1, 3),
            "node_degree": np.random.randint(1, 3),
            
            "threat_intel_match_count": np.random.randint(0, 2),
            "max_threat_intel_score": np.random.uniform(0.0, 0.40),
            
            "evidence_diversity": 1,
            "evidence_count": np.random.randint(1, 3),
            "sigma_match_count": 0,
            "historical_incident_frequency": np.random.randint(0, 2),
            "temporal_activity": np.random.uniform(2.0, 60.0),
            
            "monitoring_queue_size": np.random.uniform(0.0, 4.0),
            "monitoring_latency": np.random.uniform(0.1, 2.0),
            "label": 1
        }
        data.append(row)

    # 5. Multi-stage attack (15% of malicious)
    n_multi = int(n * 0.15)
    for _ in range(n_multi):
        row = {
            "network_score": np.random.uniform(0.60, 0.92),
            "network_confidence": np.random.uniform(0.85, 1.0),
            "network_severity": np.random.choice(["HIGH", "CRITICAL"]),
            
            "identity_score": np.random.uniform(0.65, 0.90),
            "identity_confidence": np.random.uniform(0.80, 1.0),
            "identity_severity": np.random.choice(["MEDIUM", "HIGH"]),
            
            "endpoint_score": np.random.uniform(0.70, 0.95),
            "endpoint_confidence": np.random.uniform(0.85, 1.0),
            "endpoint_severity": np.random.choice(["HIGH", "CRITICAL"]),
            
            "ot_score": np.random.uniform(0.0, 0.35),
            "ot_confidence": np.random.uniform(0.8, 1.0),
            "ot_severity": "INFO",
            
            "honeypot_touched": 0.0,
            
            "degree_centrality": np.random.uniform(0.15, 0.45),
            "betweenness_centrality": np.random.uniform(0.08, 0.25),
            "closeness_centrality": np.random.uniform(0.15, 0.45),
            "pagerank": np.random.uniform(0.08, 0.20),
            
            "weakly_connected_components_count": np.random.randint(1, 3),
            "communities_count": np.random.randint(2, 5),
            "community_size": np.random.randint(3, 10),
            "node_degree": np.random.randint(3, 8),
            
            "threat_intel_match_count": np.random.randint(2, 5),
            "max_threat_intel_score": np.random.uniform(0.70, 0.98),
            
            "evidence_diversity": np.random.randint(2, 4),
            "evidence_count": np.random.randint(3, 9),
            "sigma_match_count": np.random.randint(1, 5),
            "historical_incident_frequency": np.random.randint(1, 5),
            "temporal_activity": np.random.uniform(30.0, 360.0),
            
            "monitoring_queue_size": np.random.uniform(2.0, 12.0),
            "monitoring_latency": np.random.uniform(0.5, 6.0),
            "label": 1
        }
        data.append(row)

    # 6. Honeypot Touched (10% of malicious)
    n_honey = n - n_net - n_id - n_ep - n_ot - n_multi
    for _ in range(max(0, n_honey)):
        row = {
            "network_score": np.random.uniform(0.0, 0.60),
            "network_confidence": np.random.uniform(0.8, 1.0),
            "network_severity": np.random.choice(["INFO", "LOW", "MEDIUM"]),
            
            "identity_score": np.random.uniform(0.0, 0.60),
            "identity_confidence": np.random.uniform(0.8, 1.0),
            "identity_severity": np.random.choice(["INFO", "LOW"]),
            
            "endpoint_score": np.random.uniform(0.0, 0.60),
            "endpoint_confidence": np.random.uniform(0.8, 1.0),
            "endpoint_severity": np.random.choice(["INFO", "LOW", "MEDIUM"]),
            
            "ot_score": np.random.uniform(0.0, 0.50),
            "ot_confidence": np.random.uniform(0.8, 1.0),
            "ot_severity": "INFO",
            
            "honeypot_touched": 1.0,
            
            "degree_centrality": np.random.uniform(0.05, 0.25),
            "betweenness_centrality": np.random.uniform(0.01, 0.12),
            "closeness_centrality": np.random.uniform(0.05, 0.25),
            "pagerank": np.random.uniform(0.03, 0.12),
            
            "weakly_connected_components_count": np.random.randint(1, 4),
            "communities_count": np.random.randint(1, 4),
            "community_size": np.random.randint(2, 6),
            "node_degree": np.random.randint(1, 5),
            
            "threat_intel_match_count": np.random.randint(1, 3),
            "max_threat_intel_score": np.random.uniform(0.30, 0.80),
            
            "evidence_diversity": np.random.randint(1, 3),
            "evidence_count": np.random.randint(1, 5),
            "sigma_match_count": np.random.randint(0, 3),
            "historical_incident_frequency": np.random.randint(0, 2),
            "temporal_activity": np.random.uniform(5.0, 120.0),
            
            "monitoring_queue_size": np.random.uniform(0.0, 8.0),
            "monitoring_latency": np.random.uniform(0.1, 4.0),
            "label": 1
        }
        data.append(row)

    return pd.DataFrame(data)

def main() -> None:
    logger.info("Generating scenario datasets for training...")
    
    benign_df = generate_benign_scenarios(1000)
    malicious_df = generate_malicious_scenarios(1500)
    
    df = pd.concat([benign_df, malicious_df], ignore_index=True)
    df = df.sample(frac=1, random_state=SEED).reset_index(drop=True)
    
    X = df[FEATURE_COLUMNS].copy()
    
    # Map categorical severities to numeric before train split using SEVERITY_MAP
    severity_cols = ["network_severity", "identity_severity", "endpoint_severity", "ot_severity"]
    for col in severity_cols:
        X[col] = df[col].map(lambda x: SEVERITY_MAP.get(str(x).upper(), 0.0) if isinstance(x, str) else float(x))
        
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=SEED, stratify=y)
    
    logger.info(f"Dataset split: Train={X_train.shape[0]}, Test={X_test.shape[0]}")
    
    # Save simulated dataset to disk for reproducibility
    processed_dir = Path("data/processed/correlation")
    processed_dir.mkdir(parents=True, exist_ok=True)
    df.to_parquet(processed_dir / "meta_training_data.parquet")
    logger.info(f"Simulated training dataset saved to {processed_dir / 'meta_training_data.parquet'}")
    
    # Initialize and train Meta-Classifier
    classifier = MetaClassifier(model_path=str(MODEL_PATH))
    results = classifier.train(X_train, y_train)
    
    # Evaluate on hold-out Test Set
    import lightgbm as lgb
    from sklearn.metrics import accuracy_score, classification_report, roc_auc_score
    
    # Run test prediction
    df_test = X_test[FEATURE_COLUMNS].fillna(0.0)
    test_probs = classifier.model.predict_proba(df_test)[:, 1]
    test_preds = classifier.model.predict(df_test)
    
    test_acc = accuracy_score(y_test, test_preds)
    test_auc = roc_auc_score(y_test, test_probs)
    
    print("\n=======================================================")
    print("META-CLASSIFIER EVALUATION REPORT")
    print("=======================================================")
    print(f"Test Accuracy: {test_acc:.4f}")
    print(f"Test ROC-AUC:  {test_auc:.4f}")
    print("\nClassification Report:")
    report = classification_report(y_test, test_preds)
    print(report)
    print("Feature Importances:")
    sorted_importance = sorted(results["feature_importances"].items(), key=lambda item: item[1], reverse=True)
    for feat, val in sorted_importance[:10]:
        print(f"  {feat}: {val:.4f}")
    print("=======================================================\n")
    
    logger.info("Successfully trained and serialized Unified LightGBM Meta-Classifier!")

if __name__ == "__main__":
    main()
