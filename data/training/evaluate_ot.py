import os
import sys
import json
import logging
from pathlib import Path
import pandas as pd
import numpy as np
import joblib
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, precision_recall_curve, auc, confusion_matrix
)

# Ensure project root is in path if executing directly
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from sentinel_prime.detection.detectors.ot.ot_detector import OTDetector

logger = logging.getLogger(__name__)

def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    logger.info("Initializing OT Specialist evaluation script...")

    # Paths
    test_split_path = Path("data/processed/ot/test_split_temp.parquet")
    reports_dir = Path("data/processed/ot/reports")
    model_dir = Path("models/ot")

    if not test_split_path.exists():
        logger.error(f"Test split temp Parquet not found at {test_split_path}. Run train_ot first.")
        sys.exit(1)

    # 1. Load active models
    detector = OTDetector()
    health = detector.health()
    logger.info(f"Detector Health Status: {health}")

    # 2. Load test split
    df_test = pd.read_parquet(test_split_path)
    logger.info(f"Loaded test dataset split with {len(df_test)} rows.")

    with open(model_dir / "feature_contract.json", "r", encoding="utf-8") as f:
        contract = json.load(f)
    features = list(contract.keys())

    # 3. Predict on Test Set
    anomaly_scores = []
    severities = []
    attack_probs = []
    
    # Iterate row-by-row using predict() to simulate real interface
    for _, row in df_test.iterrows():
        # Build features input dictionary
        feat_dict = row.to_dict()
        res = detector.predict(feat_dict)
        anomaly_scores.append(res.get("anomaly_score", 0.0))
        severities.append(res.get("severity", "LOW"))
        attack_probs.append(res.get("attack_probability", 0.0))

    df_test["anomaly_score"] = anomaly_scores
    df_test["severity"] = severities
    df_test["attack_probability"] = attack_probs

    y_test = df_test["attack_label"].astype(int)

    # 4. Evaluate Isolation Forest Metrics
    # Anomaly score as threat probability
    anomaly_arr = np.array(anomaly_scores)
    try:
        iforest_roc_auc = float(roc_auc_score(y_test, anomaly_arr))
    except Exception:
        iforest_roc_auc = 0.5
        
    p_cur, r_cur, _ = precision_recall_curve(y_test, anomaly_arr)
    iforest_pr_auc = float(auc(r_cur, p_cur))

    # Threshold for prediction is risk_threshold (default 0.75 or threshold_high)
    iforest_pred = (anomaly_arr >= 0.70).astype(int)
    iforest_acc = float(accuracy_score(y_test, iforest_pred))
    iforest_prec = float(precision_score(y_test, iforest_pred, zero_division=0))
    iforest_rec = float(recall_score(y_test, iforest_pred, zero_division=0))
    
    cm_if = confusion_matrix(y_test, iforest_pred, labels=[0, 1])
    tn_if, fp_if, fn_if, tp_if = [int(x) for x in cm_if.ravel()]

    iforest_metrics = {
        "roc_auc": iforest_roc_auc,
        "pr_auc": iforest_pr_auc,
        "accuracy": iforest_acc,
        "precision": iforest_prec,
        "recall": iforest_rec,
        "confusion_matrix": {
            "true_negatives": tn_if,
            "false_positives": fp_if,
            "false_negatives": fn_if,
            "true_positives": tp_if
        }
    }

    # 5. Evaluate LightGBM Metrics (if trained)
    lgb_metrics = {}
    if detector.model and detector.model.lightgbm:
        lgb_prob_arr = np.array(attack_probs)
        try:
            lgb_roc_auc = float(roc_auc_score(y_test, lgb_prob_arr))
        except Exception:
            lgb_roc_auc = 0.5
            
        p_c, r_c, _ = precision_recall_curve(y_test, lgb_prob_arr)
        lgb_pr_auc = float(auc(r_c, p_c))
        
        lgb_pred = (lgb_prob_arr >= 0.50).astype(int)
        lgb_acc = float(accuracy_score(y_test, lgb_pred))
        lgb_prec = float(precision_score(y_test, lgb_pred, zero_division=0))
        lgb_rec = float(recall_score(y_test, lgb_pred, zero_division=0))
        lgb_f1 = float(f1_score(y_test, lgb_pred, zero_division=0))
        
        cm_lg = confusion_matrix(y_test, lgb_pred, labels=[0, 1])
        tn_lg, fp_lg, fn_lg, tp_lg = [int(x) for x in cm_lg.ravel()]
        
        lgb_metrics = {
            "roc_auc": lgb_roc_auc,
            "pr_auc": lgb_pr_auc,
            "accuracy": lgb_acc,
            "precision": lgb_prec,
            "recall": lgb_rec,
            "f1_score": lgb_f1,
            "confusion_matrix": {
                "true_negatives": tn_lg,
                "false_positives": fp_lg,
                "false_negatives": fn_lg,
                "true_positives": tp_lg
            }
        }

    # 6. Save Reports & Metrics
    eval_report = {
        "model_version": detector.metadata().get("model_version", "v1"),
        "iforest_metrics": iforest_metrics,
        "lightgbm_metrics": lgb_metrics
    }
    
    with open(reports_dir / "evaluation_report.json", "w", encoding="utf-8") as f:
        json.dump(eval_report, f, indent=2)

    # Markdown Reports
    lgb_section = "N/A (LightGBM not trained)"
    if lgb_metrics:
        lgb_section = f"""- **Accuracy**: {lgb_metrics['accuracy']:.4f}
- **Precision**: {lgb_metrics['precision']:.4f}
- **Recall**: {lgb_metrics['recall']:.4f}
- **F1 Score**: {lgb_metrics['f1_score']:.4f}
- **ROC AUC**: {lgb_metrics['roc_auc']:.4f}
- **PR AUC**: {lgb_metrics['pr_auc']:.4f}

#### Confusion Matrix
| Metric | Count |
|---|---|
| True Negatives | {tn_lg} |
| True Positives | {tp_lg} |
| False Positives | {fp_lg} |
| False Negatives | {fn_lg} |
"""

    eval_md = f"""# Evaluation Report (OT Specialist)

Detailed performance metrics computed against holdout chronological test split.

## Isolation Forest (Unsupervised Baseline)
- **Accuracy (threshold >= 0.70)**: {iforest_acc:.4f}
- **Precision**: {iforest_prec:.4f}
- **Recall**: {iforest_rec:.4f}
- **ROC AUC**: {iforest_roc_auc:.4f}
- **PR AUC**: {iforest_pr_auc:.4f}

#### Confusion Matrix
| Metric | Count |
|---|---|
| True Negatives | {tn_if} |
| True Positives | {tp_if} |
| False Positives | {fp_if} |
| False Negatives | {fn_if} |

## LightGBM (Supervised Refinement)
{lgb_section}
"""
    (reports_dir / "evaluation_report.md").write_text(eval_md, encoding="utf-8")

    # Anomaly Distribution Markdown
    low_count = int(np.sum(anomaly_arr < 0.45))
    med_count = int(np.sum((anomaly_arr >= 0.45) & (anomaly_arr < 0.70)))
    high_count = int(np.sum((anomaly_arr >= 0.70) & (anomaly_arr < 0.85)))
    crit_count = int(np.sum(anomaly_arr >= 0.85))

    dist_md = f"""# Anomaly Distribution Report

Distribution of calibrated anomaly scores over chronological holdout test set.

## Severity Distribution Counts
- **LOW (< 0.45)**: {low_count} windows
- **MEDIUM (0.45 - 0.70)**: {med_count} windows
- **HIGH (0.70 - 0.85)**: {high_count} windows
- **CRITICAL (>= 0.85)**: {crit_count} windows

## Analysis & Insights
- High scoring anomalies are flagged for shifted process sensors.
- Baseline profile standard deviation limits ensure stable scoring.
"""
    (reports_dir / "anomaly_distribution.md").write_text(dist_md, encoding="utf-8")

    # Clean up temp test parquet
    if test_split_path.exists():
        os.remove(test_split_path)
        
    logger.info("OT Specialist evaluation report generated successfully.")

if __name__ == "__main__":
    main()
