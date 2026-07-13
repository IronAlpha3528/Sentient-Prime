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

logger = logging.getLogger(__name__)

def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    logger.info("Initializing Endpoint Specialist evaluation script...")

    # Paths
    test_split_path = Path("data/processed/endpoint/test_split_temp.parquet")
    model_dir = Path("models/endpoint")
    reports_dir = Path("data/processed/endpoint/reports")

    if not test_split_path.exists():
        logger.error(f"Test split parquet not found at {test_split_path}. Run train_endpoint first.")
        sys.exit(1)

    # 1. Load active model and configuration
    model_file = model_dir / "lightgbm_model.pkl"
    if not model_file.exists():
        logger.error(f"Model file not found at {model_file}")
        sys.exit(1)

    model = joblib.load(model_file)
    
    with open(model_dir / "feature_contract.json", "r", encoding="utf-8") as f:
        contract = json.load(f)
    features = list(contract.keys())

    with open(model_dir / "training_metadata.json", "r", encoding="utf-8") as f:
        metadata = json.load(f)
    version = metadata.get("model_version", "v1")

    # 2. Load test split
    df_test = pd.read_parquet(test_split_path)
    X_test = df_test[features]
    y_test = df_test["label"]

    # 3. Prediction
    probs = model.predict_proba(X_test)[:, 1]
    y_pred = model.predict(X_test)

    # 4. Calculate metrics
    accuracy = float(accuracy_score(y_test, y_pred))
    precision = float(precision_score(y_test, y_pred, zero_division=0))
    recall = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    
    try:
        roc_auc = float(roc_auc_score(y_test, probs))
    except Exception:
        roc_auc = 0.0

    p_curve, r_curve, _ = precision_recall_curve(y_test, probs)
    pr_auc = float(auc(r_curve, p_curve))
    
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = [int(x) for x in cm.ravel()]

    metrics = {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "confusion_matrix": {
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "true_positives": tp
        }
    }

    # Save metrics to active model dir and version folder
    v_folder = model_dir / version
    for path in [model_dir, v_folder]:
        with open(path / "model_metrics.json", "w", encoding="utf-8") as f:
            json.dump(metrics, f, indent=2)

    logger.info("Test set classification performance:")
    logger.info(f"  Accuracy:  {accuracy:.4f}")
    logger.info(f"  Precision: {precision:.4f}")
    logger.info(f"  Recall:    {recall:.4f}")
    logger.info(f"  F1 Score:  {f1:.4f}")
    logger.info(f"  ROC AUC:   {roc_auc:.4f}")
    logger.info(f"  PR AUC:    {pr_auc:.4f}")

    # 5. Error Analysis (Top False Positives & False Negatives)
    df_test["prob"] = probs
    df_test["pred"] = y_pred

    false_positives = df_test[(df_test["label"] == 0) & (df_test["pred"] == 1)].sort_values(by="prob", ascending=False)
    false_negatives = df_test[(df_test["label"] == 1) & (df_test["pred"] == 0)].sort_values(by="prob", ascending=True)

    fp_list = []
    for _, row in false_positives.head(10).iterrows():
        fp_list.append({
            "window_id": row["window_id"],
            "process": row["process"],
            "parent_process": row["parent_process"],
            "probability": float(row["prob"]),
            "event_count": int(row["event_count"])
        })

    fn_list = []
    for _, row in false_negatives.head(10).iterrows():
        fn_list.append({
            "window_id": row["window_id"],
            "process": row["process"],
            "parent_process": row["parent_process"],
            "probability": float(row["prob"]),
            "event_count": int(row["event_count"])
        })

    # 6. Save Reports
    eval_report = {
        "model_version": version,
        "metrics": metrics,
        "top_false_positives": fp_list,
        "top_false_negatives": fn_list
    }
    
    with open(reports_dir / "evaluation_report.json", "w", encoding="utf-8") as f:
        json.dump(eval_report, f, indent=2)

    # Markdown report
    fp_rows = "\n".join(f"| {x['window_id']} | {x['process']} | {x['probability']:.4f} | {x['event_count']} |" for x in fp_list)
    fn_rows = "\n".join(f"| {x['window_id']} | {x['process']} | {x['probability']:.4f} | {x['event_count']} |" for x in fn_list)

    md_content = f"""# Evaluation Report

Model classification statistics computed against chronological test split dataset.

## Classifier Performance Metrics
- **Accuracy**: {accuracy:.4f}
- **Precision**: {precision:.4f}
- **Recall**: {recall:.4f}
- **F1 Score**: {f1:.4f}
- **ROC AUC**: {roc_auc:.4f}
- **PR AUC**: {pr_auc:.4f}

### Confusion Matrix
- **True Negatives**: {tn}
- **True Positives**: {tp}
- **False Positives**: {fp}
- **False Negatives**: {fn}

## False Positive Error Analysis (Benign windows classified as Attack)
| Window ID | Process | Prediction Prob | Event Count |
|---|---|---|---|
{fp_rows if fp_rows else "| None | - | - | - |"}

## False Negative Error Analysis (Attack windows classified as Benign)
| Window ID | Process | Prediction Prob | Event Count |
|---|---|---|---|
{fn_rows if fn_rows else "| None | - | - | - |"}
"""
    (reports_dir / "evaluation_report.md").write_text(md_content, encoding="utf-8")

    # Clean up temp test split file
    if test_split_path.exists():
        os.remove(test_split_path)
    logger.info("Evaluation report generated successfully.")

if __name__ == "__main__":
    main()
