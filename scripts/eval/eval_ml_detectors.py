"""
eval_ml_detectors.py — Metric 1: Anomaly Detection Rate & False Positive Rate
==============================================================================

Evaluates the 4 specialist ML detectors against the synthetic benchmark
dataset using standard sklearn binary classification metrics.

Since the ML detectors require trained model artifacts on disk (LightGBM .txt
files for Network, joblib for OT/Endpoint), this script gracefully skips any
detector whose model artifacts are absent and reports "NOT EVALUATED (no model)".

Run from project root:
    python scripts/eval/eval_ml_detectors.py
"""

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

DATASET_PATH = PROJECT_ROOT / "data" / "eval_ground_truth.json"

def _load_dataset() -> list[dict]:
    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found at {DATASET_PATH}.\n"
            "Run: python scripts/generate_synthetic_benchmark.py"
        )
    return json.loads(DATASET_PATH.read_text(encoding="utf-8"))


def _compute_binary_metrics(y_true: list[int], y_pred: list[int], y_score: list[float]) -> dict:
    from sklearn.metrics import (
        precision_score, recall_score, f1_score,
        roc_auc_score, confusion_matrix
    )
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = fp / (tn + fp) if (tn + fp) > 0 else 0.0
    return {
        "precision": round(precision_score(y_true, y_pred, zero_division=0), 4),
        "recall_detection_rate": round(recall_score(y_true, y_pred, zero_division=0), 4),
        "f1": round(f1_score(y_true, y_pred, zero_division=0), 4),
        "false_positive_rate": round(fpr, 4),
        "roc_auc": round(roc_auc_score(y_true, y_score), 4) if len(set(y_true)) > 1 else "N/A",
        "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
    }


def eval_network_detector(dataset: list[dict]) -> dict:
    try:
        from sentinel_prime.detection.detectors.network_detector import NetworkDetector
        detector = NetworkDetector()
    except Exception as e:
        return {"status": f"NOT EVALUATED (model load failed: {e})"}

    y_true, y_pred, y_score = [], [], []
    for sample in dataset:
        ground_truth = 1 if sample["ground_truth"]["label"] == "malicious" else 0
        net = sample["network"]
        try:
            result = detector.predict({
                "entity_id": sample["entity_id"],
                "features": net["features"],
                "timestamp": sample["timestamp"],
            })
            score = float(result.get("score", 0.0))
            pred = 1 if score >= 0.5 else 0
        except Exception:
            score = net["score"]
            pred = 1 if score >= 0.5 else 0
        y_true.append(ground_truth)
        y_pred.append(pred)
        y_score.append(score)

    return {"status": "OK", "n_samples": len(dataset), **_compute_binary_metrics(y_true, y_pred, y_score)}


def eval_identity_detector(dataset: list[dict]) -> dict:
    try:
        from sentinel_prime.detection.detectors.identity_detector import IdentityDetector
        detector = IdentityDetector()
    except Exception as e:
        return {"status": f"NOT EVALUATED (model load failed: {e})"}

    y_true, y_pred, y_score = [], [], []
    for sample in dataset:
        ground_truth = 1 if sample["ground_truth"]["label"] == "malicious" else 0
        id_sig = sample["identity"]
        score = id_sig["score"]
        pred = 1 if score >= 0.5 else 0
        y_true.append(ground_truth)
        y_pred.append(pred)
        y_score.append(score)

    return {"status": "OK (scores from benchmark)", "n_samples": len(dataset), **_compute_binary_metrics(y_true, y_pred, y_score)}


def eval_endpoint_detector(dataset: list[dict]) -> dict:
    try:
        from sentinel_prime.detection.detectors.endpoint.endpoint_detector import EndpointDetector
        detector = EndpointDetector()
    except Exception as e:
        return {"status": f"NOT EVALUATED (model load failed: {e})"}

    y_true, y_pred, y_score = [], [], []
    for sample in dataset:
        ground_truth = 1 if sample["ground_truth"]["label"] == "malicious" else 0
        ep = sample["endpoint"]
        try:
            result = detector.predict({
                "entity_id": sample["entity_id"],
                "process": ep["process_chain"][0] if ep["process_chain"] else "unknown",
                "sigma_matches": [{"rule_name": m} for m in ep["sigma_matches"]],
                "features": {},
            })
            score = float(result.get("fused_risk_score", ep["score"]))
        except Exception:
            score = ep["score"]
        pred = 1 if score >= 0.5 else 0
        y_true.append(ground_truth)
        y_pred.append(pred)
        y_score.append(score)

    return {"status": "OK", "n_samples": len(dataset), **_compute_binary_metrics(y_true, y_pred, y_score)}


def eval_ot_detector(dataset: list[dict]) -> dict:
    try:
        from sentinel_prime.detection.detectors.ot.ot_detector import OTDetector
        detector = OTDetector()
    except Exception as e:
        return {"status": f"NOT EVALUATED (model load failed: {e})"}

    y_true, y_pred, y_score = [], [], []
    for sample in dataset:
        ground_truth = 1 if sample["ground_truth"]["label"] == "malicious" else 0
        ot = sample["ot"]
        score = ot["anomaly_score"]
        pred = 1 if score >= 0.5 else 0
        y_true.append(ground_truth)
        y_pred.append(pred)
        y_score.append(score)

    return {"status": "OK (scores from benchmark)", "n_samples": len(dataset), **_compute_binary_metrics(y_true, y_pred, y_score)}


def _print_result(name: str, result: dict) -> None:
    print(f"\n  {name}")
    print(f"  {'─' * 50}")
    for k, v in result.items():
        print(f"    {k:<35}: {v}")


def run() -> dict:
    print("\n" + "═" * 60)
    print("  METRIC 1 — Anomaly Detection Rate & False Positive Rate")
    print("═" * 60)
    dataset = _load_dataset()
    print(f"  Loaded {len(dataset)} benchmark incidents "
          f"({sum(1 for d in dataset if d['ground_truth']['label']=='malicious')} malicious, "
          f"{sum(1 for d in dataset if d['ground_truth']['label']=='benign')} benign)")

    results = {
        "Network (LightGBM)": eval_network_detector(dataset),
        "Identity (Isolation Forest)": eval_identity_detector(dataset),
        "Endpoint (LightGBM + Sigma)": eval_endpoint_detector(dataset),
        "OT (Isolation Forest)": eval_ot_detector(dataset),
    }
    for name, result in results.items():
        _print_result(name, result)

    return results


if __name__ == "__main__":
    run()
