import os
import sys
import time
import json
import logging
from pathlib import Path
from datetime import datetime
import pandas as pd
import numpy as np

# Ensure project root is in path if executing directly
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from detectors.ot.ot_detector import OTDetector

logger = logging.getLogger(__name__)

def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    logger.info("Initializing OT Specialist performance benchmark...")

    features_path = Path("data/processed/ot/features/ot_features.parquet")
    reports_dir = Path("data/processed/ot/reports")
    pred_dir = Path("data/processed/ot/predictions")
    root_pred_dir = Path("processed/ot/predictions")

    for d in [reports_dir, pred_dir, root_pred_dir]:
        d.mkdir(parents=True, exist_ok=True)

    if not features_path.exists():
        logger.error(f"Features Parquet not found at {features_path}")
        sys.exit(1)

    # 1. Load detector
    detector = OTDetector()
    health = detector.health()
    logger.info(f"Detector Health: {health}")

    df = pd.read_parquet(features_path)
    total_windows = len(df)
    logger.info(f"Loaded {total_windows} windows for evaluation.")

    # Convert to list of dicts to simulate records
    records = df.to_dict(orient="records")

    # 2. Benchmark batch predictions
    t0 = time.time()
    results = detector.predict_batch(records)
    t_inf = time.time() - t0

    predictions_sec = total_windows / t_inf if t_inf > 0 else 0.0
    avg_inf_latency_ms = (t_inf / total_windows) * 1000.0 if total_windows > 0 else 0.0

    # 3. Benchmark single window prediction (simulate streaming)
    sample_size = min(100, total_windows)
    sample_records = records[:sample_size]
    
    t_start = time.time()
    for rec in sample_records:
        detector.predict(rec)
    t_end = time.time()
    
    predict_latency_ms = ((t_end - t_start) / sample_size) * 1000.0 if sample_size > 0 else 0.0
    windows_sec = sample_size / (t_end - t_start) if (t_end - t_start) > 0 else 0.0

    # 4. Compile Metrics
    anomaly_scores = [r["anomaly_score"] for r in results]
    avg_score = float(np.mean(anomaly_scores)) if anomaly_scores else 0.0
    anomalous_count = int(np.sum(np.array(anomaly_scores) >= 0.70))

    # Top shifted variables overall
    top_shifted = []
    for r in results:
        top_shifted.extend(r.get("top_shifted_variables", []))
    shifted_counts = pd.Series(top_shifted).value_counts().head(5).to_dict()

    pred_summary = {
        "total_windows": total_windows,
        "normal_windows": total_windows - anomalous_count,
        "anomalous_windows": anomalous_count,
        "average_score": avg_score,
        "average_attack_probability": float(np.mean([r.get("attack_probability", 0.0) for r in results])),
        "top_shifted_variables": list(shifted_counts.keys()),
        "inference_time_seconds": t_inf
    }

    # Generate ot_dashboard.json
    dashboard_metrics = {
        "risk_histogram": {
            "low (0-0.45)": int(np.sum(np.array(anomaly_scores) < 0.45)),
            "medium (0.45-0.70)": int(np.sum((np.array(anomaly_scores) >= 0.45) & (np.array(anomaly_scores) < 0.70))),
            "high (0.70-0.85)": int(np.sum((np.array(anomaly_scores) >= 0.70) & (np.array(anomaly_scores) < 0.85))),
            "critical (0.85-1.0)": int(np.sum(np.array(anomaly_scores) >= 0.85))
        },
        "top_shifted_sensors": shifted_counts,
        "top_anomalous_windows": [
            {
                "window_id": r.get("window_end", "unknown"),
                "anomaly_score": r["anomaly_score"],
                "severity": r["severity"],
                "timestamp": r["timestamp"]
            } for r in sorted(results, key=lambda x: x["anomaly_score"], reverse=True)[:5]
        ],
        "current_system_health": health
    }

    # Write prediction files to both paths
    for p_dir in [pred_dir, root_pred_dir]:
        with open(p_dir / "prediction_summary.json", "w", encoding="utf-8") as f:
            json.dump(pred_summary, f, indent=2)
        with open(p_dir / "ot_dashboard.json", "w", encoding="utf-8") as f:
            json.dump(dashboard_metrics, f, indent=2)

    # 5. Generate performance_report.md
    perf_md = f"""# Performance Report (OT Specialist)

Documents processing throughput, memory utilization, and inference latency statistics.

## Throughput Statistics
- **Total Windows Benchmarked**: {total_windows}
- **Batch Inference Time**: {t_inf:.4f} seconds
- **Throughput (predictions/sec)**: {predictions_sec:.2f} predictions/second
- **Average Batch Latency/window**: {avg_inf_latency_ms:.4f} ms/window
- **Single Window Predict latency**: {predict_latency_ms:.4f} ms/window
- **Throughput (windows/sec)**: {windows_sec:.2f} windows/second

## Health & Status
- **Detector Health Status**: {health}
"""
    (reports_dir / "performance_report.md").write_text(perf_md, encoding="utf-8")
    logger.info("Performance report generated successfully.")

if __name__ == "__main__":
    main()
