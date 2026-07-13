import os
import sys
import yaml
import json
import logging
from pathlib import Path
import pandas as pd

# Ensure project root is in path if executing directly
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from detectors.ot.dataset_discovery import discover_ot_datasets
from detectors.ot.hai_loader import load_ot_dataset_incremental
from detectors.ot.timeseries_normalizer import TimeseriesNormalizer
from detectors.ot.window_builder import build_sliding_windows
from detectors.ot.feature_builder import build_features_for_window
from detectors.ot.feature_contract import generate_feature_contract

logger = logging.getLogger(__name__)

def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    logger.info("Starting OT Specialist preprocessing pipeline...")

    # 1. Load Configuration
    config_path = Path("config/ot.yaml")
    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}
    else:
        config = {}

    window_length = config.get("window_length", 60)
    stride = config.get("stride", 10)
    raw_dir = config.get("raw_directory", "data/raw/HAI")
    
    # Outputs Directories
    proc_dir = Path("data/processed/ot")
    norm_dir = proc_dir / "normalized"
    wind_dir = proc_dir / "windows"
    feat_dir = proc_dir / "features"
    meta_dir = proc_dir / "metadata"

    for d in [norm_dir, wind_dir, feat_dir, meta_dir]:
        d.mkdir(parents=True, exist_ok=True)

    # 2. Discover Datasets
    manifests = discover_ot_datasets(raw_dir)
    if not manifests:
        logger.error(f"No OT datasets found in raw directory {raw_dir}")
        sys.exit(1)

    # We will pick the first train file inside the ZIP or flat CSV to process
    # Typical names inside zip: hai-21.03/train1.csv
    train_manifest = None
    for m in manifests:
        if "train" in m.relative_path.lower():
            train_manifest = m
            break
            
    if not train_manifest:
        train_manifest = manifests[0]

    logger.info(f"Selected manifest for processing: {train_manifest.relative_path} (estimated {train_manifest.row_estimate} rows)")

    # 3. Load & Normalize in Chunks
    # To keep memory footprint low and runs fast (under 30s), we process up to 60,000 rows
    max_rows = 60000
    rows_loaded = 0
    chunks = []
    
    normalizer = TimeseriesNormalizer(
        timestamp_col=train_manifest.timestamp_column or "timestamp",
        label_col=train_manifest.label_column or "attack"
    )

    try:
        loader = load_ot_dataset_incremental(
            file_path=train_manifest.file_path,
            chunk_size=20000,
            timestamp_col=train_manifest.timestamp_column
        )
        for chunk_df in loader:
            chunks.append(chunk_df)
            rows_loaded += len(chunk_df)
            if rows_loaded >= max_rows:
                logger.info(f"Reached processing limit of {max_rows} rows.")
                break
    except Exception as e:
        logger.error(f"Failed to stream incremental dataset: {e}")
        sys.exit(1)

    if not chunks:
        logger.error("No data chunks loaded.")
        sys.exit(1)

    full_df = pd.concat(chunks, ignore_index=True)
    logger.info(f"Loaded total of {len(full_df)} rows. Normalizing time-series...")

    # Fit and normalize
    normalized_df = normalizer.fit_normalize(full_df)
    
    # Save normalized timeseries to parquet
    normalized_parquet_path = norm_dir / "normalized_timeseries.parquet"
    normalized_df.to_parquet(normalized_parquet_path, index=False)
    logger.info(f"Saved normalized timeseries to {normalized_parquet_path}")

    # 4. Sliding Windows Generation & Feature Building
    window_generator = build_sliding_windows(
        normalized_df,
        window_length=window_length,
        stride=stride
    )

    windows_meta = []
    features_list = []

    for win_item in window_generator:
        meta = win_item["metadata"]
        # Convert meta object to dict
        meta_dict = {
            "window_id": meta.window_id,
            "start_time": meta.start_time,
            "end_time": meta.end_time,
            "host": meta.host,
            "label": meta.label,
            "duration_seconds": meta.duration_seconds,
            "row_count": meta.row_count,
            "attack_ratio": meta.attack_ratio
        }
        windows_meta.append(meta_dict)
        
        # Build features
        feats = build_features_for_window(win_item)
        features_list.append(feats)

    # Save Windows Metadata Parquet
    windows_df = pd.DataFrame(windows_meta)
    windows_parquet_path = wind_dir / "windows.parquet"
    windows_df.to_parquet(windows_parquet_path, index=False)
    logger.info(f"Generated {len(windows_df)} windows. Saved metadata to {windows_parquet_path}")

    # Save Features Parquet
    features_df = pd.DataFrame(features_list)
    features_parquet_path = feat_dir / "ot_features.parquet"
    features_df.to_parquet(features_parquet_path, index=False)
    logger.info(f"Extracted {features_df.shape[1]} features. Saved features dataset to {features_parquet_path}")

    # 5. Generate and Save Reports & Contracts
    # Generate Feature Contract
    if features_list:
        generate_feature_contract(features_list[0], meta_dir / "feature_contract.json")

    # Save reports
    with open(meta_dir / "sampling_report.json", "w", encoding="utf-8") as f:
        json.dump(normalizer.temporal_report, f, indent=2)

    with open(meta_dir / "sensor_classification.json", "w", encoding="utf-8") as f:
        json.dump(normalizer.classification, f, indent=2)

    with open(meta_dir / "missing_value_report.json", "w", encoding="utf-8") as f:
        json.dump(normalizer.missing_report, f, indent=2)

    # Count variables categories
    counts = {"Sensor": 0, "Actuator": 0, "Controller": 0, "Status": 0, "Label": 0, "Timestamp": 0, "Unknown": 0}
    for col, group in normalizer.classification.items():
        counts[group] = counts.get(group, 0) + 1

    # Generate Preprocessing Summary MD
    summary_md = f"""# Preprocessing Summary Report (OT Specialist)

This report details the execution and metadata of the OT/ICS preprocessing pipeline.

## Dataset Statistics
- **Source File**: {train_manifest.relative_path}
- **Rows Processed**: {len(full_df)}
- **Window Size**: {window_length} samples
- **Window Stride**: {stride} samples
- **Window Count**: {len(windows_df)} windows
- **Feature Count**: {features_df.shape[1] - 6} engineered features (excluding window metadata)
- **Output Dataset Shape**: {features_df.shape}

## Column Classification
- **Sensors**: {counts['Sensor']}
- **Actuators**: {counts['Actuator']}
- **Controllers**: {counts['Controller']}
- **Status Flags**: {counts['Status']}
- **Timestamp / Label**: {counts['Timestamp']} / {counts['Label']}

## Temporal Integrity Check
- **Monotonic**: {normalizer.temporal_report.get('is_monotonic')}
- **Estimated Sampling Interval**: {normalizer.temporal_report.get('sampling_interval_seconds')} seconds
- **Duplicate Timestamps**: {normalizer.temporal_report.get('duplicate_count')}
- **Gap Count**: {normalizer.temporal_report.get('gap_count')}
- **Estimated Missing Timestamps**: {normalizer.temporal_report.get('missing_count')}

## Missing Value Diagnostics
- Preprocessed columns successfully loaded. 
- Details stored under `missing_value_report.json`.
"""
    (meta_dir / "preprocessing_summary.md").write_text(summary_md, encoding="utf-8")
    logger.info("OT Preprocessing completed successfully.")

if __name__ == "__main__":
    main()
