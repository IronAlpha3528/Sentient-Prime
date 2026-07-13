import os
import json
import csv
import sys
from pathlib import Path
import zipfile
import pandas as pd
import numpy as np

HAI_ZIP = Path("data/raw/HAI/archive (1).zip")
OUT_DIR = Path("data/processed/ot_ics/inspection")

def main() -> None:
    if not HAI_ZIP.exists():
        print(f"Error: HAI zip archive not found at: {HAI_ZIP}", file=sys.stderr)
        sys.exit(1)

    print(f"Inspecting HAI OT/ICS dataset from zip: {HAI_ZIP}")
    out_dir = Path("data/processed/ot_ics/inspection")
    out_dir.mkdir(parents=True, exist_ok=True)

    manifests = []
    global_schema_classifications = {}
    
    # We sample a portion of each CSV file for speed and memory efficiency (Task H1)
    N_ROWS_TO_INSPECT = 10000

    # Open ZIP archive (Task H1)
    with zipfile.ZipFile(HAI_ZIP, "r") as z_file:
        members = z_file.infolist()
        csv_members = [m for m in members if m.filename.endswith(".csv")]
        print(f"Found {len(csv_members)} CSV data files inside the ZIP archive.")

        for idx, m in enumerate(csv_members):
            print(f"Processing ({idx+1}/{len(csv_members)}): {m.filename}")
            file_manifest = {
                "file_name": Path(m.filename).name,
                "file_path": f"{HAI_ZIP}!{m.filename}",
                "relative_path": m.filename,
                "file_type": "csv",
                "file_size_bytes": m.file_size,
                "read_success": False,
                "read_error": "",
                "row_count": 0,
                "column_count": 0,
                "column_names": [],
                "detected_timestamp_column": "",
                "earliest_timestamp": None,
                "latest_timestamp": None,
                "detected_label_columns": [],
                "label_values": {},
                "missing_value_summary": {},
                "numeric_column_count": 0,
                "categorical_column_count": 0,
                "constant_column_count": 0,
                "near_constant_column_count": 0,
                "duplicate_timestamp_count": 0,
                "sampling_interval_estimate": 0.0,
                "sampling_interval_variability": 0.0
            }

            try:
                # Read header and first chunk incrementally using pandas (Task H1)
                with z_file.open(m.filename) as f:
                    # Estimate row count by looking at first chunk or file size, or read sampled chunk
                    df_chunk = pd.read_csv(f, nrows=N_ROWS_TO_INSPECT)
                    
                if len(df_chunk) == 0:
                    file_manifest["read_success"] = True
                    manifests.append(file_manifest)
                    continue

                file_manifest["row_count"] = len(df_chunk)
                file_manifest["column_count"] = len(df_chunk.columns)
                file_manifest["column_names"] = list(df_chunk.columns)

                # Column counts
                num_cols = df_chunk.select_dtypes(include=[np.number]).columns
                cat_cols = df_chunk.select_dtypes(exclude=[np.number]).columns
                file_manifest["numeric_column_count"] = len(num_cols)
                file_manifest["categorical_column_count"] = len(cat_cols)

                # Find timestamp column
                ts_col = ""
                for col in df_chunk.columns:
                    if col.lower() in ["timestamp", "time", "date"]:
                        ts_col = col
                        break
                if not ts_col and len(cat_cols) > 0:
                    ts_col = cat_cols[0] # Default fallback to first categorical column
                
                file_manifest["detected_timestamp_column"] = ts_col
                
                if ts_col in df_chunk.columns:
                    file_manifest["earliest_timestamp"] = str(df_chunk[ts_col].iloc[0])
                    file_manifest["latest_timestamp"] = str(df_chunk[ts_col].iloc[-1])
                    
                    # Duplicate timestamp count (Task H2)
                    file_manifest["duplicate_timestamp_count"] = int(df_chunk[ts_col].duplicated().sum())
                    
                    # Sampling interval estimate (Task H2)
                    try:
                        ts_series = pd.to_datetime(df_chunk[ts_col], format="ISO8601", errors="coerce")
                        intervals = ts_series.diff().dropna().dt.total_seconds()
                        if len(intervals) > 0:
                            file_manifest["sampling_interval_estimate"] = float(intervals.median())
                            file_manifest["sampling_interval_variability"] = float(intervals.std())
                    except Exception:
                        pass

                # Find labels (Task H4)
                lbl_cols = []
                for col in df_chunk.columns:
                    if col.lower() in ["attack", "label", "anomaly"] or col.lower().startswith("attack_"):
                        lbl_cols.append(col)
                        
                file_manifest["detected_label_columns"] = lbl_cols
                
                for col in lbl_cols:
                    counts = df_chunk[col].value_counts().to_dict()
                    file_manifest["label_values"][col] = {str(k): int(v) for k, v in counts.items()}

                # Missing values count (Task H2)
                missing = df_chunk.isnull().sum().to_dict()
                file_manifest["missing_value_summary"] = {k: int(v) for k, v in missing.items() if v > 0}

                # Constant and near-constant columns
                const_count = 0
                near_const_count = 0
                for col in num_cols:
                    if df_chunk[col].nunique() <= 1:
                        const_count += 1
                    elif df_chunk[col].nunique() <= 5:
                        near_const_count += 1
                        
                file_manifest["constant_column_count"] = const_count
                file_manifest["near_constant_column_count"] = near_const_count
                file_manifest["read_success"] = True

                # Dynamic tag schema analysis on the first found valid CSV (Task H3)
                if not global_schema_classifications and len(num_cols) > 20:
                    for col in df_chunk.columns:
                        col_lower = col.lower()
                        if col == ts_col:
                            classification = "TIMESTAMP"
                            confidence = "high"
                            reason = "Explicit timestamp column containing ordered temporal strings"
                        elif col in lbl_cols:
                            classification = "ATTACK_LABEL"
                            confidence = "high"
                            reason = "Binary or categorical label column marking attack execution periods"
                        elif col_lower.endswith("d") or col_lower.endswith("z") or "val" in col_lower or "autosd" in col_lower:
                            classification = "ACTUATOR_CONTROL_STATE"
                            confidence = "medium"
                            reason = "Suffix suggests discrete control command or valve actuator position"
                        elif "sp" in col_lower:
                            classification = "SETPOINT"
                            confidence = "medium"
                            reason = "Name indicates control-loop reference setpoint"
                        elif "lamp" in col_lower or "onoff" in col_lower:
                            classification = "STATUS_MODE"
                            confidence = "medium"
                            reason = "Suffix or name indicates binary status/mode display indicator"
                        elif col in num_cols:
                            classification = "SENSOR_PROCESS_VALUE"
                            confidence = "medium"
                            reason = "Continuous numeric variable measuring process state variables"
                        else:
                            classification = "UNKNOWN"
                            confidence = "low"
                            reason = "Unresolved type or format"
                            
                        global_schema_classifications[col] = {
                            "classification": classification,
                            "confidence": confidence,
                            "reason": reason
                        }

            except Exception as e:
                file_manifest["read_success"] = False
                file_manifest["read_error"] = str(e)
                print(f"Error inspecting file {m.filename}: {e}")

            manifests.append(file_manifest)

    # 1. Classification of train/test temporal candidates (Task H5)
    train_candidates = []
    test_candidates = []
    unknown_files = []
    for m in manifests:
        rel_path = m["relative_path"]
        if "train" in rel_path.lower():
            train_candidates.append(rel_path)
        elif "test" in rel_path.lower():
            test_candidates.append(rel_path)
        else:
            unknown_files.append(rel_path)

    print("\n--- Running Time-Series Temporal Regularity Analysis ---")
    rep_test_file = "hai-22.04/test1.csv"
    rep_df = None
    with zipfile.ZipFile(HAI_ZIP, "r") as z_file:
        if rep_test_file in z_file.namelist():
            with z_file.open(rep_test_file) as f:
                rep_df = pd.read_csv(f)  # Load fully for statistics and distribution shift

    sampling_type = "irregular"
    dominant_interval = 1.0
    if rep_df is not None and "timestamp" in rep_df.columns:
        ts_series = pd.to_datetime(rep_df["timestamp"], format="ISO8601", errors="coerce")
        diffs = ts_series.diff().dropna().dt.total_seconds()
        median_diff = float(diffs.median())
        std_diff = float(diffs.std())
        dominant_interval = median_diff
        if std_diff < 0.01:
            sampling_type = "fixed interval"
        else:
            sampling_type = "variable interval"
            
        print(f"Representative file: {rep_test_file}")
        print(f"  Total inspected rows: {len(rep_df)}")
        print(f"  Duplicates detected:  {rep_df['timestamp'].duplicated().sum()}")
        print(f"  Median sampling gap:  {median_diff:.2f} seconds")
        print(f"  Sampling variability: {std_diff:.4f} seconds ({sampling_type})")
    else:
        print("Representative time-series data could not be parsed.")

    # 3. Sensor Statistics (Task H7)
    sensor_stats = []
    if rep_df is not None:
        num_cols = rep_df.select_dtypes(include=[np.number]).columns
        # Exclude Attack label from sensor stats if present
        sensor_cols = [c for c in num_cols if c.lower() != "attack"]
        
        for col in sensor_cols:
            series = rep_df[col].dropna()
            if len(series) == 0:
                continue
            
            stats_record = {
                "column": col,
                "count": len(series),
                "missing_count": int(rep_df[col].isnull().sum()),
                "mean": float(series.mean()),
                "std": float(series.std()),
                "min": float(series.min()),
                "p1": float(np.percentile(series, 1)),
                "p5": float(np.percentile(series, 5)),
                "p25": float(np.percentile(series, 25)),
                "median": float(series.median()),
                "p75": float(np.percentile(series, 75)),
                "p95": float(np.percentile(series, 95)),
                "p99": float(np.percentile(series, 99)),
                "max": float(series.max()),
                "unique_count": int(series.nunique())
            }
            stats_record["constant_flag"] = 1 if stats_record["unique_count"] <= 1 else 0
            stats_record["near_constant_flag"] = 1 if stats_record["unique_count"] <= 5 and stats_record["unique_count"] > 1 else 0
            sensor_stats.append(stats_record)

    # 4. Attack vs Normal Distribution Shifts (Task H8)
    distribution_shifts = []
    if rep_df is not None and "Attack" in rep_df.columns:
        attack_mask = (rep_df["Attack"] == 1)
        normal_mask = (rep_df["Attack"] == 0)
        
        attack_count = attack_mask.sum()
        normal_count = normal_mask.sum()
        print(f"\nLabel distribution in sample ({len(rep_df)} rows):")
        print(f"  Normal rows: {normal_count} ({normal_count / len(rep_df) * 100.0:.2f}%)")
        print(f"  Attack rows: {attack_count} ({attack_count / len(rep_df) * 100.0:.2f}%)")

        if attack_count > 0 and normal_count > 0:
            num_cols = rep_df.select_dtypes(include=[np.number]).columns
            sensor_cols = [c for c in num_cols if c.lower() != "attack"]
            
            for col in sensor_cols:
                att_series = rep_df[attack_mask][col].dropna()
                norm_series = rep_df[normal_mask][col].dropna()
                
                if len(att_series) > 0 and len(norm_series) > 0:
                    att_mean = att_series.mean()
                    norm_mean = norm_series.mean()
                    norm_std = norm_series.std()
                    
                    mean_shift = abs(att_mean - norm_mean)
                    norm_shift = mean_shift / (norm_std + 1e-6)
                    std_ratio = att_series.std() / (norm_std + 1e-6)
                    
                    distribution_shifts.append({
                        "column": col,
                        "mean_normal": float(norm_mean),
                        "mean_attack": float(att_mean),
                        "std_normal": float(norm_std),
                        "std_attack": float(att_series.std()),
                        "absolute_mean_shift": float(mean_shift),
                        "normalized_mean_shift": float(norm_shift),
                        "std_ratio": float(std_ratio)
                    })
            
            # Rank top 30 distribution shift variables
            distribution_shifts = sorted(distribution_shifts, key=lambda x: x["normalized_mean_shift"], reverse=True)
            print("\nTop 15 variables showing strongest exploratory distribution shift:")
            for idx, item in enumerate(distribution_shifts[:15]):
                print(f"  #{idx+1:<2} | {item['column']:<12} | Mean Shift: {item['absolute_mean_shift']:.4f} | Normalized Shift: {item['normalized_mean_shift']:.4f}")

    # 5. Lag and Multivariate Relationships (Task H9)
    relationships = []
    if rep_df is not None:
        # Compute correlation on process variables
        num_cols = rep_df.select_dtypes(include=[np.number]).columns
        proc_cols = [c for c in num_cols if c.lower() != "attack"][:30] # Limit to 30 columns for memory limits
        corr_matrix = rep_df[proc_cols].corr().abs()
        
        # Extract highly correlated pairs
        pairs = []
        for i in range(len(proc_cols)):
            for j in range(i + 1, len(proc_cols)):
                c = corr_matrix.iloc[i, j]
                if c >= 0.85:
                    pairs.append((proc_cols[i], proc_cols[j], c))
                    
        pairs = sorted(pairs, key=lambda x: x[2], reverse=True)
        print("\nStrong process relationships observed:")
        for idx, (col1, col2, score) in enumerate(pairs[:10]):
            relationships.append({
                "variable_1": col1,
                "variable_2": col2,
                "correlation": float(score)
            })
            print(f"  Pair: ({col1}, {col2}) | Correlation: {score:.4f}")

    # 6. Windowing Feasibility Analysis (Task H10)
    # sampling interval = 1 second
    candidate_lengths = [10, 30, 60, 120, 300]
    window_evals = []
    for length in candidate_lengths:
        duration_desc = f"{length} seconds"
        # Estimate windows count
        total_w = len(rep_df) - length + 1 if rep_df is not None else 0
        memory_est = f"{(length * 88 * 8) / 1024:.2f} KB per window"
        window_evals.append({
            "window_size_samples": length,
            "real_time_duration": duration_desc,
            "sample_windows_count": total_w,
            "estimated_memory": memory_est
        })
    
    # Recommend window size
    recommended_window = 60
    rec_window_reason = "A 60-sample (1-minute) window captures temporal context without consuming excess memory, making it ideal for low-compute models."

    # 7. Model recommendation (Task H11)
    model_comparison = {
        "low_compute": {
            "model_type": "Isolation Forest on rolling statistical window features",
            "suitability": "High",
            "computational_cost": "Very Low",
            "explainability": "High"
        },
        "medium_compute": {
            "model_type": "Small Temporal Convolutional Network (TCN) Autoencoder",
            "suitability": "Medium-High",
            "computational_cost": "Medium",
            "explainability": "Medium"
        }
    }

    # 8. Feature Candidate Report (Task H12)
    feature_candidates = {
        "rolling_features": [
            "current_value", "rolling_mean", "rolling_std", "rolling_min",
            "rolling_max", "rolling_range", "first_difference", "rate_of_change"
        ],
        "actuator_state_features": [
            "state", "state_change_flag", "state_change_count", "time_in_current_state"
        ],
        "multivariate_features": [
            "cross_variable_correlation_deviation", "residual_from_related_variable"
        ]
    }

    # 9. Output reports to directories (Task H13)
    # Save manifests and reports
    with open(out_dir / "hai_file_manifest.json", "w", encoding="utf-8") as f:
        json.dump(manifests, f, indent=2)

    with open(out_dir / "hai_file_manifest.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["file_name", "relative_path", "file_size_bytes", "row_count", "column_count", "timestamp_col", "label_cols", "read_success"])
        for m in manifests:
            writer.writerow([
                m["file_name"],
                m["relative_path"],
                m["file_size_bytes"],
                m["row_count"],
                m["column_count"],
                m["detected_timestamp_column"],
                ",".join(m["detected_label_columns"]),
                m["read_success"]
            ])

    with open(out_dir / "hai_schema_report.json", "w", encoding="utf-8") as f:
        json.dump(global_schema_classifications, f, indent=2)

    # Label report
    labels_dict = {}
    for m in manifests:
        if m["detected_label_columns"]:
            labels_dict[m["relative_path"]] = m["label_values"]
    with open(out_dir / "hai_label_report.json", "w", encoding="utf-8") as f:
        json.dump(labels_dict, f, indent=2)

    # Temporal report
    temporal_report = {
        "dominant_sampling_interval_seconds": dominant_interval,
        "sampling_regularity_classification": sampling_type,
        "duplicate_timestamps_found": int(rep_df["timestamp"].duplicated().sum()) if rep_df is not None else 0
    }
    with open(out_dir / "hai_temporal_report.json", "w", encoding="utf-8") as f:
        json.dump(temporal_report, f, indent=2)

    # Sensor statistics
    if sensor_stats:
        pd.DataFrame(sensor_stats).to_csv(out_dir / "hai_sensor_statistics.csv", index=False)

    # Distribution shift report
    if distribution_shifts:
        pd.DataFrame(distribution_shifts).to_csv(out_dir / "hai_distribution_shift_report.csv", index=False)

    with open(out_dir / "hai_relationship_report.json", "w", encoding="utf-8") as f:
        json.dump(relationships, f, indent=2)

    with open(out_dir / "hai_window_recommendation.json", "w", encoding="utf-8") as f:
        json.dump({
            "window_evaluations": window_evals,
            "recommended_window_size": recommended_window,
            "reasoning": rec_window_reason
        }, f, indent=2)

    with open(out_dir / "hai_model_recommendation.json", "w", encoding="utf-8") as f:
        json.dump(model_comparison, f, indent=2)

    with open(out_dir / "hai_feature_candidate_report.json", "w", encoding="utf-8") as f:
        json.dump(feature_candidates, f, indent=2)

    # Save summary report
    active_lbl = lbl_cols[0] if lbl_cols else "None"
    total_process_vars = len(proc_cols) if rep_df is not None else 0
    
    summary_md = f"""# HAI OT/ICS Dataset Inspection Summary

This report documents the findings from inspecting the local HAI OT/ICS time-series dataset.

## File Manifest Summary
- **Total discovered CSV files**: {len(csv_members)}
- **Training file candidates**: {len(train_candidates)} ({", ".join(train_candidates[:3])}...)
- **Test/Attack file candidates**: {len(test_candidates)} ({", ".join(test_candidates[:3])}...)
- **Timestamp field**: {ts_col}
- **Labels detected**: {", ".join(lbl_cols)}

## Data & Temporal Characteristics
- **Dominant sampling interval**: {dominant_interval:.2f} seconds
- **Sampling regularity**: {sampling_type}
- **Number of process variables**: {total_process_vars}
- **Constant columns**: {const_count}
- **Near-constant columns**: {near_const_count}

## Ground-Truth & Window recommendations
- **Label column used**: {active_lbl}
- **Label distribution**: {normal_count} normal vs {attack_count} attack rows
- **Recommended Window Length**: {recommended_window} samples (approx. {recommended_window} seconds)
- **Recommended Low-Compute Model**: Isolation Forest or LightGBM on rolling statistical window features.
- **Recommended Medium-Compute Model**: Small Temporal Convolutional Network (TCN) Autoencoder to learn cross-sensor correlation states.

## Dataset Limitations
1. Highly imbalanced labels (attack records form a small percentage of test logs).
2. The exact mapping between sensor tags and physical components (e.g. valve names, turbine states) requires external mapping registers.
"""
    (out_dir / "hai_inspection_summary.md").write_text(summary_md, encoding="utf-8")
    print(f"Saved inspection reports to: {out_dir}")


if __name__ == "__main__":
    main()
