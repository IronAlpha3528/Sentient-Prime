import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd

TEST_PATH = Path("data/processed/identity/test.parquet")
MODEL_DIR_V2_1 = Path("data/models/identity/v2_1")
MODEL_DIR_V2 = Path("data/models/identity/v2")
MODEL_DIR_V1 = Path("data/models/identity/v1")


def explain_anomaly_v2_1(row) -> list[str]:
    reasons = []
    
    # 1. New destination access ratio
    new_ratio = float(row.get("new_computer_ratio", 0.0))
    if new_ratio > 0.5:
        reasons.append(f"{new_ratio * 100:.1f}% of accessed computers are new for this user")
        
    # 2. Authentication volume deviation (using RAW z-score for exact reporting)
    auth_z = float(row.get("raw_auth_count_zscore", 0.0))
    if auth_z > 3.0:
        reasons.append(f"authentication volume is {auth_z:.1f} standard deviations above user baseline")
        
    # 3. Computer fanout deviation (using RAW z-score)
    comp_z = float(row.get("raw_unique_computers_zscore", 0.0))
    if comp_z > 3.0:
        reasons.append(f"computer traversal is {comp_z:.1f} standard deviations above user baseline")
        
    # 4. Off hours activity
    if int(row.get("off_hours_flag", 0)) == 1:
        reasons.append("activity occurred outside configured normal hours")
        
    # 5. Fast traversal
    fanout = float(row.get("fanout_rate", 0.0))
    if fanout > 10.0:
        reasons.append(f"high host traversal velocity: {fanout:.1f} computers/hour")

    # 6. Timing deviation (Task I6)
    gap_z = float(row.get("raw_mean_auth_gap_zscore", 0.0))
    if gap_z > 3.0:
        reasons.append(f"authentication timing gap is {gap_z:.1f} standard deviations above user baseline")
    elif gap_z < -3.0:
        reasons.append(f"authentication timing gap is {abs(gap_z):.1f} standard deviations below user baseline")

    # 7. Fanout rate deviation (Task I6)
    fanout_z = float(row.get("raw_fanout_rate_zscore", 0.0))
    if fanout_z > 3.0:
        reasons.append(f"host traversal velocity is {fanout_z:.1f} standard deviations above user baseline")
        
    return reasons


def main() -> None:
    if not TEST_PATH.exists():
        raise FileNotFoundError(f"Test split not found at: {TEST_PATH}")
    
    # Load v2.1 model and metadata
    model_path_v2_1 = MODEL_DIR_V2_1 / "identity_model.pkl"
    metadata_path_v2_1 = MODEL_DIR_V2_1 / "model_metadata.json"
    if not model_path_v2_1.exists() or not metadata_path_v2_1.exists():
        raise FileNotFoundError("Trained model or metadata file missing for identity v2.1.")

    model_v2_1 = joblib.load(model_path_v2_1)
    with open(metadata_path_v2_1, encoding="utf-8") as f:
        metadata_v2_1 = json.load(f)

    features_v2_1 = metadata_v2_1["feature_columns"]
    norm_params_v2_1 = metadata_v2_1["score_normalization_parameters"]
    min_raw_v2_1 = norm_params_v2_1["min_raw_score"]
    max_raw_v2_1 = norm_params_v2_1["max_raw_score"]

    print("Loading test dataset...")
    df = pd.read_parquet(TEST_PATH)

    # Run v2.1 inference
    df["raw_anomaly_score_v2_1"] = model_v2_1.decision_function(df[features_v2_1])
    df["suspiciousness_score_v2_1"] = np.clip(
        (max_raw_v2_1 - df["raw_anomaly_score_v2_1"]) / (max_raw_v2_1 - min_raw_v2_1),
        0.0,
        1.0
    )

    # Check if v2 model is available for comparisons
    v2_available = False
    model_path_v2 = MODEL_DIR_V2 / "identity_model.pkl"
    metadata_path_v2 = MODEL_DIR_V2 / "model_metadata.json"
    if model_path_v2.exists() and metadata_path_v2.exists():
        try:
            model_v2 = joblib.load(model_path_v2)
            with open(metadata_path_v2, encoding="utf-8") as f:
                meta_v2 = json.load(f)
            features_v2 = meta_v2["feature_columns"]
            norm_params_v2 = meta_v2["score_normalization_parameters"]
            min_raw_v2 = norm_params_v2["min_raw_score"]
            max_raw_v2 = norm_params_v2["max_raw_score"]
            
            # Predict using v2
            df["raw_anomaly_score_v2"] = model_v2.decision_function(df[features_v2])
            df["suspiciousness_score_v2"] = np.clip(
                (max_raw_v2 - df["raw_anomaly_score_v2"]) / (max_raw_v2 - min_raw_v2),
                0.0,
                1.0
            )
            v2_available = True
            print("Loaded Identity v2 model for comparison.")
        except Exception as e:
            print(f"Warning: Could not run v2 comparison: {e}")

    # ========================================================
    # SECTION 1: IDENTITY MODEL V2.1 TEST EVALUATION
    # ========================================================
    print("\n==================================================")
    print("IDENTITY MODEL V2.1 TEST EVALUATION")
    print("==================================================")
    print(f"Total test rows evaluated: {len(df)}")
    print(f"Test window_id range: {int(df['window_id'].min())} to {int(df['window_id'].max())}")
    print("-" * 50)
    print("Raw Anomaly Score Statistics (v2.1):")
    print(f"  Minimum: {df['raw_anomaly_score_v2_1'].min():.4f}")
    print(f"  Maximum: {df['raw_anomaly_score_v2_1'].max():.4f}")
    print(f"  Mean:    {df['raw_anomaly_score_v2_1'].mean():.4f}")
    print(f"  Median:  {df['raw_anomaly_score_v2_1'].median():.4f}")
    print(f"  Std Dev: {df['raw_anomaly_score_v2_1'].std():.4f}")
    print("-" * 50)
    print("Normalized Suspiciousness Statistics (v2.1):")
    print(f"  Minimum: {df['suspiciousness_score_v2_1'].min():.4f}")
    print(f"  Maximum: {df['suspiciousness_score_v2_1'].max():.4f}")
    print(f"  Mean:    {df['suspiciousness_score_v2_1'].mean():.4f}")
    print(f"  Median:  {df['suspiciousness_score_v2_1'].median():.4f}")
    print(f"  Std Dev: {df['suspiciousness_score_v2_1'].std():.4f}")
    print("\n[CONSERVATIVE NOTICE]")
    print("Isolation Forest anomalies represent behavioural deviations, not confirmed malicious attacks.")
    print("==================================================\n")

    # Show top 10 anomalous windows
    df_sorted = df.sort_values("raw_anomaly_score_v2_1")
    anomalous_rows = df_sorted.head(10)
    print("--- Top 10 Anomalous Windows (v2.1) ---")
    for idx, (_, row) in enumerate(anomalous_rows.iterrows()):
        reasons = explain_anomaly_v2_1(row)
        print(f"\nAnomaly #{idx + 1}:")
        print(f"  User: {row['user']} | Window ID: {row['window_id']}")
        print(f"  Auth Count: {row['auth_count']} (Raw Z-score: {row['raw_auth_count_zscore']:.2f} | Clipped: {row['auth_count_zscore']:.2f})")
        print(f"  Unique Computers: {row['unique_computers']} (Raw Z-score: {row['raw_unique_computers_zscore']:.2f} | Clipped: {row['unique_computers_zscore']:.2f})")
        print(f"  Computer Fanout Rate: {row['fanout_rate']:.2f} (Raw Z-score: {row['raw_fanout_rate_zscore']:.2f} | Clipped: {row['fanout_rate_zscore']:.2f})")
        print(f"  New Computers: {row['new_computer_count']} (Ratio: {row['new_computer_ratio']:.2f})")
        print(f"  Mean Auth Gap: {row['mean_auth_gap']:.2f} (Raw Z-score: {row['raw_mean_auth_gap_zscore']:.2f} | Clipped: {row['mean_auth_gap_zscore']:.2f} | Has Gap: {row['has_auth_gap']})")
        print(f"  Time details: Hour {row['hour_of_day']} | Off-Hours Flag: {row['off_hours_flag']}")
        print(f"  Scores: Raw IF Score: {row['raw_anomaly_score_v2_1']:.4f} | Normalized Suspiciousness Score: {row['suspiciousness_score_v2_1']:.4f}")
        print("  Detected Reasons:")
        if reasons:
            for r in reasons:
                print(f"    - {r}")
        else:
            print("    - None (flagged via complex multivariate anomaly interaction)")

    # ========================================================
    # SECTION 2: SERVICE/HIGH-VOLUME ACCOUNT ANALYSIS
    # ========================================================
    print("\n==================================================")
    print("SECTION 2: HIGH-VOLUME BASELINE-CONSISTENT ACCOUNTS")
    print("==================================================")
    
    cutoff_val = df["auth_count"].quantile(0.99)
    print(f"99th percentile of auth count: {cutoff_val:.1f}")

    service_candidates = df[
        (df["auth_count"] >= cutoff_val) &
        (df["auth_count_zscore"].abs() < 2) &
        (df["unique_computers_zscore"].abs() < 2) &
        (df["new_computer_ratio"] < 0.2)
    ].copy()

    print(f"Found {len(service_candidates)} matching baseline-consistent high-volume windows.")
    
    if len(service_candidates) > 0:
        median_susp_v2_1 = service_candidates["suspiciousness_score_v2_1"].median()
        print(f"Median v2.1 suspiciousness: {median_susp_v2_1:.4f}")
        
        if v2_available:
            median_susp_v2 = service_candidates["suspiciousness_score_v2"].median()
            print(f"Median v2 suspiciousness:   {median_susp_v2:.4f}")
            print(f"Suspiciousness difference (v2 -> v2.1): {median_susp_v2_1 - median_susp_v2:.4f}")
        else:
            print("v2 model is not available for comparison.")
    else:
        print("No high-volume baseline-consistent accounts found in test split.")
    print("==================================================\n")

    # ========================================================
    # SECTION 3: LOW-ACTIVITY ANOMALY DOMINANCE ANALYSIS (Task I8)
    # ========================================================
    print("==================================================")
    print("SECTION 3: LOW-ACTIVITY ANOMALY DOMINANCE ANALYSIS")
    print("==================================================")
    
    low_activity_mask = (
        (df["auth_count"] <= 2) &
        (df["unique_computers"] <= 2) &
        (df["new_computer_ratio"] == 0.0) &
        (df["off_hours_flag"] == 0)
    )
    low_count = low_activity_mask.sum()
    print(f"Total matching low-activity baseline-safe windows: {low_count}")
    
    if low_count > 0:
        low_df_v2_1 = df[low_activity_mask]
        print(f"Suspiciousness stats for low-activity windows (v2.1):")
        print(f"  Mean:   {low_df_v2_1['suspiciousness_score_v2_1'].mean():.4f}")
        print(f"  Median: {low_df_v2_1['suspiciousness_score_v2_1'].median():.4f}")
        print(f"  P90:    {np.percentile(low_df_v2_1['suspiciousness_score_v2_1'], 90):.4f}")
        print(f"  P95:    {np.percentile(low_df_v2_1['suspiciousness_score_v2_1'], 95):.4f}")
        print(f"  P99:    {np.percentile(low_df_v2_1['suspiciousness_score_v2_1'], 99):.4f}")
        
        # Count presence in top ranks
        top_10_low = len(df_sorted.head(10)[low_activity_mask.loc[df_sorted.head(10).index]])
        top_50_low = len(df_sorted.head(50)[low_activity_mask.loc[df_sorted.head(50).index]])
        top_100_low = len(df_sorted.head(100)[low_activity_mask.loc[df_sorted.head(100).index]])
        
        len_1pct = int(0.01 * len(df))
        top_1pct_low = len(df_sorted.head(len_1pct)[low_activity_mask.loc[df_sorted.head(len_1pct).index]])
        
        print(f"\nPresence of low-activity windows in v2.1 anomaly rankings:")
        print(f"  In Top 10:  {top_10_low}")
        print(f"  In Top 50:  {top_50_low}")
        print(f"  In Top 100: {top_100_low}")
        print(f"  In Top 1% ({len_1pct} rows): {top_1pct_low}")
        
        if v2_available:
            df_sorted_v2 = df.sort_values("raw_anomaly_score_v2")
            top_100_low_v2 = len(df_sorted_v2.head(100)[low_activity_mask.loc[df_sorted_v2.head(100).index]])
            median_susp_v2_low = df[low_activity_mask]["suspiciousness_score_v2"].median()
            print(f"\nComparison with v2:")
            print(f"  v2 Median Suspiciousness:   {median_susp_v2_low:.4f}")
            print(f"  v2.1 Median Suspiciousness: {low_df_v2_1['suspiciousness_score_v2_1'].median():.4f}")
            print(f"  v2 Top-100 low-activity count:   {top_100_low_v2}")
            print(f"  v2.1 Top-100 low-activity count: {top_100_low}")
            
        print("\nHighest-scoring low-activity baseline-safe windows in v2.1:")
        top_low_rows = low_df_v2_1.sort_values("raw_anomaly_score_v2_1").head(10)
        for i, (_, row) in enumerate(top_low_rows.iterrows()):
            print(f"  #{i+1}: User {row['user']} | window_id {row['window_id']} | suspiciousness {row['suspiciousness_score_v2_1']:.4f}")
    else:
        print("No low-activity baseline-safe windows found in test set.")
    print("==================================================\n")

    # ========================================================
    # SECTION 4: CYBER-RELEVANT BEHAVIOURAL DEVIATION ANALYSIS (Task I9)
    # ========================================================
    print("==================================================")
    print("SECTION 4: CYBER-RELEVANT BEHAVIOURAL DEVIATION ANALYSIS")
    print("==================================================")
    
    deviation_mask = (
        (df["raw_auth_count_zscore"] >= 5.0) |
        (df["raw_unique_computers_zscore"] >= 5.0) |
        (df["raw_fanout_rate_zscore"] >= 5.0) |
        ((df["new_computer_ratio"] >= 0.50) & (df["unique_computers"] >= 5)) |
        ((df["off_hours_flag"] == 1) & (df["new_computer_ratio"] >= 0.50))
    )
    dev_count = deviation_mask.sum()
    print(f"Total matching strong behavioural-deviation candidates: {dev_count}")
    
    if dev_count > 0:
        dev_df = df[deviation_mask]
        print(f"Suspiciousness stats for deviation candidates (v2.1):")
        print(f"  Mean:   {dev_df['suspiciousness_score_v2_1'].mean():.4f}")
        print(f"  Median: {dev_df['suspiciousness_score_v2_1'].median():.4f}")
        print(f"  P90:    {np.percentile(dev_df['suspiciousness_score_v2_1'], 90):.4f}")
        
        # Rankings checks
        total_len = len(df)
        top_10pct_cnt = len(df_sorted.head(int(0.10 * total_len))[deviation_mask.loc[df_sorted.head(int(0.10 * total_len)).index]])
        top_5pct_cnt = len(df_sorted.head(int(0.05 * total_len))[deviation_mask.loc[df_sorted.head(int(0.05 * total_len)).index]])
        top_1pct_cnt = len(df_sorted.head(int(0.01 * total_len))[deviation_mask.loc[df_sorted.head(int(0.01 * total_len)).index]])
        
        print(f"\nPercentage of deviation candidates falling in v2.1 top rankings:")
        print(f"  In Top 10%: {top_10pct_cnt / dev_count * 100.0:.2f}%")
        print(f"  In Top 5%:  {top_5pct_cnt / dev_count * 100.0:.2f}%")
        print(f"  In Top 1%:  {top_1pct_cnt / dev_count * 100.0:.2f}%")
        
        # Count presence in absolute counts
        top_10_dev = len(df_sorted.head(10)[deviation_mask.loc[df_sorted.head(10).index]])
        top_50_dev = len(df_sorted.head(50)[deviation_mask.loc[df_sorted.head(50).index]])
        top_100_dev = len(df_sorted.head(100)[deviation_mask.loc[df_sorted.head(100).index]])
        
        print(f"\nPresence of deviation candidates in absolute v2.1 rankings:")
        print(f"  In Top 10:  {top_10_dev}")
        print(f"  In Top 50:  {top_50_dev}")
        print(f"  In Top 100: {top_100_dev}")
        
        print("\nHighest-ranked strong behavioural-deviation candidates in v2.1:")
        top_dev_rows = dev_df.sort_values("raw_anomaly_score_v2_1").head(20)
        for i, (_, row) in enumerate(top_dev_rows.iterrows()):
            print(f"  #{i+1}: User {row['user']} | window_id {row['window_id']} | suspiciousness {row['suspiciousness_score_v2_1']:.4f} | auth_count {row['auth_count']} | unique_comp {row['unique_computers']} | new_comp_ratio {row['new_computer_ratio']:.2f}")
            reasons = explain_anomaly_v2_1(row)
            for r in reasons[:3]:
                print(f"    - {r}")
    else:
        print("No strong behavioural-deviation candidates found in test set.")
    print("==================================================\n")

    # ========================================================
    # SECTION 5: RANKING COMPARISON (Task I10)
    # ========================================================
    print("==================================================")
    print("SECTION 5: FINAL IDENTITY RANKING COMPARISON")
    print("==================================================")
    
    median_susp_low = df[low_activity_mask]["suspiciousness_score_v2_1"].median() if low_count > 0 else 0.0
    top_100_low_cnt = len(df_sorted.head(100)[low_activity_mask.loc[df_sorted.head(100).index]]) if low_count > 0 else 0
    
    median_susp_dev = df[deviation_mask]["suspiciousness_score_v2_1"].median() if dev_count > 0 else 0.0
    top_100_dev_cnt = len(df_sorted.head(100)[deviation_mask.loc[df_sorted.head(100).index]]) if dev_count > 0 else 0

    print("LOW-ACTIVITY BASELINE-SAFE WINDOWS")
    print(f"  Count: {low_count}")
    print(f"  Median suspiciousness: {median_susp_low:.4f}")
    print(f"  Top-100 count: {top_100_low_cnt}")
    
    print("\nSTRONG BEHAVIOURAL-DEVIATION CANDIDATES")
    print(f"  Count: {dev_count}")
    print(f"  Median suspiciousness: {median_susp_dev:.4f}")
    print(f"  Top-100 count: {top_100_dev_cnt}")
    print("-" * 50)
    
    if median_susp_dev > median_susp_low and top_100_dev_cnt >= top_100_low_cnt:
        print("\nConclusion:")
        print("Identity v2.1 ranks strong user-relative behavioural deviations above low-activity baseline-safe windows.")
    else:
        print("\nConclusion:")
        print("Identity v2.1 still exhibits anomaly-ranking distortion and requires further feature analysis.")
    print("==================================================\n")

    # ========================================================
    # SECTION 6: RED TEAM GROUND TRUTH
    # ========================================================
    print("LANL red-team ground truth was not available in the local dataset directory. Current Identity evaluation measures behavioural deviation quality rather than confirmed attack detection.")


if __name__ == "__main__":
    main()
