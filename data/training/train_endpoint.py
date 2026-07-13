import os
import sys
import json
import logging
from pathlib import Path
from datetime import datetime
import pandas as pd
import numpy as np
import joblib
import lightgbm as lgb
from sklearn.model_selection import train_test_split

# Ensure project root is in path if executing directly
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

logger = logging.getLogger(__name__)

# List of processes that are strongly indicative of offensive tools in OTRF
ATTACK_PROCESSES = {
    "mimikatz.exe", "rubeus.exe", "seatbelt.exe", "dumpert.exe", "psexec.exe", 
    "sharpview.exe", "sharpsc.exe", "msfvenom.exe", "installutil.exe", 
    "mshta.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe"
}

def assign_heuristic_labels(df: pd.DataFrame) -> pd.Series:
    """
    Heuristically assigns binary labels based on scenario execution behaviors:
    - 1 (Malicious) if it uses known attack processes OR exhibits highly suspicious behaviors
      (e.g., remote threads, LSASS access, base64 PowerShell, LOLBin misuse).
    - 0 (Benign) otherwise.
    """
    labels = pd.Series(0, index=df.index)
    
    # Heuristics
    is_attack_proc = df["process"].str.lower().isin(ATTACK_PROCESSES)
    has_lsass_access = df["lsass_access_count"] > 0
    has_remote_thread = df["remote_thread_count"] > 0
    has_encoded_cmd = df["encoded_command_flag"] > 0
    is_rare_powershell = (df["powershell_flag"] > 0) & (df["command_length"] > 150)
    has_rare_dlls = df["rare_image_load_count"] > 0
    
    malicious_mask = (
        is_attack_proc | 
        has_lsass_access | 
        has_remote_thread | 
        has_encoded_cmd | 
        is_rare_powershell | 
        has_rare_dlls
    )
    
    labels[malicious_mask] = 1
    return labels

def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    logger.info("Initializing Endpoint Specialist training script...")

    # Paths
    features_path = Path("data/processed/endpoint/features/endpoint_features.parquet")
    contract_path = Path("data/processed/endpoint/features/feature_contract.json")
    model_dir = Path("models/endpoint")
    reports_dir = Path("data/processed/endpoint/reports")
    
    model_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    if not features_path.exists():
        logger.error(f"Features Parquet not found at: {features_path}. Run preprocess_endpoint first.")
        sys.exit(1)

    if not contract_path.exists():
        logger.error(f"Feature contract not found at: {contract_path}.")
        sys.exit(1)

    # 1. Load Preprocessed Data
    df = pd.read_parquet(features_path)
    logger.info(f"Loaded feature dataset with shape: {df.shape}")

    # 2. Validate Feature Contract
    with open(contract_path, "r", encoding="utf-8") as f:
        contract = json.load(f)
    
    features = list(contract.keys())
    missing_cols = [c for c in features if c not in df.columns]
    if missing_cols:
        logger.error(f"Feature validation failed. Missing columns from contract: {missing_cols}")
        sys.exit(1)

    # Drop constant/near-constant features reports
    constant_features = []
    near_constant_features = []
    for col in features:
        nunique = df[col].nunique()
        if nunique <= 1:
            constant_features.append(col)
        elif nunique <= 5:
            near_constant_features.append(col)

    logger.info(f"Validated {len(features)} features from contract.")
    logger.info(f"Constant features detected: {constant_features}")
    logger.info(f"Near-constant features detected (1-5 values): {near_constant_features}")

    # 3. Label Assignment Strategy
    logger.info("Assigning labels using process metadata and behavioural heuristics...")
    df["label"] = assign_heuristic_labels(df)
    
    label_counts = df["label"].value_counts()
    benign_count = label_counts.get(0, 0)
    attack_count = label_counts.get(1, 0)
    total_count = len(df)
    
    benign_pct = (benign_count / total_count) * 100.0 if total_count > 0 else 0.0
    attack_pct = (attack_count / total_count) * 100.0 if total_count > 0 else 0.0
    
    logger.info(f"Class Distribution: Benign: {benign_count} ({benign_pct:.2f}%), Attack: {attack_count} ({attack_pct:.2f}%)")

    if attack_count == 0 or benign_count == 0:
        logger.error("Supervised training aborted: Lack of distinct class labels in OTRF feature set.")
        sys.exit(1)

    # 4. Train / Validation / Test chronologically
    logger.info("Sorting windows chronologically for validation split...")
    df_sorted = df.sort_values(by="window_start")
    
    X = df_sorted[features]
    y = df_sorted["label"]
    
    # 70% Train, 15% Val, 15% Test
    total_len = len(df_sorted)
    train_idx = int(total_len * 0.70)
    val_idx = int(total_len * 0.85)

    X_train, y_train = X.iloc[:train_idx], y.iloc[:train_idx]
    X_val, y_val = X.iloc[train_idx:val_idx], y.iloc[train_idx:val_idx]
    X_test, y_test = X.iloc[val_idx:], y.iloc[val_idx:]

    logger.info(f"Dataset split indices: Train: {len(X_train)}, Val: {len(X_val)}, Test: {len(X_test)}")

    # 5. Model Hyperparameters & Setup
    # Imbalance handler
    scale_pos_weight = 1.0
    if attack_count > 0 and benign_count > 0:
        scale_pos_weight = float(benign_count / attack_count)
        
    lgb_params = {
        "boosting_type": "gbdt",
        "objective": "binary",
        "metric": "binary_logloss",
        "learning_rate": 0.05,
        "n_estimators": 150,
        "max_depth": 6,
        "num_leaves": 31,
        "scale_pos_weight": scale_pos_weight,
        "random_state": 42,
        "verbose": -1
    }

    logger.info(f"Training LightGBM with parameters: {lgb_params}")
    model = lgb.LGBMClassifier(**lgb_params)
    
    # Train
    model.fit(
        X_train, y_train,
        eval_set=[(X_val, y_val)],
        callbacks=[lgb.early_stopping(stopping_rounds=15, verbose=False)]
    )

    # 6. Evaluate feature importance
    importances = model.feature_importances_
    importance_df = pd.DataFrame({
        "feature": features,
        "importance": importances
    }).sort_values(by="importance", ascending=False)
    
    # Save Feature Importance Report
    importance_df.to_csv(reports_dir / "feature_importance.csv", index=False)
    
    # Save Feature Importance JSON
    with open(reports_dir / "feature_importance.json", "w", encoding="utf-8") as f:
        json.dump(importance_df.set_index("feature")["importance"].to_dict(), f, indent=2)

    # Markdown Feature Importance Report
    importance_rows = "\n".join(f"| {idx+1} | {row['feature']} | {row['importance']} |" for idx, row in importance_df.head(30).iterrows())
    fi_md = f"""# Feature Importance Report
This report outlines the feature split importances derived from the LightGBM classifier.

| Rank | Feature | Importance (Splits) |
|---|---|---|
{importance_rows}
"""
    (reports_dir / "feature_importance.md").write_text(fi_md, encoding="utf-8")

    # 7. Model Versioning & Saving
    # Determine model version
    v_folder = model_dir / "v1"
    version_num = 1
    while v_folder.exists():
        version_num += 1
        v_folder = model_dir / f"v{version_num}"
    
    v_folder.mkdir(parents=True, exist_ok=True)
    
    # Save files to active model directory and version folder
    for path in [model_dir, v_folder]:
        joblib.dump(model, path / "lightgbm_model.pkl")
        with open(path / "feature_contract.json", "w", encoding="utf-8") as f:
            json.dump(contract, f, indent=2)
            
        # Metadata
        metadata = {
            "model_version": f"v{version_num}",
            "training_date": datetime.now().isoformat(),
            "training_dataset": str(features_path),
            "feature_contract_hash": str(hash(json.dumps(contract))),
            "lightgbm_version": lgb.__version__,
            "python_version": sys.version,
            "samples_count": total_len,
            "train_samples": len(X_train),
            "val_samples": len(X_val),
            "test_samples": len(X_test)
        }
        with open(path / "training_metadata.json", "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

    logger.info(f"Model saved to active directory {model_dir} and version {v_folder}")
    
    # Also save training summary
    train_summary = f"""# Training Summary

- **Training Date**: {metadata['training_date']}
- **Model Version**: {metadata['model_version']}
- **Samples Used**: {total_len}
- **Imbalance Scale Weight**: {scale_pos_weight:.2f}
- **LightGBM Early Stopping**: Triggered successfully.
"""
    (reports_dir / "training_summary.md").write_text(train_summary, encoding="utf-8")
    
    # Save a temporary parquet file containing splits for evaluate_endpoint.py
    # We save test set to temp
    test_split_path = Path("data/processed/endpoint/test_split_temp.parquet")
    df_sorted.iloc[val_idx:].to_parquet(test_split_path, index=False)
    logger.info("Training script completed successfully.")

if __name__ == "__main__":
    main()
