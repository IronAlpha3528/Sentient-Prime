import os
import sys
import json
import logging
from pathlib import Path
from datetime import datetime
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
import lightgbm as lgb

from typing import Dict, Any, List, Optional
# Ensure project root is in path if executing directly
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from detectors.ot.anomaly_calibrator import AnomalyCalibrator

logger = logging.getLogger(__name__)

def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    logger.info("Initializing OT Specialist model training pipeline...")

    # Paths
    features_path = Path("data/processed/ot/features/ot_features.parquet")
    contract_path = Path("data/processed/ot/metadata/feature_contract.json")
    model_dir = Path("models/ot")
    reports_dir = Path("data/processed/ot/reports")
    
    model_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    # 1. Load Configurations
    config_path = Path("config/ot.yaml")
    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            import yaml
            config = yaml.safe_load(f) or {}
    else:
        config = {}

    window_length = config.get("window_length", 60)
    stride = config.get("stride", 10)
    
    # Isolation Forest params
    iforest_params = config.get("iforest_parameters", {
        "n_estimators": 100,
        "max_samples": "auto",
        "contamination": 0.05,
        "random_state": 42,
        "bootstrap": False
    })
    
    # LightGBM params
    lgb_params = config.get("lightgbm_parameters", {
        "boosting_type": "gbdt",
        "objective": "binary",
        "metric": "binary_logloss",
        "learning_rate": 0.05,
        "n_estimators": 100,
        "max_depth": 5,
        "num_leaves": 31,
        "verbose": -1,
        "random_state": 42
    })

    if not features_path.exists():
        logger.error(f"Features dataset not found at {features_path}. Run preprocess_ot first.")
        sys.exit(1)

    if not contract_path.exists():
        logger.error(f"Feature contract not found at {contract_path}")
        sys.exit(1)

    # 2. Load Preprocessed Features
    df = pd.read_parquet(features_path)
    logger.info(f"Loaded features dataset with shape {df.shape}")

    # Load feature contract
    with open(contract_path, "r", encoding="utf-8") as f:
        contract = json.load(f)
    features = list(contract.keys())
    
    # Sort chronologically
    df = df.sort_values(by="start_time").reset_index(drop=True)

    # 3. Split: Train 70% / Val 15% / Test 15% chronologically
    total_len = len(df)
    train_idx = int(total_len * 0.70)
    val_idx = int(total_len * 0.85)

    df_train = df.iloc[:train_idx]
    df_val = df.iloc[train_idx:val_idx]
    df_test = df.iloc[val_idx:]

    logger.info(f"Dataset chronological split indices: Train: {len(df_train)}, Val: {len(df_val)}, Test: {len(df_test)}")

    # 4. Fit Isolation Forest (Unsupervised)
    # MUST train ONLY on normal windows (label == 0)
    normal_train = df_train[df_train["attack_label"] == 0]
    attack_train_rows = len(df_train) - len(normal_train)
    
    logger.info(f"Isolation Forest dataset balance verification:")
    logger.info(f"  Total train rows: {len(df_train)}")
    logger.info(f"  Removed attack rows: {attack_train_rows}")
    logger.info(f"  Final training size (normal only): {len(normal_train)}")

    X_train_if = normal_train[features]
    
    # Init and fit
    logger.info(f"Training Isolation Forest with parameters: {iforest_params}")
    iforest = IsolationForest(
        n_estimators=iforest_parameters_get(iforest_params, "n_estimators", 100),
        max_samples=iforest_parameters_get(iforest_params, "max_samples", "auto"),
        contamination=iforest_parameters_get(iforest_params, "contamination", 0.05),
        random_state=iforest_parameters_get(iforest_params, "random_state", 42),
        bootstrap=iforest_parameters_get(iforest_params, "bootstrap", False),
        n_jobs=-1
    )
    iforest.fit(X_train_if)

    # Fit Anomaly Calibrator using normal validation set raw scores
    X_val_if = df_val[df_val["attack_label"] == 0][features]
    if X_val_if.empty:
        # fallback to training normal scores if validation has no normal rows
        X_val_if = X_train_if
        
    val_raw_scores = iforest.score_samples(X_val_if)
    calibrator = AnomalyCalibrator()
    calibrator.fit(val_raw_scores)

    # 5. Fit LightGBM (Supervised Refinement - Optional)
    # Only train if attack labels exist in training split
    y_train = df_train["attack_label"]
    has_attack_labels = int(y_train.sum()) > 0
    
    lightgbm_model = None
    if has_attack_labels:
        logger.info("Attack labels detected. Training LightGBM classifier...")
        X_train_lgb = df_train[features]
        X_val_lgb = df_val[features]
        y_val = df_val["attack_label"]
        
        # Calculate imbalance weight
        neg_count = (y_train == 0).sum()
        pos_count = (y_train == 1).sum()
        scale_pos_weight = neg_count / pos_count if pos_count > 0 else 1.0
        
        lgb_params["scale_pos_weight"] = scale_pos_weight
        logger.info(f"LightGBM parameters: {lgb_params}")
        
        lightgbm_model = lgb.LGBMClassifier(**lgb_params)
        lightgbm_model.fit(
            X_train_lgb, y_train,
            eval_set=[(X_val_lgb, y_val)],
            callbacks=[lgb.early_stopping(stopping_rounds=15, verbose=False)]
        )
        logger.info("LightGBM classifier trained successfully.")
    else:
        logger.warning("No attack labels found in training split. Skipping LightGBM training.")

    # 6. Generate Baseline Feature Statistics (mean/std)
    # Used by Evidence Generator to identify top shifted variables
    baseline_stats = {}
    for col in features:
        baseline_stats[col] = {
            "mean": float(normal_train[col].mean()),
            "std": float(normal_train[col].std())
        }
    
    # Save baseline stats inside model folder
    with open(model_dir / "baseline_stats.json", "w", encoding="utf-8") as f:
        json.dump(baseline_stats, f, indent=2)

    # 7. Model Versioning & Saving
    v_num = 1
    v_folder = model_dir / "v1"
    while v_folder.exists():
        v_num += 1
        v_folder = model_dir / f"v{v_num}"
    v_folder.mkdir(parents=True, exist_ok=True)

    # Save metadata
    metadata = {
        "model_version": f"v{v_num}",
        "training_date": datetime.now().isoformat(),
        "training_dataset": str(features_path),
        "feature_contract_hash": str(hash(json.dumps(contract))),
        "python_version": sys.version,
        "scikit_learn_version": "1.3.0", # Scikit-learn estimated
        "lightgbm_version": lgb.__version__,
        "train_samples": len(df_train),
        "val_samples": len(df_val),
        "test_samples": len(df_test),
        "calibrator_stats": {
            "mean": calibrator.mean,
            "std": calibrator.std,
            "threshold_medium": calibrator.threshold_medium,
            "threshold_high": calibrator.threshold_high,
            "threshold_critical": calibrator.threshold_critical
        }
    }

    # Save to active model dir and versioned dir
    for path in [model_dir, v_folder]:
        joblib.dump(iforest, path / "isolation_forest.pkl")
        if lightgbm_model:
            joblib.dump(lightgbm_model, path / "lightgbm.pkl")
        with open(path / "feature_contract.json", "w", encoding="utf-8") as f:
            json.dump(contract, f, indent=2)
        with open(path / "training_metadata.json", "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)
        with open(path / "baseline_stats.json", "w", encoding="utf-8") as f:
            json.dump(baseline_stats, f, indent=2)

    logger.info(f"Model saved under {model_dir} and version folder {v_folder}")

    # 8. Feature Importance Export
    # For LightGBM: standard gain feature importance
    importance_list = []
    if lightgbm_model:
        importances = lightgbm_model.feature_importances_
        importance_df = pd.DataFrame({
            "feature": features,
            "importance": importances
        }).sort_values(by="importance", ascending=False)
        importance_list = importance_df.to_dict(orient="records")
        
        importance_df.to_csv(reports_dir / "feature_importance.csv", index=False)
        with open(reports_dir / "feature_importance.json", "w", encoding="utf-8") as f:
            json.dump(importance_df.set_index("feature")["importance"].to_dict(), f, indent=2)

        # Markdown importance table
        imp_rows = "\n".join(f"| {idx+1} | {row['feature']} | {row['importance']} |" for idx, row in importance_df.head(25).iterrows())
        imp_md = f"""# Feature Importance (LightGBM)

| Rank | Feature | Importance (Splits) |
|---|---|---|
{imp_rows}
"""
        (reports_dir / "feature_importance.md").write_text(imp_md, encoding="utf-8")
    else:
        # For Isolation Forest, generate mock/heuristic importance based on variance
        var_importance = pd.DataFrame({
            "feature": features,
            "importance": [float(df_train[col].var()) for col in features]
        }).sort_values(by="importance", ascending=False)
        var_importance.to_csv(reports_dir / "feature_importance.csv", index=False)
        with open(reports_dir / "feature_importance.json", "w", encoding="utf-8") as f:
            json.dump(var_importance.set_index("feature")["importance"].to_dict(), f, indent=2)
        imp_rows = "\n".join(f"| {idx+1} | {row['feature']} | {row['importance']:.4f} |" for idx, row in var_importance.head(25).iterrows())
        imp_md = f"""# Feature Importance (Variance heuristic)

| Rank | Feature | Variance |
|---|---|---|
{imp_rows}
"""
        (reports_dir / "feature_importance.md").write_text(imp_md, encoding="utf-8")

    # Save training summary md
    summary_md = f"""# Training Summary (OT Specialist)
- **Model Version**: {metadata['model_version']}
- **Training Date**: {metadata['training_date']}
- **Samples**: {metadata['train_samples']} Train, {metadata['val_samples']} Val, {metadata['test_samples']} Test
- **Isolation Forest normal training size**: {len(normal_train)}
- **LightGBM Trained**: {has_attack_labels}
"""
    (reports_dir / "training_summary.md").write_text(summary_md, encoding="utf-8")

    # Save holdout split to temp for evaluate_ot.py
    df_test.to_parquet(Path("data/processed/ot/test_split_temp.parquet"), index=False)
    logger.info("OT Specialist model training completed successfully.")

def iforest_parameters_get(params_dict: dict, name: str, default: Any) -> Any:
    return params_dict.get(name, default)

if __name__ == "__main__":
    main()
