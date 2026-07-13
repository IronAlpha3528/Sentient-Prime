import json
from pathlib import Path

import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder

from data.training.network_common import PROCESSED_DIR

MODEL_DIR_V2 = Path("data/models/network/v2")


def main() -> None:
    metadata = json.loads(
        (PROCESSED_DIR / "metadata.json").read_text(encoding="utf-8")
    )
    label_column = metadata["label_column"]
    family_label_column = metadata["family_label_column"]
    features = metadata["feature_columns"]

    print("Loading train and validation Parquet data...")
    train = pd.read_parquet(PROCESSED_DIR / "train.parquet")
    valid = pd.read_parquet(PROCESSED_DIR / "valid.parquet")

    # ========================================================
    # STAGE 1: Binary Classifier (Benign vs Suspicious/Attack)
    # ========================================================
    print("\n--- Training Stage 1: Binary Classifier ---")
    
    # 0 = Benign, 1 = Attack
    y_train_s1 = (train[family_label_column] != "Benign").astype(int)
    y_valid_s1 = (valid[family_label_column] != "Benign").astype(int)

    # Class imbalance handling for Stage 1 using scale_pos_weight
    # scale_pos_weight = count(negative) / count(positive)
    neg_count = (y_train_s1 == 0).sum()
    pos_count = (y_train_s1 == 1).sum()
    scale_pos_weight = float(neg_count / pos_count) if pos_count > 0 else 1.0
    print(f"Stage 1 scale_pos_weight: {scale_pos_weight:.4f} (Neg: {neg_count}, Pos: {pos_count})")

    train_set_s1 = lgb.Dataset(train[features], label=y_train_s1)
    valid_set_s1 = lgb.Dataset(valid[features], label=y_valid_s1, reference=train_set_s1)

    params_s1 = {
        "objective": "binary",
        "metric": "binary_logloss",
        "learning_rate": 0.05,
        "num_leaves": 63,
        "feature_fraction": 0.9,
        "bagging_fraction": 0.9,
        "bagging_freq": 1,
        "verbosity": -1,
        "seed": 42,
        "scale_pos_weight": scale_pos_weight,
    }

    model_s1 = lgb.train(
        params_s1,
        train_set_s1,
        num_boost_round=1000,
        valid_sets=[valid_set_s1],
        callbacks=[
            lgb.early_stopping(50),
            lgb.log_evaluation(25),
        ],
    )

    # ========================================================
    # STAGE 2: Multiclass Attack Family Classifier
    # ========================================================
    print("\n--- Training Stage 2: Attack Family Classifier ---")
    
    # Filter to only attack rows
    train_attack = train[train[family_label_column] != "Benign"].copy()
    valid_attack = valid[valid[family_label_column] != "Benign"].copy()

    encoder_s2 = LabelEncoder()
    y_train_s2 = encoder_s2.fit_transform(train_attack[family_label_column])
    y_valid_s2 = encoder_s2.transform(valid_attack[family_label_column])

    # Balanced class weights calculation for Stage 2
    # weight = total_samples / (num_classes * class_samples)
    num_classes = len(encoder_s2.classes_)
    total_attack_rows = len(train_attack)
    class_counts = train_attack[family_label_column].value_counts().to_dict()
    
    class_weights = {}
    for cls, count in class_counts.items():
        class_weights[cls] = float(total_attack_rows / (num_classes * count))
    
    print("Stage 2 class weights:")
    for cls, weight in class_weights.items():
        print(f"  {cls}: {weight:.4f} (Count: {class_counts[cls]})")

    # Map class weights to samples
    sample_weights_train = train_attack[family_label_column].map(class_weights).values

    train_set_s2 = lgb.Dataset(train_attack[features], label=y_train_s2, weight=sample_weights_train)
    valid_set_s2 = lgb.Dataset(valid_attack[features], label=y_valid_s2, reference=train_set_s2)

    params_s2 = {
        "objective": "multiclass",
        "num_class": num_classes,
        "metric": "multi_logloss",
        "learning_rate": 0.05,
        "num_leaves": 63,
        "feature_fraction": 0.9,
        "bagging_fraction": 0.9,
        "bagging_freq": 1,
        "verbosity": -1,
        "seed": 42,
    }

    model_s2 = lgb.train(
        params_s2,
        train_set_s2,
        num_boost_round=1000,
        valid_sets=[valid_set_s2],
        callbacks=[
            lgb.early_stopping(50),
            lgb.log_evaluation(25),
        ],
    )

    # ========================================================
    # SAVE MODEL V2 ARTIFACTS
    # ========================================================
    MODEL_DIR_V2.mkdir(parents=True, exist_ok=True)
    
    # Save LightGBM booster model files
    model_s1.save_model(str(MODEL_DIR_V2 / "stage1_binary_model.txt"))
    model_s2.save_model(str(MODEL_DIR_V2 / "stage2_family_model.txt"))
    
    # Save encoders & feature names
    joblib.dump(encoder_s2, MODEL_DIR_V2 / "family_label_encoder.pkl")
    (MODEL_DIR_V2 / "feature_columns.json").write_text(
        json.dumps(features, indent=2),
        encoding="utf-8",
    )

    model_metadata = {
        "model_version": "network-hierarchical-lightgbm-v2",
        "stage1_model_type": "LightGBM Binary Classifier",
        "stage2_model_type": "LightGBM Multiclass Classifier",
        "feature_columns": features,
        "attack_family_mapping": metadata["attack_family_mapping"],
        "stage1_class_distribution": {
            "Benign": int(neg_count),
            "Attack": int(pos_count)
        },
        "stage2_family_distribution": {
            cls: int(count) for cls, count in class_counts.items()
        },
        "stage1_weighting_strategy": f"scale_pos_weight={scale_pos_weight}",
        "stage2_weighting_strategy": "balanced sample weighting",
        "training_rows": len(train),
        "validation_rows": len(valid),
        "random_seed": 42
    }

    (MODEL_DIR_V2 / "model_metadata.json").write_text(
        json.dumps(model_metadata, indent=2),
        encoding="utf-8",
    )

    print("\n--- Training Complete ---")
    print(f"Stage 1 Saved: {MODEL_DIR_V2 / 'stage1_binary_model.txt'}")
    print(f"Stage 2 Saved: {MODEL_DIR_V2 / 'stage2_family_model.txt'}")
    print(f"Encoder Saved: {MODEL_DIR_V2 / 'family_label_encoder.pkl'}")
    print(f"Metadata Saved: {MODEL_DIR_V2 / 'model_metadata.json'}")


if __name__ == "__main__":
    main()
