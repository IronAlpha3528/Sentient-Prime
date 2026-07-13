import json
from pathlib import Path

import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    average_precision_score,
    accuracy_score,
    precision_recall_fscore_support
)

PROCESSED_DIR = Path("data/processed/network")
MODEL_DIR_V2 = Path("data/models/network/v2")


def main() -> None:
    metadata_path = PROCESSED_DIR / "metadata.json"
    if not metadata_path.exists():
        raise FileNotFoundError(f"Metadata not found at: {metadata_path}")
        
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    label_column = metadata["label_column"]
    family_label_column = metadata["family_label_column"]
    features = metadata["feature_columns"]

    print("Loading test data...")
    test = pd.read_parquet(PROCESSED_DIR / "test.parquet")

    # Load Stage 1 & Stage 2 models
    print("Loading models...")
    model_s1 = lgb.Booster(model_file=str(MODEL_DIR_V2 / "stage1_binary_model.txt"))
    model_s2 = lgb.Booster(model_file=str(MODEL_DIR_V2 / "stage2_family_model.txt"))
    encoder_s2 = joblib.load(MODEL_DIR_V2 / "family_label_encoder.pkl")

    # ========================================================
    # SECTION 1: STAGE 1 BINARY DETECTION
    # ========================================================
    print("\n" + "=" * 56)
    print("SECTION 1: STAGE 1 BINARY DETECTION (BENIGN vs ATTACK)")
    print("=" * 56)

    # True labels for Stage 1: 0 = Benign, 1 = Attack
    y_true_s1 = (test[family_label_column] != "Benign").astype(int)
    
    # Get raw probabilities
    s1_probs = model_s1.predict(test[features])
    y_pred_s1 = (s1_probs >= 0.5).astype(int)

    test_rows = len(test)
    benign_rows = (y_true_s1 == 0).sum()
    attack_rows = (y_true_s1 == 1).sum()

    acc_s1 = accuracy_score(y_true_s1, y_pred_s1)
    prec_s1, rec_s1, f1_s1, _ = precision_recall_fscore_support(
        y_true_s1, y_pred_s1, average="binary", zero_division=0
    )
    auc_s1 = roc_auc_score(y_true_s1, s1_probs)
    pr_auc_s1 = average_precision_score(y_true_s1, s1_probs)

    # Confusion matrix & False Positive Rate
    cm_s1 = confusion_matrix(y_true_s1, y_pred_s1)
    tn, fp, fn, tp = cm_s1.ravel()
    fpr_s1 = fp / (tn + fp) if (tn + fp) > 0 else 0.0

    print(f"Total test rows: {test_rows}")
    print(f"Benign test rows: {benign_rows}")
    print(f"Attack test rows: {attack_rows}")
    print("-" * 56)
    print(f"Accuracy:         {acc_s1:.4f}")
    print(f"Attack Precision: {prec_s1:.4f}")
    print(f"Attack Recall:    {rec_s1:.4f}")
    print(f"Attack F1-score:  {f1_s1:.4f}")
    print(f"ROC-AUC:          {auc_s1:.4f}")
    print(f"PR-AUC:           {pr_auc_s1:.4f}")
    print(f"False Positive Rate: {fpr_s1:.4f}")
    print("-" * 56)
    print("Stage 1 Confusion Matrix:")
    print(cm_s1)
    print(f"Actual attack flows classified as benign (Misses): {fn}")

    # ========================================================
    # SECTION 2: STAGE 2 ATTACK FAMILY CLASSIFICATION
    # ========================================================
    print("\n" + "=" * 56)
    print("SECTION 2: STAGE 2 ATTACK FAMILY CLASSIFICATION")
    print("=" * 56)

    # Evaluate strictly on true attack rows
    test_attack = test[test[family_label_column] != "Benign"].copy()
    
    if len(test_attack) > 0:
        y_true_s2 = encoder_s2.transform(test_attack[family_label_column])
        y_pred_s2 = np.argmax(model_s2.predict(test_attack[features]), axis=1)

        print(
            classification_report(
                y_true_s2,
                y_pred_s2,
                target_names=encoder_s2.classes_,
                zero_division=0,
            )
        )
        print("Stage 2 Family Confusion Matrix:")
        print(confusion_matrix(y_true_s2, y_pred_s2))
    else:
        print("No attack test flows found to evaluate.")

    # ========================================================
    # SECTION 3: END-TO-END HIERARCHICAL EVALUATION
    # ========================================================
    print("\n" + "=" * 56)
    print("SECTION 3: END-TO-END HIERARCHICAL PIPELINE RUN")
    print("=" * 56)

    # Standard simulation
    # Run Stage 2 predictions on all rows to be efficient
    s2_probs_all = model_s2.predict(test[features])
    s2_preds_all = np.argmax(s2_probs_all, axis=1)
    s2_preds_decoded = encoder_s2.inverse_transform(s2_preds_all)

    y_pred_final = []
    for i in range(len(test)):
        if y_pred_s1[i] == 0:
            y_pred_final.append("Benign")
        else:
            y_pred_final.append(s2_preds_decoded[i])

    y_true_final = test[family_label_column].values

    classes_hierarchy = ["Benign"] + list(encoder_s2.classes_)
    print(
        classification_report(
            y_true_final,
            y_pred_final,
            labels=classes_hierarchy,
            zero_division=0,
        )
    )
    print("Hierarchical Confusion Matrix:")
    print(confusion_matrix(y_true_final, y_pred_final, labels=classes_hierarchy))
    print("-" * 56)

    # Infiltration Detailed Recalls
    infiltration_mask = (test[label_column] == "Infilteration")
    infil_total = infiltration_mask.sum()
    
    if infil_total > 0:
        infil_indices = np.where(infiltration_mask)[0]
        infil_pred_s1 = y_pred_s1[infil_indices]
        infil_passed = int(infil_pred_s1.sum())
        infil_missed = int(len(infil_pred_s1) - infil_passed)
        s1_infil_recall = infil_passed / infil_total

        infil_pred_final = np.array(y_pred_final)[infil_indices]
        infil_correct_final = int((infil_pred_final == "Infiltration").sum())
        
        cond_s2_recall = infil_correct_final / infil_passed if infil_passed > 0 else 0.0
        e2e_infil_recall = infil_correct_final / infil_total

        print(f"Infiltration Total Test Flows:       {infil_total}")
        print(f"Infiltration Detected as Attack (S1): {infil_passed}")
        print(f"Infiltration Missed as Benign (S1):   {infil_missed}")
        print(f"Stage 1 Infiltration Recall:         {s1_infil_recall:.4f}")
        print(f"Conditional Stage 2 Infiltration Recall: {cond_s2_recall:.4f}")
        print(f"End-to-End Infiltration Recall (v2):  {e2e_infil_recall:.4f}")
        print("Previous Baseline Recall (v1):       ~0.0223")
        print("-" * 56)
    else:
        print("No Infiltration flows in test set.")

    # ========================================================
    # SECTION 4: STAGE-1 INFILTRATION PROBABILITY ANALYSIS (Task N1)
    # ========================================================
    print("\n" + "=" * 56)
    print("SECTION 4: STAGE-1 INFILTRATION PROBABILITY ANALYSIS")
    print("=" * 56)

    if infil_total > 0:
        infil_probs = s1_probs[infiltration_mask]
        
        infil_min = np.min(infil_probs)
        infil_max = np.max(infil_probs)
        infil_mean = np.mean(infil_probs)
        infil_median = np.median(infil_probs)
        infil_std = np.std(infil_probs)

        print("Infiltration Stage-1 Attack Probability Distribution")
        print(f"  Minimum: {infil_min:.6f}")
        print(f"  P1:      {np.percentile(infil_probs, 1):.6f}")
        print(f"  P5:      {np.percentile(infil_probs, 5):.6f}")
        print(f"  P10:     {np.percentile(infil_probs, 10):.6f}")
        print(f"  P25:     {np.percentile(infil_probs, 25):.6f}")
        print(f"  Median:  {infil_median:.6f}")
        print(f"  P75:     {np.percentile(infil_probs, 75):.6f}")
        print(f"  P90:     {np.percentile(infil_probs, 90):.6f}")
        print(f"  P95:     {np.percentile(infil_probs, 95):.6f}")
        print(f"  P99:     {np.percentile(infil_probs, 99):.6f}")
        print(f"  Maximum: {infil_max:.6f}")
        print(f"  Std Dev: {infil_std:.6f}")
        print("-" * 56)

        thresholds = [0.50, 0.40, 0.30, 0.20, 0.10]
        print(f"{'Threshold':<9} | {'Precision':<9} | {'Recall':<9} | {'F1':<9} | {'FPR':<9} | {'Infil Recall':<12} | {'Benign FP':<9} | {'Attack FN':<9}")
        print("-" * 105)

        for th in thresholds:
            y_pred_th = (s1_probs >= th).astype(int)
            prec_th, rec_th, f1_th, _ = precision_recall_fscore_support(
                y_true_s1, y_pred_th, average="binary", zero_division=0
            )
            cm_th = confusion_matrix(y_true_s1, y_pred_th)
            tn_th, fp_th, fn_th, tp_th = cm_th.ravel()
            fpr_th = fp_th / (tn_th + fp_th) if (tn_th + fp_th) > 0 else 0.0

            # Infiltration recall for this threshold
            infil_passed_th = (s1_probs[infiltration_mask] >= th).sum()
            infil_recall_th = infil_passed_th / infil_total

            print(f"{th:<9.2f} | {prec_th:<9.4f} | {rec_th:<9.4f} | {f1_th:<9.4f} | {fpr_th:<9.4f} | {infil_recall_th:<12.4f} | {fp_th:<9} | {fn_th:<9}")
        print("-" * 56)
    else:
        print("No Infiltration flows in test set.")

    # ========================================================
    # SECTION 5: FAMILY EVIDENCE FOR MISSED INFILTRATION (Task N2)
    # ========================================================
    print("\n" + "=" * 56)
    print("SECTION 5: FAMILY EVIDENCE FOR MISSED INFILTRATION")
    print("=" * 56)

    if infil_total > 0:
        missed_mask = infiltration_mask & (s1_probs < 0.50)
        missed_count = missed_mask.sum()
        print(f"Number of Stage-1 missed Infiltration flows: {missed_count} (out of {infil_total})")

        if missed_count > 0:
            # Predict families for missed flows
            missed_features = test[missed_mask][features]
            missed_s2_probs = model_s2.predict(missed_features)
            missed_preds = np.argmax(missed_s2_probs, axis=1)
            missed_decoded = encoder_s2.inverse_transform(missed_preds)

            # Print distribution
            unique, counts = np.unique(missed_decoded, return_counts=True)
            dist = dict(zip(unique, counts))
            print("\nStage-2 predicted family distribution for missed infiltration flows:")
            all_families = ["Infiltration", "Botnet", "BruteForce", "DDoS", "DoS", "WebAttack"]
            for fam in all_families:
                print(f"  {fam}: {dist.get(fam, 0)}")

            # Infiltration family probability stats
            idx_infil = list(encoder_s2.classes_).index("Infiltration")
            missed_infil_probs = missed_s2_probs[:, idx_infil]

            print("-" * 56)
            print("Infiltration Family Probability Statistics (Stage-2) on Stage-1 missed flows:")
            print(f"  Minimum: {np.min(missed_infil_probs):.6f}")
            print(f"  P25:     {np.percentile(missed_infil_probs, 25):.6f}")
            print(f"  Median:  {np.median(missed_infil_probs):.6f}")
            print(f"  P50:     {np.percentile(missed_infil_probs, 50):.6f}")
            print(f"  P75:     {np.percentile(missed_infil_probs, 75):.6f}")
            print(f"  P90:     {np.percentile(missed_infil_probs, 90):.6f}")
            print(f"  P95:     {np.percentile(missed_infil_probs, 95):.6f}")
            print(f"  Maximum: {np.max(missed_infil_probs):.6f}")
            print(f"  Mean:    {np.mean(missed_infil_probs):.6f}")
            print("-" * 56)

            # Cumulative bins
            for cutoff in [0.90, 0.80, 0.70, 0.60, 0.50]:
                pct = (missed_infil_probs >= cutoff).sum() / missed_count * 100.0
                print(f"Percentage of missed flows where Infiltration probability >= {cutoff:.2f}: {pct:.2f}%")

            # Show up to 20 examples
            print("-" * 56)
            print("Examples of Stage-1 Missed Infiltration Flows with Stage-2 evidence:")
            missed_df = test[missed_mask].copy()
            missed_df["s1_prob"] = s1_probs[missed_mask]
            
            # Print details
            sample_count = min(20, len(missed_df))
            for i in range(sample_count):
                row_idx = i
                s1_prob = float(missed_df.iloc[row_idx]["s1_prob"])
                probs = missed_s2_probs[row_idx]
                
                # Top 3
                sorted_idx = np.argsort(probs)[::-1]
                top_3 = [
                    {
                        "family": encoder_s2.inverse_transform([int(idx)])[0],
                        "prob": float(probs[idx])
                    }
                    for idx in sorted_idx[:3]
                ]
                
                pred_fam = top_3[0]["family"]
                pred_fam_prob = top_3[0]["prob"]
                infil_prob = float(probs[idx_infil])

                print(f"\nExample #{i+1}:")
                print(f"  Stage-1 Attack Probability:      {s1_prob:.4f}")
                print(f"  Stage-2 Predicted Family:        {pred_fam} ({pred_fam_prob:.4f})")
                print(f"  Infiltration family probability: {infil_prob:.4f}")
                print("  Top 3 Predictions:")
                for p in top_3:
                    print(f"    - {p['family']}: {p['prob']:.4f}")
        else:
            print("No Stage-1 missed Infiltration flows found.")
    else:
        print("No Infiltration flows in test set.")


if __name__ == "__main__":
    main()
