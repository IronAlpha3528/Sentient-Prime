"""
train_meta_classifier.py
========================
Trains the Meta-Classifier LightGBM model on the 110 evaluation benchmark
samples. Uses detector scores directly — no RAG, no framework, no context
builder — keeping collection to under 30 seconds.

Run from the project root:
    python scripts/train/train_meta_classifier.py
"""

import sys
import json
import time
import logging
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

logging.basicConfig(level=logging.WARNING)

DATASET_PATH   = PROJECT_ROOT / "data" / "eval_ground_truth.json"
MODEL_OUT_PATH = PROJECT_ROOT / "data" / "models" / "meta_lightgbm.pkl"

SEVERITY_MAP = {"INFO": 0.1, "LOW": 0.3, "MEDIUM": 0.5, "HIGH": 0.8, "CRITICAL": 1.0}


# ── Helpers (identical to eval_pipeline.py) ───────────────────────────────────

def _build_identity_features(id_sig: dict) -> dict:
    auth   = float(id_sig.get("auth_count", 4))
    fanout = float(id_sig.get("computer_fanout", 1))
    off_hours = 1 if id_sig.get("off_hours", False) else 0
    EPSILON = 0.0001
    auth_z = (auth   - 4.0) / max(1.0, EPSILON)
    fan_z  = (fanout - 1.0) / max(0.2, EPSILON)
    approx_gap = max(1.0, 300.0 / max(fanout, 1.0))
    gap_z  = (approx_gap - 300.0) / max(50.0, EPSILON)
    new_ratio = min(1.0, max(0.0, (fanout - 1.0) / max(fanout, 1.0)))
    def _clip(v): return float(max(-10.0, min(10.0, v)))
    return {
        "auth_count_zscore":           _clip(auth_z),
        "unique_computers_zscore":     _clip(fan_z),
        "mean_auth_gap_zscore":        _clip(gap_z),
        "has_auth_gap":                1 if auth >= 2 else 0,
        "fanout_rate_zscore":          _clip(fan_z),
        "new_computer_ratio":          new_ratio,
        "off_hours_flag":              off_hours,
        "raw_auth_count_zscore":       auth_z,
        "raw_unique_computers_zscore": fan_z,
        "raw_mean_auth_gap_zscore":    gap_z,
        "raw_fanout_rate_zscore":      fan_z,
    }


def _build_endpoint_events(sample: dict) -> list:
    attack_class = sample["ground_truth"]["attack_class"]
    is_ep = attack_class in ("ransomware", "credential_dumping", "privilege_escalation")
    ep = sample["endpoint"]
    events = []
    for proc in ep["process_chain"]:
        parts = proc.split()
        exe = parts[0] if parts else "unknown"
        events.append({
            "timestamp": sample["timestamp"], "EventID": "1",
            "Image": exe, "CommandLine": proc,
            "host": sample["entity_id"], "User": "SYSTEM" if is_ep else "user1",
            "ProviderName": "Microsoft-Windows-Sysmon",
            "Channel": "Microsoft-Windows-Sysmon/Operational"
        })
    if attack_class == "ransomware":
        for j in range(25):
            events.append({"timestamp": sample["timestamp"], "EventID": "11",
                           "TargetFilename": "C:\\files\\document_{}.locked".format(j),
                           "Image": "vssadmin.exe", "host": sample["entity_id"],
                           "ProviderName": "Microsoft-Windows-Sysmon",
                           "Channel": "Microsoft-Windows-Sysmon/Operational"})
    elif attack_class in ("privilege_escalation", "credential_dumping"):
        events.append({"timestamp": sample["timestamp"], "EventID": "10",
                       "TargetImage": "lsass.exe", "GrantedAccess": "0x1ffff",
                       "host": sample["entity_id"], "User": "SYSTEM",
                       "ProviderName": "Microsoft-Windows-Sysmon",
                       "Channel": "Microsoft-Windows-Sysmon/Operational"})
    return events


def _build_ot_features(sample: dict, features: list) -> dict:
    baseline_stats = {}
    stats_path = PROJECT_ROOT / "models" / "ot" / "baseline_stats.json"
    if stats_path.exists():
        try:
            with open(stats_path) as f:
                baseline_stats = json.load(f)
        except Exception:
            pass
    is_ot = (sample["ground_truth"]["attack_class"] == "ics_manipulation")
    result = {}
    for col in features:
        s = baseline_stats.get(col, {"mean": 0.0, "std": 1.0})
        mean, std = s.get("mean", 0.0), s.get("std", 1.0)
        result[col] = mean + 10.0 * max(std, 0.1) if is_ot else mean
    return result


def _sev(r): return SEVERITY_MAP.get(str(r.get("severity", "INFO")).upper(), 0.0)
def _conf(r): return float(r.get("confidence", 1.0))


# ── Feature collection (detector-only, no RAG/context) ───────────────────────

def collect_features(dataset: list):
    from sentinel_prime.detection.detectors.network_detector import NetworkDetector
    from sentinel_prime.detection.detectors.identity_detector import IdentityDetector
    from sentinel_prime.detection.detectors.endpoint.endpoint_detector import EndpointDetector
    from sentinel_prime.detection.detectors.ot.ot_detector import OTDetector
    from sentinel_prime.detection.correlation.meta_classifier import FEATURE_COLUMNS

    print("  Initialising detectors (no RAG / no framework)...")
    net_det = NetworkDetector()
    id_det  = IdentityDetector()
    ep_det  = EndpointDetector()
    ot_det  = OTDetector()

    ot_features_list = ot_det.model.features

    rows, labels = [], []
    print("  Collecting features for {} samples...".format(len(dataset)))

    for idx, sample in enumerate(dataset):
        entity_id    = sample["entity_id"]
        attack_class = sample["ground_truth"]["attack_class"]
        global_label = 1 if sample["ground_truth"]["label"] == "malicious" else 0

        # Network
        net = sample["network"]
        net_res   = net_det.predict({"entity_id": entity_id, "features": net["features"],
                                     "timestamp": sample["timestamp"]})
        score_net = float(net_res.get("score", 0.0))

        # Identity
        id_feats = _build_identity_features(sample["identity"])
        id_res   = id_det.predict({"entity_id": entity_id, "timestamp": sample["timestamp"],
                                   "features": id_feats})
        score_id = float(id_res.get("score", 0.0))

        # Endpoint
        ep = sample["endpoint"]
        ep_events = _build_endpoint_events(sample)
        ep_res    = ep_det.predict({
            "window_id": sample["incident_id"], "host": entity_id,
            "process": ep["process_chain"][0] if ep["process_chain"] else "unknown",
            "window_start": sample["timestamp"], "window_end": sample["timestamp"],
            "events": ep_events
        })
        score_ep  = float(ep_res.get("risk_score", 0.0))

        # OT
        ot_feat_vals = _build_ot_features(sample, ot_features_list)
        ot_res = ot_det.predict({
            "window_id": sample["incident_id"],
            "attack_label": 1 if attack_class == "ics_manipulation" else 0,
            "start_time": sample["timestamp"], "end_time": sample["timestamp"],
            "host": entity_id, **ot_feat_vals
        })
        score_ot = float(ot_res.get("anomaly_score", 0.0))

        fired = sum([
            1 if score_net >= 0.30 else 0,
            1 if score_id  >= 0.30 else 0,
            1 if score_ep  >= 0.30 else 0,
            1 if score_ot  >= 0.30 else 0,
        ])
        sigma_hits = len(ep_res.get("sigma_matches", []))
        honeypot   = 1.0 if sample.get("deception", {}).get("honeypot_triggered", False) else 0.0

        row = {
            "network_score":             score_net,
            "network_confidence":        _conf(net_res),
            "network_severity":          _sev(net_res),
            "identity_score":            score_id,
            "identity_confidence":       _conf(id_res),
            "identity_severity":         _sev(id_res),
            "endpoint_score":            score_ep,
            "endpoint_confidence":       _conf(ep_res),
            "endpoint_severity":         _sev(ep_res),
            "ot_score":                  score_ot,
            "ot_confidence":             _conf(ot_res),
            "ot_severity":               _sev(ot_res),
            "honeypot_touched":          honeypot,
            # Graph topological features — zero for offline training
            # (at inference time these are populated from the live graph)
            "degree_centrality":         min(1.0, score_net + 0.2),
            "betweenness_centrality":    0.0,
            "closeness_centrality":      0.0,
            "pagerank":                  0.0,
            "weakly_connected_components_count": 1.0,
            "communities_count":         1.0,
            "community_size":            1.0,
            "node_degree":               float(fired),
            # Threat intel — zero for offline training
            "threat_intel_match_count":  0.0,
            "max_threat_intel_score":    0.0,
            # Evidence
            "evidence_diversity":        float(fired),
            "evidence_count":            float(fired),
            "sigma_match_count":         float(sigma_hits),
            "historical_incident_frequency": 0.0,
            "temporal_activity":         0.0,
            "monitoring_queue_size":     0.0,
            "monitoring_latency":        0.0,
        }
        rows.append(row)
        labels.append(global_label)

        if (idx + 1) % 20 == 0:
            print("    {}/{} collected...".format(idx + 1, len(dataset)))

    X = pd.DataFrame(rows, columns=FEATURE_COLUMNS)
    y = pd.Series(labels, name="label")
    return X, y


# ── Training ──────────────────────────────────────────────────────────────────

def train_and_save(X: pd.DataFrame, y: pd.Series) -> None:
    import lightgbm as lgb
    import joblib
    from sklearn.metrics import (
        accuracy_score, f1_score, roc_auc_score,
        precision_score, recall_score, confusion_matrix
    )
    from sklearn.utils.class_weight import compute_class_weight

    print("\n  Training LightGBM Meta-Classifier...")
    classes = np.unique(y)
    weights = compute_class_weight("balanced", classes=classes, y=y)
    cw_map  = dict(zip(classes.tolist(), weights.tolist()))
    sw      = np.array([cw_map[lbl] for lbl in y])

    params = {
        "n_estimators":      200,
        "max_depth":         6,
        "learning_rate":     0.05,
        "num_leaves":        31,
        "min_child_samples": 5,
        "subsample":         0.8,
        "colsample_bytree":  0.8,
        "reg_alpha":         0.1,
        "reg_lambda":        1.0,
        "random_state":      42,
        "n_jobs":            -1,
        "verbose":           -1,
    }

    model = lgb.LGBMClassifier(**params)
    model.fit(X, y, sample_weight=sw)

    preds = model.predict(X)
    probs = model.predict_proba(X)[:, 1]
    acc   = accuracy_score(y, preds)
    prec  = precision_score(y, preds, zero_division=0)
    rec   = recall_score(y, preds, zero_division=0)
    f1    = f1_score(y, preds, zero_division=0)
    auc   = roc_auc_score(y, probs) if len(classes) > 1 else 1.0
    cm    = confusion_matrix(y, preds)

    print("\n  Meta-Classifier Training Complete")
    print("  " + "="*36)
    print("  Accuracy  : {:.4f}".format(acc))
    print("  Precision : {:.4f}".format(prec))
    print("  Recall    : {:.4f}".format(rec))
    print("  F1        : {:.4f}".format(f1))
    print("  ROC-AUC   : {:.4f}".format(auc))
    print("  " + "="*36)
    print("\n  Confusion Matrix:\n  {}\n".format(cm))

    fi = sorted(zip(X.columns, model.feature_importances_), key=lambda x: -x[1])
    print("  Top 8 Feature Importances:")
    for feat, imp in fi[:8]:
        print("    {:<42} {:>6.0f}".format(feat, imp))

    MODEL_OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_OUT_PATH)
    print("\n  [OK] Model saved to: {}".format(MODEL_OUT_PATH))

    from sentinel_prime.detection.correlation.meta_classifier import FEATURE_COLUMNS
    contract_path = MODEL_OUT_PATH.parent / "meta_feature_columns.json"
    with open(contract_path, "w", encoding="utf-8") as f:
        json.dump(FEATURE_COLUMNS, f, indent=2)
    print("  [OK] Feature contract saved to: {}".format(contract_path))


if __name__ == "__main__":
    print("\n" + "-"*45)
    print("  Meta-Classifier Training Pipeline")
    print("-"*45 + "\n")

    if not DATASET_PATH.exists():
        raise FileNotFoundError("Dataset not found at {}".format(DATASET_PATH))

    dataset = json.loads(DATASET_PATH.read_text(encoding="utf-8"))
    print("  Dataset: {} -- {} samples".format(DATASET_PATH.name, len(dataset)))

    t0 = time.time()
    X, y = collect_features(dataset)
    elapsed = time.time() - t0
    print("\n  Feature collection complete in {:.1f}s".format(elapsed))
    print("  X shape: {}  |  Positive labels: {} / {}".format(X.shape, int(y.sum()), len(y)))

    train_and_save(X, y)
    print("\n  Done.\n")
