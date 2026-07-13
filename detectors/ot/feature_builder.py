import logging
from typing import Dict, Any, List
import pandas as pd
import numpy as np

logger = logging.getLogger(__name__)

def calculate_entropy(series: pd.Series, bins: int = 10) -> float:
    """
    Computes Shannon entropy of a continuous series by binning.
    """
    clean_series = series.dropna()
    if clean_series.empty:
        return 0.0
    counts, _ = np.histogram(clean_series, bins=bins)
    probs = counts / np.sum(counts)
    probs = probs[probs > 0]
    return float(-np.sum(probs * np.log2(probs))) if len(probs) > 0 else 0.0

def build_features_for_window(window_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generates rolling behavioural and correlation features from a window DataFrame.
    """
    meta = window_data["metadata"]
    df = window_data["data"].copy()

    features = {
        "window_id": meta.window_id,
        "start_time": meta.start_time,
        "end_time": meta.end_time,
        "host": meta.host,
        "attack_label": int(meta.label),
        "attack_ratio": float(meta.attack_ratio)
    }

    # Group columns by classification type
    sensor_cols = [c for c in df.columns if c.startswith("sensor_")]
    actuator_cols = [c for c in df.columns if c.startswith("actuator_")]
    controller_cols = [c for c in df.columns if c.startswith("controller_")]
    status_cols = [c for c in df.columns if c.startswith("status_")]

    # Limit detailed computation to top N columns to prevent combinatorial explosion
    top_sensors = sensor_cols[:15]
    top_actuators = actuator_cols[:8]
    top_controllers = controller_cols[:8]

    # 1. Sensors Feature Extraction
    for col in sensor_cols:
        series = df[col]
        mean_val = float(series.mean()) if not series.empty else 0.0
        std_val = float(series.std()) if not series.empty else 0.0
        min_val = float(series.min()) if not series.empty else 0.0
        max_val = float(series.max()) if not series.empty else 0.0
        
        # Basic stats
        features[f"{col}_mean"] = mean_val
        features[f"{col}_std"] = std_val
        features[f"{col}_min"] = min_val
        features[f"{col}_max"] = max_val
        features[f"{col}_range"] = max_val - min_val

        # Compute complex behavioural metrics for top sensors
        if col in top_sensors:
            features[f"{col}_median"] = float(series.median()) if not series.empty else 0.0
            features[f"{col}_variance"] = float(series.var()) if not series.empty else 0.0
            
            p25 = float(series.quantile(0.25))
            p75 = float(series.quantile(0.75))
            features[f"{col}_p25"] = p25
            features[f"{col}_p75"] = p75
            features[f"{col}_iqr"] = p75 - p25
            features[f"{col}_cv"] = std_val / mean_val if mean_val != 0.0 else 0.0
            features[f"{col}_energy"] = float(np.sum(series.fillna(0) ** 2))
            features[f"{col}_entropy"] = calculate_entropy(series)

            # Temporal and stability metrics
            diffs = series.diff().dropna()
            features[f"{col}_first_diff_mean"] = float(diffs.abs().mean()) if not diffs.empty else 0.0
            features[f"{col}_rate_of_change"] = float(series.iloc[-1] - series.iloc[0]) / len(series) if len(series) > 1 else 0.0
            
            # Zero crossings around mean
            centered = series - mean_val
            crossings = np.diff(np.sign(centered).fillna(0)) != 0
            features[f"{col}_zero_crossings"] = int(np.sum(crossings))

            # Flatlines: max consecutive equal values
            is_flat = series.diff() == 0
            flat_dur = 0
            if is_flat.any():
                flat_dur = int(is_flat.astype(int).groupby((~is_flat).cumsum()).sum().max())
            features[f"{col}_flatline_duration"] = flat_dur

            # Oscillation counts: local peaks
            peaks = np.diff(np.sign(diffs).fillna(0)) != 0
            features[f"{col}_oscillation_count"] = int(np.sum(peaks))

    # 2. Actuator Features
    for col in actuator_cols:
        series = df[col]
        # Count state changes
        diffs = series.diff().dropna()
        state_changes = int((diffs != 0).sum())
        features[f"{col}_state_changes"] = state_changes
        features[f"{col}_transition_rate"] = state_changes / len(series) if len(series) > 0 else 0.0
        
        # Max consecutive time in one state
        if col in top_actuators:
            same_state = series.diff() == 0
            max_state_dur = 0
            if same_state.any():
                max_state_dur = int(same_state.astype(int).groupby((~same_state).cumsum()).sum().max()) + 1
            features[f"{col}_max_state_duration"] = max_state_dur

    # 3. Control Loop Features
    for col in controller_cols:
        series = df[col]
        features[f"{col}_variance"] = float(series.var()) if not series.empty else 0.0
        diffs = series.diff().dropna()
        features[f"{col}_change_count"] = int((diffs != 0).sum())
        
        if col in top_controllers:
            features[f"{col}_entropy"] = calculate_entropy(series)

    # 4. Cross-Sensor Pairwise Features (Pearson Correlation & Covariance)
    # Compute correlation among top 6 sensors to detect deviation
    corr_sensors = top_sensors[:6]
    for i in range(len(corr_sensors)):
        for j in range(i + 1, len(corr_sensors)):
            s1 = corr_sensors[i]
            s2 = corr_sensors[j]
            
            val_corr = df[s1].corr(df[s2])
            val_cov = df[s1].cov(df[s2])
            
            features[f"cross_corr_{s1}_vs_{s2}"] = float(val_corr) if pd.notna(val_corr) else 0.0
            features[f"cross_cov_{s1}_vs_{s2}"] = float(val_cov) if pd.notna(val_cov) else 0.0

    return features
