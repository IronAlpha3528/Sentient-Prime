import logging
from typing import Dict, Any, List, Optional
from sentinel_prime.detection.detectors.ot.ot_evidence import OTEvidence

logger = logging.getLogger(__name__)

def generate_ot_reasons(features: Dict[str, Any], risk_score: float) -> List[str]:
    reasons = []

    # Heuristic rules from feature values
    for k, val in features.items():
        if k.endswith("_flatline_duration") and val > 45:
            sensor_name = k.replace("_flatline_duration", "").replace("sensor_", "")
            reasons.append(f"Sensor flatline detected: {sensor_name} remained constant for {int(val)}s")
        if k.endswith("_oscillation_count") and val > 15:
            sensor_name = k.replace("_oscillation_count", "").replace("sensor_", "")
            reasons.append(f"Unexpected process oscillation detected for sensor: {sensor_name}")
        if k.endswith("_rate_of_change"):
            sensor_name = k.replace("_rate_of_change", "").replace("sensor_", "")
            if val > 5.0:
                reasons.append(f"Rapid value increase observed for sensor: {sensor_name}")
            elif val < -5.0:
                reasons.append(f"Rapid value decrease observed for sensor: {sensor_name}")
        if k.startswith("cross_corr_") and val < 0.35 and val != 0.0:
            pair = k.replace("cross_corr_sensor_", "").replace("sensor_", "")
            reasons.append(f"Cross-sensor correlation dropped for pair: {pair}")
        if k.endswith("_state_changes") and val == 0:
            act_name = k.replace("_state_changes", "").replace("actuator_", "")
            # Only add if it's a key actuator showing flat behavior in anomalous window
            if risk_score >= 0.70 and "fcv" in act_name.lower():
                reasons.append(f"Control loop state locked: actuator {act_name} failed to transition")

    if risk_score >= 0.75:
        reasons.append("Window deviates strongly from historical normal industrial baseline")
        
    return list(set(reasons))

def generate_top_shifted_variables(
    features: Dict[str, Any],
    baseline_stats: Dict[str, Dict[str, float]],
    top_n: int = 5
) -> List[str]:
    """
    Identifies the top N variables that show the largest standard deviation shift from normal.
    """
    deviations = []
    for k, val in features.items():
        # Only check root variables (excluding mean, std, zero_crossings derivatives)
        if not (k.startswith("sensor_") or k.startswith("actuator_") or k.startswith("controller_")):
            continue
        # Check base values (we check the mean value feature of the sensor)
        if not k.endswith("_mean"):
            continue
            
        base_var = k.replace("_mean", "")
        
        if base_var in baseline_stats:
            mean = baseline_stats[base_var].get("mean", 0.0)
            std = baseline_stats[base_var].get("std", 1.0)
            std = std if std > 0 else 1.0
            dev = abs(val - mean) / std
            deviations.append((base_var, dev))
        else:
            # Fallback if no stats: check absolute range of the variable
            range_key = f"{base_var}_range"
            if range_key in features:
                deviations.append((base_var, abs(features[range_key])))

    # Sort descending by shift magnitude
    deviations.sort(key=lambda x: x[1], reverse=True)
    
    # Return cleaned variable names (e.g. sensor_P1_PV01 -> P1_PV01)
    clean_vars = []
    for var, _ in deviations[:top_n]:
        clean_name = var.replace("sensor_", "").replace("actuator_", "").replace("controller_", "")
        clean_vars.append(clean_name)
        
    return clean_vars

class OTEvidenceGenerator:
    def __init__(self, baseline_stats: Optional[Dict[str, Dict[str, float]]] = None):
        self.baseline_stats = baseline_stats or {}

    def create_evidence(
        self,
        anomaly_score: float,
        attack_probability: float,
        severity: str,
        features: Dict[str, Any],
        window_metadata: Dict[str, Any]
    ) -> OTEvidence:
        """
        Fuses predictions and metadata into an OTEvidence block.
        """
        # Calculate composite risk score (neither source dominates)
        # If supervised probability is available, combine them. Otherwise use anomaly score.
        if attack_probability > 0:
            risk_score = 0.6 * anomaly_score + 0.4 * attack_probability
        else:
            risk_score = anomaly_score

        # Identify shifted sensors
        shifted_vars = generate_top_shifted_variables(features, self.baseline_stats, top_n=5)
        
        # Generate explanations
        reasons = generate_ot_reasons(features, risk_score)
        
        summary = f"Industrial process anomaly score = {anomaly_score:.2f} ({severity} severity)."
        if shifted_vars:
            summary += f" Top shifted variables: {', '.join(shifted_vars)}."

        return OTEvidence(
            detector="ot",
            entity=window_metadata.get("host", "CNI-Process-PLC"),
            timestamp=window_metadata.get("end_time"),
            window_start=window_metadata.get("start_time"),
            window_end=window_metadata.get("end_time"),
            risk_score=risk_score,
            confidence=0.85 if severity in ["HIGH", "CRITICAL"] else 0.65,
            severity=severity,
            anomaly_score=anomaly_score,
            attack_probability=attack_probability,
            top_shifted_variables=shifted_vars,
            behaviour_summary=summary,
            top_reasons=reasons,
            raw_prediction=anomaly_score
        )
