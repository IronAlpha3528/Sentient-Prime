import json
import logging
from pathlib import Path
from typing import Dict, Any

logger = logging.getLogger(__name__)

def resolve_description(name: str) -> str:
    """
    Heuristically generates descriptions for behavioral features based on naming conventions.
    """
    if name.endswith("_mean"):
        return f"Rolling mean value for {name.replace('_mean', '')} over the window"
    elif name.endswith("_std"):
        return f"Rolling standard deviation for {name.replace('_std', '')} over the window"
    elif name.endswith("_min"):
        return f"Minimum value for {name.replace('_min', '')} observed in the window"
    elif name.endswith("_max"):
        return f"Maximum value for {name.replace('_max', '')} observed in the window"
    elif name.endswith("_range"):
        return f"Peak-to-peak amplitude range for {name.replace('_range', '')}"
    elif name.endswith("_median"):
        return f"Median value for {name.replace('_median', '')}"
    elif name.endswith("_variance"):
        return f"Variance of {name.replace('_variance', '')} within the window"
    elif name.endswith("_iqr"):
        return f"Interquartile Range of {name.replace('_iqr', '')}"
    elif name.endswith("_cv"):
        return f"Coefficient of variation for {name.replace('_cv', '')}"
    elif name.endswith("_energy"):
        return f"Signal energy (sum of squares) for {name.replace('_energy', '')}"
    elif name.endswith("_entropy"):
        return f"Shannon entropy of {name.replace('_entropy', '')} based on 10-bin histogram"
    elif name.endswith("_first_diff_mean"):
        return f"Average absolute first difference of {name.replace('_first_diff_mean', '')}"
    elif name.endswith("_rate_of_change"):
        return f"Rate of change slope estimation for {name.replace('_rate_of_change', '')}"
    elif name.endswith("_zero_crossings"):
        return f"Number of times {name.replace('_zero_crossings', '')} crossed its window mean"
    elif name.endswith("_flatline_duration"):
        return f"Maximum duration in seconds where {name.replace('_flatline_duration', '')} remained unchanged"
    elif name.endswith("_oscillation_count"):
        return f"Number of local extrema peaks for {name.replace('_oscillation_count', '')}"
    elif name.endswith("_state_changes"):
        return f"Number of transitions or state changes for actuator {name.replace('_state_changes', '')}"
    elif name.endswith("_transition_rate"):
        return f"Transition rate per second for actuator {name.replace('_transition_rate', '')}"
    elif name.endswith("_max_state_duration"):
        return f"Max continuous time spent in a single state for actuator {name.replace('_max_state_duration', '')}"
    elif name.endswith("_change_count"):
        return f"Count of controller state updates for {name.replace('_change_count', '')}"
    elif name.startswith("cross_corr_"):
        return f"Pairwise Pearson correlation coefficient between two sensors: {name.replace('cross_corr_', '')}"
    elif name.startswith("cross_cov_"):
        return f"Covariance relationship between two sensors: {name.replace('cross_cov_', '')}"
    return f"Behavioral statistical indicator for {name}"

def generate_feature_contract(sample_features: Dict[str, Any], output_path: str) -> Dict[str, Any]:
    """
    Compiles and writes the feature contract definition to a JSON schema.
    """
    contract = {}
    
    # Exclude metadata identifier fields
    exclude_keys = ["window_id", "start_time", "end_time", "host", "attack_label", "attack_ratio"]
    
    for key, val in sample_features.items():
        if key in exclude_keys:
            continue
            
        dtype_str = "float64"
        if isinstance(val, int):
            dtype_str = "int64"
        elif isinstance(val, bool):
            dtype_str = "bool"
            
        contract[key] = {
            "dtype": dtype_str,
            "description": resolve_description(key),
            "normalization": "none",
            "allowed_null": False
        }
        
    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(contract, f, indent=2)
        
    logger.info(f"Feature contract with {len(contract)} columns saved to {output_path}")
    return contract
