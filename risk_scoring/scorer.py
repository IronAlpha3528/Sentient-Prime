import os

def calculate_execution_score(action_name: str, impact_level: str) -> float:
    """
    Execution Score = α(Containment Value) - β(Business Impact)
    Alpha = 0.6, Beta = 0.4
    Returns a score between 0.0 and 1.0. Higher is safer to execute.
    """
    alpha = 0.6
    beta = 0.4
    
    # Pre-defined base values for containment actions
    action_values = {
        "Isolate Host": 0.9,
        "Revoke Credential": 0.7,
        "Block IP": 0.8,
        "Kill Process": 0.6
    }
    
    # Map qualitative impact to quantitative penalty
    impact_values = {
        "None": 0.0,
        "Low": 0.2,
        "Medium": 0.5,
        "High": 0.8,
        "Critical": 1.0
    }
    
    containment_val = action_values.get(action_name, 0.5)
    impact_val = impact_values.get(impact_level, 0.5)
    
    # Calculate score
    score = (alpha * containment_val) - (beta * impact_val)
    
    # Normalize between 0 and 1
    return max(0.0, min(1.0, score))
