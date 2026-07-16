from pathlib import Path

import yaml


RISK_PARAMS_PATH = Path(__file__).resolve().parents[4] / "config" / "risk_params.yaml"

def load_risk_config() -> dict:
    """Loads risk parameters and action library from config."""
    with RISK_PARAMS_PATH.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def score_and_rank_actions(top_hypothesis: dict, attribution_data: dict) -> dict:
    """
    Block 3: Scores response actions using math formula and determines routing.
    Formula: Score = (alpha * Containment) - (beta * Business_impact)
    """
    config = load_risk_config()
    alpha = config["weights"]["alpha"]
    beta = config["weights"]["beta"]
    
    blast_radius = attribution_data.get("blast_radius", {})
    blast_score = blast_radius.get("score", 0)
    reaches_ot = blast_radius.get("reaches_ot", False)
    
    confidence = top_hypothesis.get("confidence", 0.0)
    
    ranked_actions = []
    
    for action in config.get("actions", []):
        containment = action["containment"]
        impact = action["business_impact"]
        
        # Dynamic Adjustments based on Master Context Document rules
        if blast_score > 10 and action["id"] == "isolate_endpoint":
            # Attacker already spread, isolating one endpoint is less effective
            containment *= 0.6
            
        if confidence > 0.7 and blast_score > 10:
            containment *= 0.8
            
        # Calculate final score
        score = (alpha * containment) - (beta * impact)
        
        ranked_actions.append({
            "action_id": action["id"],
            "name": action["name"],
            "score": round(score, 4),
            "containment_used": round(containment, 4),
            "business_impact": impact
        })
        
    # Sort actions by score descending
    ranked_actions.sort(key=lambda x: x["score"], reverse=True)
    
    # Routing Logic
    # confidence >= 0.75 AND blast_score < 15 AND reaches_ot = false -> SOAR
    thresholds = config.get("routing", {})
    soar_conf = thresholds.get("soar_confidence_threshold", 0.75)
    soar_blast = thresholds.get("soar_blast_score_max", 15)
    
    route_to_soar = False
    if confidence >= soar_conf and blast_score < soar_blast and not reaches_ot:
        route_to_soar = True
        
    mandatory_parallel = []
    if reaches_ot:
        mandatory_parallel = [
            "snapshot_all_ot_assets",
            "alert_physical_security"
        ]
        
    return {
        "ranked_actions": ranked_actions,
        "route_to_soar": route_to_soar,
        "mandatory_parallel_actions": mandatory_parallel,
        "reasoning": f"Confidence={confidence}, BlastScore={blast_score}, ReachesOT={reaches_ot}"
    }

def calculate_execution_score(action_name: str, impact_level: str) -> float:
    """
    Helper function used by tests to compute the execution score for a given action and impact level.
    Formula: Score = (alpha * Containment) - (beta * Business_impact)
    Where alpha = 0.6, beta = 0.4.
    """
    containment_map = {
        "Isolate Host": 0.9,
        "Revoke Credential": 0.75,
        "Block IP/Domain": 0.55,
        "Snapshot VM": 0.10,
        "Monitor only": 0.05
    }
    impact_map = {
        "Low": 0.2,
        "Medium": 0.4,
        "High": 0.6,
        "Critical": 1.0
    }
    containment = containment_map.get(action_name, 0.0)
    impact = impact_map.get(impact_level, 0.0)
    return 0.6 * containment - 0.4 * impact

if __name__ == "__main__":
    # Test Block 3
    mock_hypo = {"confidence": 0.8}
    mock_attr = {
        "blast_radius": {
            "score": 12,
            "reaches_ot": False
        }
    }
    print("Testing Risk Scorer...")
    result = score_and_rank_actions(mock_hypo, mock_attr)
    import json
    print(json.dumps(result, indent=2))
