import json
from typing import Dict, Any

from .hypothesis_agent import generate_hypotheses
from .apt_attribution import attribute_and_predict
from sentinel_prime.soar.risk_scoring.scorer import score_and_rank_actions

def run_pipeline(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """
    Entry point for the AI Reasoning Core.
    Takes a Common Evidence Object and returns a fully structured AI decision.
    """
    print(f"--- Starting AI Reasoning Pipeline for Incident {evidence.get('incident_id', 'UNKNOWN')} ---")
    
    # Block 1: Hypothesis Generation
    print("[Block 1] Generating hypotheses...")
    hypotheses = generate_hypotheses(evidence)
    
    # Filter for the most likely malicious hypothesis
    # We always ensure at least one benign exists, so we sort by confidence.
    top_hypothesis = None
    for h in sorted(hypotheses, key=lambda x: x.get("confidence", 0), reverse=True):
        if not h.get("is_benign"):
            top_hypothesis = h
            break
            
    # If all were benign, just take the highest confidence one
    if not top_hypothesis and hypotheses:
        top_hypothesis = max(hypotheses, key=lambda x: x.get("confidence", 0))
        
    if not top_hypothesis:
        return {"error": "Failed to generate any hypotheses"}

    # Block 2: Attribution and Prediction
    print("[Block 2] Attributing APT and predicting next steps...")
    attribution_data = attribute_and_predict(top_hypothesis, evidence)
    
    # Block 3: Risk Scoring and Routing
    print("[Block 3] Scoring risk and planning response...")
    scoring_data = score_and_rank_actions(top_hypothesis, attribution_data)
    
    # Combine final output
    final_output = {
        "incident_id": evidence.get("incident_id"),
        "original_evidence": evidence,
        "hypotheses": hypotheses,
        "top_hypothesis_selected": top_hypothesis,
        "attribution_and_prediction": attribution_data,
        "response_plan": scoring_data
    }
    
    print("--- Pipeline Complete ---")
    return final_output

if __name__ == "__main__":
    # Simulate a pipeline run with the 5-step attack chain mock data
    mock_evidence = {
      "incident_id": "INC-999",
      "entities": {
        "users": ["admin"],
        "hosts": ["app_server"],
        "ips": ["192.168.1.105"]
      },
      "target_asset": "app_server",
      "network": {"score": 0.87, "class": "brute_force"},
      "endpoint": {"score": 0.95, "sigma_matches": ["Multiple Failed Logins"]}
    }
    
    import os
    if os.environ.get("GEMINI_API_KEY"):
        print("Running end-to-end pipeline test...")
        result = run_pipeline(mock_evidence)
        print("\nFinal Output JSON:")
        print(json.dumps(result, indent=2))
    else:
        print("Set GEMINI_API_KEY to test the full pipeline.")
