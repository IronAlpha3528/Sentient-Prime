def evaluate_policy(ai_confidence: float, execution_score: float, simulated_impact: str) -> dict:
    """
    Strict Deterministic Rules Engine.
    Rules: 
    - Auto-Execute ONLY IF AI Confidence > 0.85 AND Business Impact == "Low".
    - Anything else requires Human Approval.
    """
    if ai_confidence > 0.85 and simulated_impact == "Low":
        return {
            "status": "AUTO_EXECUTE",
            "reason": f"Authorized. Confidence ({ai_confidence}) > 0.85 and Impact is Low."
        }
    else:
        reasons = []
        if ai_confidence <= 0.85:
            reasons.append(f"AI Confidence ({ai_confidence}) is too low (requires > 0.85).")
        if simulated_impact != "Low":
            reasons.append(f"Simulated Impact is '{simulated_impact}' (must be 'Low' for auto-execution).")
            
        return {
            "status": "HUMAN_APPROVAL",
            "reason": " ".join(reasons)
        }
