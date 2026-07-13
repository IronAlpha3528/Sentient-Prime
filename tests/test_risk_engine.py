import pytest
from sentinel_prime.soar.risk_scoring.scorer import calculate_execution_score
from sentinel_prime.soar.orchestrator.dry_run import simulate_action
from sentinel_prime.soar.orchestrator.policy_gate import evaluate_policy

def test_calculate_execution_score():
    # Isolate Host (0.9) with Low Impact (0.2)
    # Score = 0.6*0.9 - 0.4*0.2 = 0.54 - 0.08 = 0.46
    score = calculate_execution_score("Isolate Host", "Low")
    assert round(score, 2) == 0.46
    
    # Isolate Host (0.9) with Critical Impact (1.0)
    # Score = 0.6*0.9 - 0.4*1.0 = 0.54 - 0.4 = 0.14
    score2 = calculate_execution_score("Isolate Host", "Critical")
    assert score2 < score

def test_dry_run_simulation():
    graph = {
        "ENG-WS-01": [],
        "DB-SERVER": ["APP-SRV-1", "APP-SRV-2", "WEB-FRONT", "REPORTING"]
    }
    
    # Target an endpoint with no downstream dependencies
    res_low = simulate_action("Isolate Host", "ENG-WS-01", graph)
    assert res_low["simulated_impact_level"] == "Low"
    assert res_low["blast_radius_nodes"] == 0
    
    # Target a critical DB with 4 dependents
    res_high = simulate_action("Isolate Host", "DB-SERVER", graph)
    assert res_high["simulated_impact_level"] == "High"
    assert res_high["blast_radius_nodes"] == 4

def test_policy_gate():
    # Rule: Confidence > 0.85 AND Impact == "Low"
    
    # Case 1: Pass
    res1 = evaluate_policy(0.90, 0.46, "Low")
    assert res1["status"] == "AUTO_EXECUTE"
    
    # Case 2: Fail due to Impact
    res2 = evaluate_policy(0.95, 0.14, "Critical")
    assert res2["status"] == "HUMAN_APPROVAL"
    assert "must be 'Low'" in res2["reason"]
    
    # Case 3: Fail due to Confidence
    res3 = evaluate_policy(0.80, 0.46, "Low")
    assert res3["status"] == "HUMAN_APPROVAL"
    assert "too low" in res3["reason"]
