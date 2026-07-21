import pytest
from sentinel_prime.soar.risk_scoring.scorer import calculate_execution_score
from sentinel_prime.soar.orchestrator.dry_run import simulate_action
from sentinel_prime.soar.orchestrator.policy_gate import evaluate

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
    """Test the canonical evaluate() gate that the dispatcher uses.

    The gate returns {"decision": "AUTO"} when confidence >= 0.75
    and blast_radius is not HIGH, and {"decision": "ESCALATE"} otherwise.
    """
    dry_run_pass = {"passes": True, "blast_radius": "Low"}
    dry_run_high_blast = {"passes": True, "blast_radius": "HIGH"}
    dry_run_fail = {"passes": False, "blast_radius": "Low"}

    # Case 1: High confidence, low blast radius → AUTO
    incident_pass = {"incident_id": "TEST-01", "confidence": 0.90, "risk_score": 40}
    res1 = evaluate(incident_pass, dry_run_pass)
    assert res1["decision"] == "AUTO"

    # Case 2: High blast radius → ESCALATE
    res2 = evaluate(incident_pass, dry_run_high_blast)
    assert res2["decision"] == "ESCALATE"
    assert "blast radius" in res2["reason"].lower()

    # Case 3: Confidence below threshold (0.50) → ESCALATE
    incident_low_conf = {"incident_id": "TEST-03", "confidence": 0.40, "risk_score": 40}
    res3 = evaluate(incident_low_conf, dry_run_pass)
    assert res3["decision"] == "ESCALATE"
    assert "confidence" in res3["reason"].lower()

    # Case 4: Dry run failed → ESCALATE
    res4 = evaluate(incident_pass, dry_run_fail)
    assert res4["decision"] == "ESCALATE"
    assert "dry run" in res4["reason"].lower()
