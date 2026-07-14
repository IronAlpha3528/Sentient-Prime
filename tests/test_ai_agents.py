import pytest
import os
import json
from unittest.mock import patch

class MockModels:
    def generate_content(self, model, contents, config=None):
        class MockResponse:
            def __init__(self, text):
                self.text = text
        
        # Determine which mock JSON to return based on the response_schema
        schema = config.response_schema if config else None
        
        if schema and schema.__name__ == 'IncidentStory':
            return MockResponse(json.dumps({
                "summary": "Mock summary",
                "timeline": ["event 1"],
                "anomalies": ["anomaly 1"],
                "cross_domain_links": ["link 1"]
            }))
        elif schema and schema.__name__ == 'HypothesisList':
            return MockResponse(json.dumps({
                "hypotheses": [
                    {
                        "title": "Mock Hypothesis",
                        "description": "desc",
                        "is_malicious": True,
                        "confidence": 0.8,
                        "supporting_evidence": ["ev"],
                        "mitre_techniques": ["T1001"]
                    }
                ]
            }))
        elif schema and schema.__name__ == 'AttackPrediction':
            return MockResponse(json.dumps({
                "current_stage": "Execution",
                "likely_next_technique": "T1059",
                "predicted_target": "DB-01",
                "candidate_attack_path": ["ENG-WS-01", "SERVER-07"],
                "confidence": 0.9
            }))
        elif schema and schema.__name__ == 'DeceptionStrategy':
            return MockResponse(json.dumps({
                "is_testable": True,
                "hypothesis_to_test": "Lateral Movement",
                "predicted_attacker_action": "SMB Enumeration",
                "decoy_type": "fake_smb_share",
                "placement_location": "SERVER-07",
                "observation_window_minutes": 30
            }))
        elif schema and schema.__name__ == 'ResponsePlan':
            return MockResponse(json.dumps({
                "recommended_actions": [
                    {
                        "action_name": "Isolate Host",
                        "reasoning": "High confidence ransomware",
                        "expected_impact": "Host offline",
                        "mitre_mitigation_id": "M1033"
                    }
                ]
            }))
        
        return MockResponse("{}")

class MockClient:
    def __init__(self, api_key=None):
        self.models = MockModels()

@patch('google.genai.Client', MockClient)
@patch.dict(os.environ, {"GEMINI_API_KEY": "dummy_key"})
def test_correlation_agent():
    from sentinel_prime.ai.agents.correlation_agent import CorrelationAgent
    agent = CorrelationAgent()
    result = agent.run("INC-102")
    
    assert "summary" in result
    assert result["summary"] == "Mock summary"

@patch('google.genai.Client', MockClient)
@patch.dict(os.environ, {"GEMINI_API_KEY": "dummy_key"})
def test_hypothesis_agent():
    from sentinel_prime.ai.agents.hypothesis_agent import HypothesisAgent
    agent = HypothesisAgent()
    result = agent.run({"summary": "test"})
    
    assert "hypotheses" in result
    assert len(result["hypotheses"]) > 0

@patch('google.genai.Client', MockClient)
@patch.dict(os.environ, {"GEMINI_API_KEY": "dummy_key"})
def test_prediction_agent():
    from sentinel_prime.ai.agents.prediction_agent import PredictionAgent
    agent = PredictionAgent()
    result = agent.run({"hypotheses": []})
    
    assert "likely_next_technique" in result

@patch('google.genai.Client', MockClient)
@patch.dict(os.environ, {"GEMINI_API_KEY": "dummy_key"})
def test_deception_agent():
    from sentinel_prime.ai.agents.deception_agent import DeceptionAgent
    agent = DeceptionAgent()
    result = agent.run({"hypotheses": []}, {"prediction": "test"}, {"graph": "test"})
    
    assert result["is_testable"] is True
    assert result["decoy_type"] == "fake_smb_share"

@patch('google.genai.Client', MockClient)
@patch.dict(os.environ, {"GEMINI_API_KEY": "dummy_key"})
def test_response_agent():
    from sentinel_prime.ai.agents.response_agent import ResponseAgent
    agent = ResponseAgent()
    result = agent.run({"hypotheses": []}, {"prediction": "test"}, {"criticality": "high"})
    
    assert "recommended_actions" in result
    assert len(result["recommended_actions"]) > 0

