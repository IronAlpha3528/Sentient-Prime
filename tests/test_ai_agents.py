import pytest
import os
import json
from unittest.mock import patch
from sentinel_prime.core.config_manager import config

os.environ["GEMINI_API_KEY"] = "dummy_key"

class MockModels:
    def generate_content(self, model, contents, config=None):
        class MockResponse:
            def __init__(self, text):
                self.text = text
        
        schema = config.response_schema if config else None
        
        if schema and schema.__name__ == 'AnalysisResult':
            return MockResponse(json.dumps({
                "story": {
                    "summary": "Mock summary",
                    "timeline": ["event 1"],
                    "anomalies": ["anomaly 1"],
                    "cross_domain_links": ["link 1"]
                },
                "hypotheses": [
                    {
                        "title": "Mock Hypothesis",
                        "description": "desc",
                        "is_malicious": True,
                        "confidence": 0.8,
                        "supporting_evidence": ["ev"],
                        "mitre_techniques": ["T1001"]
                    }
                ],
                "prediction": {
                    "current_stage": "Execution",
                    "likely_next_technique": "T1059",
                    "predicted_target": "DB-01",
                    "candidate_attack_path": ["ENG-WS-01", "SERVER-07"],
                    "confidence": 0.9
                }
            }))
        elif schema and schema.__name__ == 'CritiqueResult':
            return MockResponse(json.dumps({
                "is_valid": True,
                "critique_feedback": "Looks good",
                "corrected_hypotheses": []
            }))
        elif schema and schema.__name__ == 'ActionPlan':
            return MockResponse(json.dumps({
                "recommended_actions": [
                    {
                        "action_name": "isolate_host",
                        "parameters": {"target": "SERVER-07"},
                        "reasoning": "High confidence ransomware"
                    }
                ]
            }))
        
        return MockResponse("{}")

class MockClient:
    def __init__(self, api_key=None):
        self.models = MockModels()

@patch('google.genai.Client', MockClient)
def test_analysis_agent():
    from sentinel_prime.ai.agents.analysis_agent import AnalysisAgent
    agent = AnalysisAgent()
    result = agent.run({"incident_id": "INC-102"})
    
    assert "story" in result
    assert result["story"]["summary"] == "Mock summary"
    assert len(result["hypotheses"]) > 0

@patch('google.genai.Client', MockClient)
def test_critique_agent():
    from sentinel_prime.ai.agents.critique_agent import CritiqueAgent
    agent = CritiqueAgent()
    result = agent.run({"hypotheses": []}, {"incident_id": "INC-102"})
    
    assert "is_valid" in result
    assert result["is_valid"] is True

@patch('google.genai.Client', MockClient)
def test_action_agent():
    from sentinel_prime.ai.agents.action_agent import ActionAgent
    agent = ActionAgent()
    result = agent.run({"hypotheses": []}, {"is_valid": True}, {"incident_id": "INC-102"})
    
    assert "recommended_actions" in result
    assert len(result["recommended_actions"]) > 0
    assert result["recommended_actions"][0]["action_name"] == "isolate_host"
