from sentinel_prime.soar.orchestrator.dispatcher import SOARDispatcher
import logging
logging.basicConfig(level=logging.INFO)

mock_incident = {
    "incident_id": "INC-TEST-123",
    "asset": "target-server-01",
    "attack_type": "lateral_movement",
    "deception_strategy": {
        "is_testable": True,
        "decoy_type": "db_credentials"
    },
    "response_agent_plan": {
        "recommended_actions": [
            {"action_name": "Isolate Host"}
        ]
    }
}

dispatcher = SOARDispatcher()
result = dispatcher.dispatch(mock_incident)
print("\nFinal SOAR Result:")
import json
print(json.dumps(result, indent=2))
