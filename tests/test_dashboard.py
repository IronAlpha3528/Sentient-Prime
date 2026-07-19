import pytest
import json
from dashboard.api_server import app, _incidents_from_ledger, _score_from_entries, _status_from_entries

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_api_health(client):
    response = client.get('/api/health')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["status"] == "ok"

def test_status_from_entries():
    entries = [
        {"event_type": "detection", "data": {"score": 0.5}},
        {"event_type": "policy_decision", "data": {"decision": "ESCALATE"}},
    ]
    assert _status_from_entries(entries) == "ESCALATED"

    entries2 = [
        {"event_type": "monitor_outcome", "data": {"status": "RESOLVED"}},
    ]
    assert _status_from_entries(entries2) == "RESOLVED"

def test_score_from_entries():
    entries = [
        {"data": {"unified_threat_score": 0.85}},
    ]
    assert _score_from_entries(entries) == 0.85

    entries2 = [
        {"data": {"risk_score": 90}}, # > 1, so should be divided by 100
    ]
    assert _score_from_entries(entries2) == 0.90
