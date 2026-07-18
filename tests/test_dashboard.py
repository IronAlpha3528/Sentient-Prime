from dashboard.app import extract_techniques, incident_summaries, response_seconds


def test_dashboard_builds_incident_summary_and_response_time():
    entries = [
        {
            "timestamp": "2026-07-16T10:00:00+00:00",
            "event_type": "dry_run",
            "incident_id": "INC-42",
            "data": {},
        },
        {
            "timestamp": "2026-07-16T10:00:03+00:00",
            "event_type": "policy_decision",
            "incident_id": "INC-42",
            "data": {"decision": "AUTO"},
        },
        {
            "timestamp": "2026-07-16T10:00:05+00:00",
            "event_type": "monitor_outcome",
            "incident_id": "INC-42",
            "data": {"status": "RESOLVED", "technique": "T1059.001"},
        },
    ]

    summary = incident_summaries(entries)

    assert summary[0]["incident_id"] == "INC-42"
    assert summary[0]["decision"] == "AUTO"
    assert summary[0]["outcome"] == "RESOLVED"
    assert response_seconds(entries) == [5.0]
    assert extract_techniques(entries) == {"T1059.001": 1}
