from sentinel_prime.core.telemetry.ledger import AuditLedger
from sentinel_prime.soar.orchestrator.dispatcher import SOARDispatcher


def test_dispatch_records_resolved_outcome(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    dispatcher = SOARDispatcher(ledger=ledger)

    result = dispatcher.dispatch(
        {
            "incident_id": "INC-1",
            "asset": "workstation-1",
            "confidence": 0.9,
            "attacker_ip": "203.0.113.10",
            "response_agent_plan": {
                "recommended_actions": [{"action_name": "Block Source IP"}]
            },
        }
    )

    assert result["decision"] == "AUTO"
    assert result["actions"] == [{"action": "block_ip", "status": "SUCCESS"}]
    assert result["outcome"]["status"] == "RESOLVED"
    assert ledger.verify_chain()


def test_dispatch_escalation_is_audited(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    dispatcher = SOARDispatcher(ledger=ledger)

    result = dispatcher.dispatch(
        {
            "incident_id": "INC-2",
            "asset": "Domain Controller",
            "confidence": 0.95,
            "response_agent_plan": {
                "recommended_actions": [{"action_name": "Block Source IP"}]
            },
        }
    )

    assert result["decision"] == "ESCALATE"
    assert result["outcome"]["status"] == "ESCALATED"
    assert ledger.verify_chain()


def test_ledger_detects_tampering(tmp_path):
    path = tmp_path / "audit.jsonl"
    ledger = AuditLedger(path)
    ledger.append_entry("decision", {"value": "AUTO"}, incident_id="INC-3")
    ledger.append_entry("outcome", {"status": "RESOLVED"}, incident_id="INC-3")

    tampered = path.read_text(encoding="utf-8").replace("RESOLVED", "PERSISTING")
    path.write_text(tampered, encoding="utf-8")

    assert not ledger.verify_chain()
