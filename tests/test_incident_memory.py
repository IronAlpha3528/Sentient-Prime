import pytest
import os
import json
import faiss
import tempfile
import sentinel_prime.ai.agents.rag.query as query
from sentinel_prime.ai.agents.rag.providers.historical_incident import HistoricalIncidentProvider
from sentinel_prime.core.context.context_builder import ContextBuilder
from sentinel_prime.core.graph.graph_manager import GraphManager

def test_incident_memory_crud_and_indexing(tmp_path):
    index_dir = str(tmp_path / "index")
    db_path = str(tmp_path / "historical_incidents_db.json")
    
    # 1. Initialize provider
    provider = HistoricalIncidentProvider(index_dir, db_path)
    assert len(provider._incidents) == 0
    
    # 2. Insert incident
    incident_data = {
        "incident_id": "INC-TEST-01",
        "timestamp": "2026-07-18T10:00:00Z",
        "attack_summary": "Brute force attack attempts on SSH logging services.",
        "timeline": ["Failed SSH logins recorded from external IP", "Alert escalates"],
        "evidence": [{"detector": "SSH", "risk_score": 0.85}],
        "affected_assets": ["server-01"],
        "attack_techniques": ["T1110"],
        "threat_groups": ["APT41"],
        "malware": ["Cobalt Strike"],
        "detection_scores": {"ssh": 0.9},
        "graph_snapshot": {},
        "unified_threat_score": 0.85,
        "confidence": 0.9,
        "soar_actions": ["Block IP address"],
        "containment_status": "Contained",
        "resolution": "IP blocked on perimeter firewall.",
        "recovery_time": "12 minutes",
        "lessons_learned": "Apply fail2ban rules to rate-limit SSH logins.",
        "tags": ["host", "ssh", "brute_force"],
        "version": "1.0",
        "references": []
    }
    
    provider.insert(incident_data)
    assert len(provider._incidents) == 1
    assert os.path.exists(db_path)
    assert os.path.exists(provider.index_path)
    
    # 3. Search and check values
    results = provider.search("SSH brute force logins", limit=1)
    assert len(results) == 1
    assert results[0]["incident_id"] == "INC-TEST-01"
    assert results[0]["lessons_learned"] == "Apply fail2ban rules to rate-limit SSH logins."
    
    # 4. Update incident
    updated_data = incident_data.copy()
    updated_data["resolved_threat"] = "APT41 Threat Actor Group"
    updated_data["lessons_learned"] = "Lessons updated."
    
    success = provider.update("INC-TEST-01", updated_data)
    assert success
    assert provider._incidents[0]["lessons_learned"] == "Lessons updated."
    
    # 5. Search with filters
    filtered_results = provider.search("SSH brute force logins", limit=1, filters={"tags": ["ssh"]})
    assert len(filtered_results) == 1
    
    non_matching_results = provider.search("SSH brute force logins", limit=1, filters={"tags": ["yara"]})
    assert len(non_matching_results) == 0
    
    # 6. Delete incident
    del_success = provider.delete("INC-TEST-01")
    assert del_success
    assert len(provider._incidents) == 0

def test_context_builder_integration(tmp_path, monkeypatch):
    index_dir = str(tmp_path / "index")
    db_path = str(tmp_path / "historical_incidents_db.json")
    
    # Setup test memory db
    incident_data = {
        "incident_id": "INC-TEST-02",
        "timestamp": "2026-07-18T10:00:00Z",
        "attack_summary": "Suspicious PowerShell base64 script execution",
        "timeline": ["Encoded script run by admin user"],
        "evidence": [],
        "affected_assets": ["workstation-01"],
        "attack_techniques": ["T1059.001"],
        "threat_groups": ["Lazarus"],
        "malware": [],
        "detection_scores": {},
        "graph_snapshot": {},
        "unified_threat_score": 0.7,
        "confidence": 0.8,
        "soar_actions": ["Isolate host"],
        "containment_status": "Contained",
        "resolution": "Host isolated via EDR.",
        "recovery_time": "5 minutes",
        "lessons_learned": "Enforce script execution policies.",
        "tags": ["powershell", "script"],
        "version": "1.0",
        "references": []
    }
    
    provider = HistoricalIncidentProvider(index_dir, db_path)
    provider.insert(incident_data)
    
    # Register historical provider into global query providers list
    monkeypatch.setitem(query._providers, "historical_incident", provider)
    monkeypatch.setattr(query, "_graph_config", {
        "enabled_providers": ["attack", "historical_incident"],
        "cache_ttl_seconds": 300,
        "max_documents": 5,
        "per_provider_limit": 2
    })
    
    with tempfile.TemporaryDirectory() as tmpdir:
        gm = GraphManager(storage_dir=tmpdir)
        gm.store.clear()
        
        # Setup mock nodes/edges in local Cyber Graph
        gm.store.add_node("USER:adm_aanoush", {"node_id": "USER:adm_aanoush", "entity_type": "USER", "display_name": "adm_aanoush", "risk_score": 0.5, "timestamp": "2026-07-18T10:00:00Z"})
        gm.store.add_node("HOST:WORKSTATION-X", {"node_id": "HOST:WORKSTATION-X", "entity_type": "HOST", "display_name": "WORKSTATION-X", "risk_score": 0.6, "timestamp": "2026-07-18T10:00:00Z"})
        gm.store.add_edge("USER:adm_aanoush", "HOST:WORKSTATION-X", {"type": "AUTHENTICATES_TO", "timestamp": "2026-07-18T10:00:00Z", "risk": 0.5, "source_detector": "IDENTITY", "metadata": {"top_reasons": ["PowerShell"]}})
        
        # Test builder
        builder = ContextBuilder(gm)
        
        context = builder.build_context("USER:adm_aanoush")
        
        # Verify context historical_incidents list populated (Step 9)
        assert len(context.historical_incidents) == 1
        assert context.historical_incidents[0]["incident_id"] == "INC-TEST-02"
        
        # Verify markdown serialization formats incidents (Step 9)
        md = context.to_markdown()
        assert "Historical Incidents Recall" in md
        assert "INC-TEST-02" in md
        assert "Enforce script execution policies" in md
