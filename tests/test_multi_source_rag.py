import pytest
import os
import networkx as nx
import sentinel_prime.ai.agents.rag.query as query
from sentinel_prime.ai.agents.rag.providers.generic import GenericProvider

def test_query_routing_rules():
    # Verify that query routing works according to keyword rules
    cve_routes = query.route_query("CVE-2023-38606 kernel exploit")
    assert "cve" in cve_routes
    assert "kev" in cve_routes

    d3fend_routes = query.route_query("Message authentication mitigation")
    assert "d3fend" in d3fend_routes

    sigma_routes = query.route_query("sysmon encoded powershell logs")
    assert "sigma" in sigma_routes

    yara_routes = query.route_query("yara signature for Cobalt Strike")
    assert "yara" in yara_routes

    playbook_routes = query.route_query("host isolation playbook")
    assert "playbook" in playbook_routes

    policy_routes = query.route_query("CNI containment policy guidelines")
    assert "policy" in policy_routes

    report_routes = query.route_query("APT41 threat report details")
    assert "threat_report" in report_routes

    general_routes = query.route_query("failed SSH login attempts")
    assert "attack" in general_routes or "sigma" in general_routes

def test_metadata_standardization_schema():
    # Verify that GenericProvider normalized data conforms to Step 7 schema
    tmp_index_dir = "tests/tmp_intel"
    os.makedirs(tmp_index_dir, exist_ok=True)
    
    import json
    mock_data = [
        {
            "id": "SIG-TEST",
            "name": "Test Sigma Rule",
            "description": "Used to test schema.",
            "entity_type": "detection_rule",
            "version": "1.0",
            "tags": ["test"],
            "references": ["http://ref.com"]
        }
    ]
    raw_path = os.path.join(tmp_index_dir, "test_sigma.json")
    with open(raw_path, "w") as f:
        json.dump(mock_data, f)
        
    prov = GenericProvider("test_sigma", tmp_index_dir)
    prov.ingest(raw_path)
    
    results = prov.search("test schema", limit=1)
    assert len(results) == 1
    r = results[0]
    
    # Standardized metadata fields (Step 7)
    assert r["source"] == "test_sigma"
    assert r["document_id"] == "SIG-TEST"
    assert r["title"] == "Test Sigma Rule"
    assert r["description"] == "Used to test schema."
    assert r["entity_type"] == "detection_rule"
    assert r["confidence"] == 1.0
    assert r["version"] == "1.0"
    assert "created_at" in r
    assert "updated_at" in r
    assert r["tags"] == ["test"]
    assert r["references"] == ["http://ref.com"]
    assert "citation" in r
    
    # Backward compatible fields (Step 10)
    assert r["technique_id"] == "SIG-TEST"
    assert r["name"] == "Test Sigma Rule"
    assert "distance" in r
    assert "score" in r
    
    # Cleanup
    try:
        os.remove(raw_path)
        os.remove(prov.index_path)
        os.remove(prov.chunks_path)
        os.rmdir(tmp_index_dir)
    except:
        pass

def test_result_fusion_and_deduplication():
    # Verify merge and deduplicate
    mock_results = [
        {"source": "sigma", "document_id": "SIG-001", "similarity_score": 1.2, "title": "A"},
        {"source": "sigma", "document_id": "SIG-001", "similarity_score": 1.5, "title": "B"}, # Duplicate
        {"source": "yara", "document_id": "YARA-001", "similarity_score": 0.8, "title": "C"}
    ]
    
    merged = query.merge_and_deduplicate(mock_results)
    assert len(merged) == 2
    # Verify sorted order (lower score first)
    assert merged[0]["document_id"] == "YARA-001"
    assert merged[1]["document_id"] == "SIG-001"

def test_failure_recovery_on_unavailable_provider(monkeypatch):
    # Verify that a provider failure does not crash orchestrator search
    monkeypatch.setattr(query, "_providers", {"broken": None})
    monkeypatch.setattr(query, "_graph_config", {"enabled_providers": ["broken", "attack"]})
    
    # Should not raise exception
    res = query.search("ssh logins", enabled_providers=["broken", "attack"], top_k=1)
    assert isinstance(res, list)
