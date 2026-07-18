import os
import tempfile
import pickle
import pytest
import networkx as nx
import sentinel_prime.ai.agents.rag.query as query
from sentinel_prime.ai.agents.rag.build_index import parse_attack_data

# Mock STIX 2.1 data for parsing tests
MOCK_STIX_DATA = {
    "objects": [
        {
            "id": "attack-pattern--t1110",
            "type": "attack-pattern",
            "name": "Brute Force",
            "description": "Adversaries may use brute force to gain access.",
            "x_mitre_platforms": ["Windows", "Linux"],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}],
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1110"}
            ]
        },
        {
            "id": "attack-pattern--t1110-001",
            "type": "attack-pattern",
            "name": "Password Guessing",
            "description": "Guessing passwords.",
            "x_mitre_is_subtechnique": True,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1110.001"}
            ]
        },
        {
            "id": "intrusion-set--g0096",
            "type": "intrusion-set",
            "name": "APT41",
            "description": "APT41 is a threat group.",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "G0096"}
            ]
        },
        {
            "id": "malware--s0154",
            "type": "malware",
            "name": "Cobalt Strike",
            "description": "Cobalt Strike is a platform.",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "S0154"}
            ]
        },
        {
            "id": "course-of-action--m1036",
            "type": "course-of-action",
            "name": "Account Use Policies",
            "description": "Mitigate brute force.",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "M1036"}
            ]
        },
        {
            "id": "relationship--rel1",
            "type": "relationship",
            "relationship_type": "uses",
            "source_ref": "intrusion-set--g0096",
            "target_ref": "attack-pattern--t1110"
        },
        {
            "id": "relationship--rel2",
            "type": "relationship",
            "relationship_type": "uses",
            "source_ref": "malware--s0154",
            "target_ref": "attack-pattern--t1110"
        },
        {
            "id": "relationship--rel3",
            "type": "relationship",
            "relationship_type": "mitigates",
            "source_ref": "course-of-action--m1036",
            "target_ref": "attack-pattern--t1110"
        },
        {
            "id": "relationship--rel4",
            "type": "relationship",
            "relationship_type": "subtechnique-of",
            "source_ref": "attack-pattern--t1110-001",
            "target_ref": "attack-pattern--t1110"
        }
    ]
}

@pytest.fixture
def mock_attack_json(tmp_path):
    import json
    p = tmp_path / "enterprise-attack.json"
    with open(p, "w", encoding="utf-8") as f:
        json.dump(MOCK_STIX_DATA, f)
    return str(p)

def test_stix_parsing_and_graph_build(mock_attack_json, monkeypatch):
    # Set the package constants to point to our mock file
    import sentinel_prime.ai.agents.rag.build_index as build_index
    monkeypatch.setattr(build_index, "ATTACK_JSON_PATH", mock_attack_json)
    
    techniques, G = parse_attack_data()
    
    # Assertions on techniques extracted
    assert len(techniques) == 2
    assert techniques[0]["technique_id"] == "T1110"
    assert techniques[1]["technique_id"] == "T1110.001"
    
    # Assertions on graph attributes
    assert G.number_of_nodes() == 5
    assert G.number_of_edges() == 4
    
    # Check node properties
    t_attrs = G.nodes["attack-pattern--t1110"]
    assert t_attrs["external_id"] == "T1110"
    assert t_attrs["type"] == "technique"
    assert t_attrs["platforms"] == ["Windows", "Linux"]
    assert t_attrs["phase_names"] == ["credential-access"]
    
    sub_attrs = G.nodes["attack-pattern--t1110-001"]
    assert sub_attrs["type"] == "sub-technique"
    
    g_attrs = G.nodes["intrusion-set--g0096"]
    assert g_attrs["type"] == "group"
    assert g_attrs["name"] == "APT41"
    
    m_attrs = G.nodes["course-of-action--m1036"]
    assert m_attrs["type"] == "mitigation"
    
    # Check edges
    assert G.has_edge("intrusion-set--g0096", "attack-pattern--t1110")
    assert G.edges["intrusion-set--g0096", "attack-pattern--t1110"]["relationship_type"] == "uses"
    assert G.has_edge("attack-pattern--t1110-001", "attack-pattern--t1110")
    assert G.edges["attack-pattern--t1110-001", "attack-pattern--t1110"]["relationship_type"] == "subtechnique-of"

def test_graph_traversal_engine():
    # Build a small manual graph
    G = nx.DiGraph()
    G.add_node("T1", type="technique", external_id="T1110", name="Brute Force")
    G.add_node("G1", type="group", external_id="G0096", name="APT41")
    G.add_node("M1", type="mitigation", external_id="M1036", name="Policy")
    G.add_node("S1", type="malware", external_id="S0154", name="Cobalt Strike")
    G.add_node("T1_001", type="sub-technique", external_id="T1110.001", name="Guesser")
    
    G.add_edge("G1", "T1", relationship_type="uses")
    G.add_edge("S1", "T1", relationship_type="uses")
    G.add_edge("M1", "T1", relationship_type="mitigates")
    G.add_edge("T1_001", "T1", relationship_type="subtechnique-of")
    
    # Inject into query module
    query._graph = G
    
    # Test traversal starting from T1
    expanded = query.traverse_and_expand_technique("T1", max_depth=2)
    
    assert len(expanded["groups"]) == 1
    assert expanded["groups"][0]["name"] == "APT41"
    assert expanded["groups"][0]["id"] == "G0096"
    assert expanded["groups"][0]["graph_depth"] == 1
    
    assert len(expanded["software"]) == 1
    assert expanded["software"][0]["name"] == "Cobalt Strike"
    
    assert len(expanded["mitigations"]) == 1
    assert expanded["mitigations"][0]["name"] == "Policy"
    
    assert len(expanded["subtechniques"]) == 1
    assert expanded["subtechniques"][0]["name"] == "Guesser"
    
    # Check relationship source extraction
    assert expanded["groups"][0]["relationship_source"] == "reverse-uses"
    assert expanded["software"][0]["relationship_source"] == "reverse-uses"
    assert expanded["mitigations"][0]["relationship_source"] == "reverse-mitigates"
    assert expanded["subtechniques"][0]["relationship_source"] == "reverse-subtechnique-of"

def test_query_search_graphrag_enrichment(monkeypatch):
    # Setup mock FAISS and metadata chunks
    class MockIndex:
        def search(self, query_vector, k):
            import numpy as np
            # Return indices [0] and distance [1.5]
            return np.array([[1.5]]), np.array([[0]])
            
    mock_metadata = [
        {
            "technique_id": "T1110",
            "name": "Brute Force",
            "description": "Original Description text."
        }
    ]
    
    class MockModel:
        def encode(self, texts):
            import numpy as np
            return np.array([[0.1] * 384])
            
    # Mock resources loading
    monkeypatch.setattr(query, "_index", MockIndex())
    monkeypatch.setattr(query, "_metadata", mock_metadata)
    monkeypatch.setattr(query, "_model", MockModel())
    
    # Setup NetworkX graph
    G = nx.DiGraph()
    G.add_node("attack-pattern--t1110", type="technique", external_id="T1110", name="Brute Force", description="Original Description text.")
    G.add_node("intrusion-set--g1", type="group", external_id="G0096", name="APT41", description="Group description")
    G.add_edge("intrusion-set--g1", "attack-pattern--t1110", relationship_type="uses")
    
    monkeypatch.setattr(query, "_graph", G)
    monkeypatch.setattr(query, "_ext_to_stix_cache", None)
    
    # Run backward-compatible search
    results = query.search("ssh failures", top_k=1, enable_expansion=True, traversal_depth=2)
    
    # Check structure
    assert isinstance(results, list)
    assert len(results) == 1
    res = results[0]
    
    assert res["technique_id"] == "T1110"
    assert res["distance"] == 1.5
    assert res["score"] == 1.5
    assert res["entity_type"] == "technique"
    assert res["graph_depth"] == 0
    assert res["confidence"] == 0.85
    
    # Verify metadata arrays populated
    assert len(res["connected_groups"]) == 1
    assert res["connected_groups"][0]["name"] == "APT41"
    
    # Verify description enrichment with markdown GraphRAG section
    assert "### ATT&CK GraphRAG Enrichment" in res["description"]
    assert "* **Threat Groups**: [G0096] APT41" in res["description"]
    
    # Test extended API return (include_graph_details=True)
    extended_results = query.search("ssh failures", top_k=1, include_graph_details=True, enable_expansion=True)
    
    assert isinstance(extended_results, dict)
    assert "results" in extended_results
    assert "connected_entities" in extended_results
    assert "traversal_explanation" in extended_results
    assert "traversal_paths" in extended_results
    assert "graph" in extended_results
    
    assert len(extended_results["results"]) == 1
    assert extended_results["connected_entities"][0]["name"] == "APT41"
    assert "points to: 1 group(s)" in extended_results["traversal_explanation"]
    assert extended_results["graph"]["nodes"] != []
