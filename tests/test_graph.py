import os
import tempfile
import pytest
from sentinel_prime.core.evidence import NetworkEvidence, OTEvidence, EvidenceEvent, EventPriority, EventStatus
from sentinel_prime.core.graph.graph_manager import GraphManager
from sentinel_prime.core.graph.graph_schema import NodeType, EdgeType

def test_node_edge_creation_and_merge():
    # Fresh GraphManager
    with tempfile.TemporaryDirectory() as tmpdir:
        gm = GraphManager(storage_dir=tmpdir)
        gm.store.clear()

        # Generate mock events
        net_ev = NetworkEvidence(
            detector="NETWORK",
            entity="192.168.1.1",
            entity_type="HOST",
            timestamp="2026-07-13T19:00:00+00:00",
            window_start="2026-07-13T19:00:00+00:00",
            window_end="2026-07-13T19:10:00+00:00",
            confidence=0.9,
            risk_score=0.4,
            severity="MEDIUM",
            attack_family="Trojan",
            source_ip="192.168.1.1",
            destination_ip="10.0.0.1"
        )
        event = EvidenceEvent.wrap(net_ev.to_dict(), priority=EventPriority.NORMAL)
        gm.update(event)

        # Check source node
        src_node = gm.query().find_node("HOST:192.168.1.1")
        assert src_node is not None
        assert src_node["display_name"] == "192.168.1.1"
        assert src_node["risk_score"] == 0.4
        assert src_node["severity"] == "MEDIUM"

        # Check edge
        edge = gm.store.get_edge("HOST:192.168.1.1", "HOST:10.0.0.1", EdgeType.CONNECTS_TO.value)
        assert edge is not None
        assert edge["risk"] == 0.4
        assert edge["occurrence_count"] == 1

        # Merge update: higher risk score and critical severity
        net_ev2 = NetworkEvidence(
            detector="NETWORK",
            entity="192.168.1.1",
            entity_type="HOST",
            timestamp="2026-07-13T19:05:00+00:00",
            window_start="2026-07-13T19:00:00+00:00",
            window_end="2026-07-13T19:10:00+00:00",
            confidence=0.95,
            risk_score=0.85,
            severity="CRITICAL",
            attack_family="Trojan",
            source_ip="192.168.1.1",
            destination_ip="10.0.0.1"
        )
        event2 = EvidenceEvent.wrap(net_ev2.to_dict(), priority=EventPriority.CRITICAL)
        gm.update(event2)

        # Assert nodes/edges merged and updated correctly
        merged_node = gm.query().find_node("HOST:192.168.1.1")
        assert merged_node["risk_score"] == 0.85
        assert merged_node["severity"] == "CRITICAL"
        assert merged_node["first_seen"] == "2026-07-13T19:00:00+00:00"
        assert merged_node["last_seen"] == "2026-07-13T19:05:00+00:00"

        merged_edge = gm.store.get_edge("HOST:192.168.1.1", "HOST:10.0.0.1", EdgeType.CONNECTS_TO.value)
        assert merged_edge["risk"] == 0.85
        assert merged_edge["occurrence_count"] == 2

def test_graph_queries_and_metrics():
    with tempfile.TemporaryDirectory() as tmpdir:
        gm = GraphManager(storage_dir=tmpdir)
        gm.store.clear()

        # Create two connected nodes
        gm.store.add_node("HOST:10.0.0.1", {"node_id": "HOST:10.0.0.1", "entity_type": "HOST", "display_name": "10.0.0.1", "risk_score": 0.5, "timestamp": "2026-07-13T19:00:00+00:00"})
        gm.store.add_node("HOST:10.0.0.2", {"node_id": "HOST:10.0.0.2", "entity_type": "HOST", "display_name": "10.0.0.2", "risk_score": 0.2, "timestamp": "2026-07-13T19:00:00+00:00"})
        gm.store.add_edge("HOST:10.0.0.1", "HOST:10.0.0.2", {"type": "CONNECTS_TO", "timestamp": "2026-07-13T19:00:00+00:00", "risk": 0.5, "source_detector": "NETWORK"})

        # Shortest path check
        path = gm.query().find_shortest_path("HOST:10.0.0.1", "HOST:10.0.0.2")
        assert path == ["HOST:10.0.0.1", "HOST:10.0.0.2"]

        # Neighbors lookup
        neighbors = gm.query().find_neighbors("HOST:10.0.0.1")
        assert "HOST:10.0.0.2" in neighbors

        # Metrics computation
        metrics = gm.metrics()
        assert metrics["nodes_count"] == 2
        assert metrics["edges_count"] == 1
        assert "HOST:10.0.0.1" in metrics["degree_centrality"]

        # High risk nodes
        high_risk = gm.query().find_high_risk_nodes(threshold=0.4)
        assert len(high_risk) == 1
        assert high_risk[0]["node_id"] == "HOST:10.0.0.1"

def test_graph_validation():
    with tempfile.TemporaryDirectory() as tmpdir:
        gm = GraphManager(storage_dir=tmpdir)
        gm.store.clear()

        # Add proper node
        gm.store.add_node("HOST:10.0.0.1", {"node_id": "HOST:10.0.0.1", "entity_type": "HOST", "display_name": "10.0.0.1", "risk_score": 0.5, "timestamp": "2026-07-13T19:00:00+00:00"})
        gm.store.add_node("HOST:10.0.0.2", {"node_id": "HOST:10.0.0.2", "entity_type": "HOST", "display_name": "10.0.0.2", "risk_score": 0.2, "timestamp": "2026-07-13T19:00:00+00:00"})
        gm.store.add_edge("HOST:10.0.0.1", "HOST:10.0.0.2", {"type": "CONNECTS_TO", "timestamp": "2026-07-13T19:00:00+00:00", "risk": 0.5, "source_detector": "NETWORK"})

        report = gm.validate()
        assert report["valid"] is True
        assert len(report["errors"]) == 0

        # Create orphan edge explicitly (source is not in graph nodes index)
        # In GraphStore, add_edge creates missing nodes by design.
        # But we can simulate schema error by injecting directly or changing type to something invalid
        gm.store._graph.add_edge("HOST:invalid-node", "HOST:10.0.0.2", type="INVALID_RELATIONSHIP")
        report_invalid = gm.validate()
        assert report_invalid["valid"] is False
        assert any("INVALID_RELATIONSHIP" in err or "Orphan" in err for err in report_invalid["errors"])
