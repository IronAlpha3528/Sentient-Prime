import os
import tempfile
import time
import pytest
from sentinel_prime.core import Framework
from sentinel_prime.core.evidence import NetworkEvidence, IdentityEvidence, EndpointEvidence, OTEvidence

def test_complete_integration_pipeline():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create temp config YAML to set custom directory
        cfg_content = f"""
graph_radius: 2
max_nodes: 50
max_edges: 100
timeline_window: 30
export_directory: "{tmpdir.replace('\\', '/')}"
"""
        cfg_file = os.path.join(tmpdir, "framework_test.yaml")
        with open(cfg_file, "w", encoding="utf-8") as f:
            f.write(cfg_content)

        # Initialize Framework
        framework = Framework(config_path=cfg_file)
        # Clear metrics
        framework.graph_manager.store.clear()

        # 1. Network Specialist alert
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
            attack_family="Brute-Force",
            source_ip="192.168.1.1",
            destination_ip="10.0.0.1"
        )
        assert framework.push(net_ev) is True

        # 2. Identity Specialist alert
        id_ev = IdentityEvidence(
            detector="IDENTITY",
            entity="adm_aanoush",
            entity_type="USER",
            timestamp="2026-07-13T19:01:00+00:00",
            window_start="2026-07-13T19:00:00+00:00",
            window_end="2026-07-13T19:10:00+00:00",
            confidence=0.95,
            risk_score=0.7,
            severity="HIGH",
            user="adm_aanoush",
            off_hours=True,
            metadata={"accessed_computers": ["192.168.1.1"]}
        )
        assert framework.push(id_ev) is True

        # 3. Endpoint Specialist alert
        ep_ev = EndpointEvidence(
            detector="ENDPOINT",
            entity="192.168.1.1",
            entity_type="HOST",
            timestamp="2026-07-13T19:02:00+00:00",
            window_start="2026-07-13T19:00:00+00:00",
            window_end="2026-07-13T19:10:00+00:00",
            confidence=1.0,
            risk_score=0.85,
            severity="HIGH",
            process="powershell.exe",
            sigma_hits=[{"rule_id": "rule_01", "title": "Access LSASS"}]
        )
        assert framework.push(ep_ev) is True

        # 4. OT Specialist alert
        ot_ev = OTEvidence(
            detector="OT",
            entity="CNI-Process-PLC",
            entity_type="PLC",
            timestamp="2026-07-13T19:03:00+00:00",
            window_start="2026-07-13T19:00:00+00:00",
            window_end="2026-07-13T19:10:00+00:00",
            confidence=0.8,
            risk_score=0.9,
            severity="CRITICAL",
            top_shifted_variables=["P1_V_VALVE"],
            anomaly_score=1.8,
            attack_probability=0.92
        )
        assert framework.push(ot_ev) is True

        # Sleep to let background processing finish queue broadcast
        time.sleep(0.3)

        # Retrieve nodes list
        nodes = framework.graph_manager.store._graph.nodes()
        assert len(nodes) >= 6  # src_ip, dst_ip, user, process, valve, plc, flow, etc.

        # Retrieve health check
        health = framework.health()
        assert health["status"] == "Healthy"

        # Build context
        context = framework.build_context("USER:adm_aanoush")
        assert context.entity == "USER:adm_aanoush"
        assert len(context.related_entities) >= 3
        assert "executed process" in context.risk_summary.lower()

        # Build metrics
        metrics = framework.metrics()
        assert metrics["contexts_generated"] == 1
        assert metrics["nodes_created"] >= 6
        
        # Shutdown
        framework.shutdown()
