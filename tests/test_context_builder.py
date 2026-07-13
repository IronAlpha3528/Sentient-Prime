import tempfile
import pytest
from core.graph.graph_manager import GraphManager
from core.context.context_builder import ContextBuilder
from core.context.timeline_builder import TimelineBuilder
from core.context.summary_builder import SummaryBuilder

def test_timeline_and_summary_builders():
    events = [
        {
            "timestamp": "2026-07-13T19:00:00+00:00",
            "detector": "IDENTITY",
            "entity": "USER:adm_aanoush",
            "risk_score": 0.3,
            "confidence": 0.9,
            "top_reasons": ["Off-hours login"]
        },
        {
            "timestamp": "2026-07-13T19:05:00+00:00",
            "detector": "ENDPOINT",
            "entity": "HOST:WORKSTATION-X",
            "risk_score": 0.8,
            "confidence": 0.95,
            "top_reasons": ["Executed obfuscated PowerShell cmd"]
        }
    ]

    timeline = TimelineBuilder.build(events)
    assert len(timeline) == 2
    assert timeline[0]["timestamp"] == "2026-07-13T19:00:00+00:00"
    assert "Off-hours login" in timeline[0]["description"]

    summary = SummaryBuilder.summarize(events)
    assert "user user:adm_aanoush authenticated" in summary.lower()
    assert "executed process" in summary.lower()

def test_context_builder_subgraph_generation():
    with tempfile.TemporaryDirectory() as tmpdir:
        gm = GraphManager(storage_dir=tmpdir)
        gm.store.clear()

        # Connect a user node to a host node, and the host to a process node
        gm.store.add_node("USER:adm_aanoush", {"node_id": "USER:adm_aanoush", "entity_type": "USER", "display_name": "adm_aanoush", "risk_score": 0.5, "timestamp": "2026-07-13T19:00:00+00:00"})
        gm.store.add_node("HOST:WORKSTATION-X", {"node_id": "HOST:WORKSTATION-X", "entity_type": "HOST", "display_name": "WORKSTATION-X", "risk_score": 0.6, "timestamp": "2026-07-13T19:00:00+00:00"})
        gm.store.add_node("PROCESS:WORKSTATION-X:powershell.exe", {"node_id": "PROCESS:WORKSTATION-X:powershell.exe", "entity_type": "PROCESS", "display_name": "powershell.exe", "risk_score": 0.8, "timestamp": "2026-07-13T19:02:00+00:00"})
        
        gm.store.add_edge("USER:adm_aanoush", "HOST:WORKSTATION-X", {"type": "AUTHENTICATES_TO", "timestamp": "2026-07-13T19:00:00+00:00", "risk": 0.5, "source_detector": "IDENTITY"})
        gm.store.add_edge("HOST:WORKSTATION-X", "PROCESS:WORKSTATION-X:powershell.exe", {"type": "RUNS_PROCESS", "timestamp": "2026-07-13T19:02:00+00:00", "risk": 0.8, "source_detector": "ENDPOINT"})

        builder = ContextBuilder(gm, config={"graph_radius": 2, "max_nodes": 10})
        context = builder.build_context("USER:adm_aanoush")

        assert context.entity == "USER:adm_aanoush"
        assert len(context.related_entities) == 2  # WORKSTATION-X and powershell.exe
        assert "HOST:WORKSTATION-X" in context.related_entities
        assert "PROCESS:WORKSTATION-X:powershell.exe" in context.related_entities
        assert len(context.graph_paths) >= 2

        # Assert timeline has correct items
        assert len(context.timeline) == 2
        
        # Test markdown conversion
        md = context.to_markdown()
        assert "Correlation Security Context" in md
        assert "USER:adm_aanoush" in md
        assert "Timeline" in md
