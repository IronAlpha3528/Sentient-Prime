import time
import pytest
from sentinel_prime.core.framework import Framework
from sentinel_prime.core.evidence.base_evidence import BaseEvidence

def test_full_context_pipeline_integration():
    # Instantiate framework with default config
    framework = Framework()
    framework.graph_manager.store.clear()
    
    # 1. Network Evidence
    net_evidence = BaseEvidence(
        detector="NETWORK",
        entity="HOST:ENG-WS-01",
        entity_type="HOST",
        timestamp="2026-07-14T09:00:00Z",
        window_start="2026-07-14T08:30:00Z",
        window_end="2026-07-14T09:00:00Z",
        confidence=0.9,
        risk_score=0.82,
        severity="HIGH",
        top_reasons=["Infiltration attempts"],
        metadata={"class": "infiltration"}
    )
    framework.push(net_evidence)
    
    # 2. Identity Evidence
    id_evidence = BaseEvidence(
        detector="IDENTITY",
        entity="USER:adm_aanoush",
        entity_type="USER",
        timestamp="2026-07-14T09:01:00Z",
        window_start="2026-07-14T08:31:00Z",
        window_end="2026-07-14T09:01:00Z",
        confidence=0.95,
        risk_score=0.94,
        severity="CRITICAL",
        top_reasons=["Admin off-hours access"],
        metadata={"new_hosts": 12}
    )
    framework.push(id_evidence)
    
    # 3. Endpoint Evidence
    ep_evidence = BaseEvidence(
        detector="ENDPOINT",
        entity="HOST:ENG-WS-01",
        entity_type="HOST",
        timestamp="2026-07-14T09:02:00Z",
        window_start="2026-07-14T08:32:00Z",
        window_end="2026-07-14T09:02:00Z",
        confidence=1.0,
        risk_score=0.97,
        severity="CRITICAL",
        top_reasons=["Encoded PowerShell"],
        metadata={"process_chain": ["WINWORD.EXE", "powershell.exe"]}
    )
    framework.push(ep_evidence)
    
    # 4. OT Evidence
    ot_evidence = BaseEvidence(
        detector="OT",
        entity="HOST:ENG-WS-01",
        entity_type="HOST",
        timestamp="2026-07-14T09:03:00Z",
        window_start="2026-07-14T08:33:00Z",
        window_end="2026-07-14T09:03:00Z",
        confidence=0.98,
        risk_score=0.88,
        severity="HIGH",
        top_reasons=["PLC write anomaly"],
        metadata={"behaviour_summary": "SCADA gateway access"}
    )
    framework.push(ot_evidence)
    
    # Add relationship edges directly to simulate cross-domain links
    framework.graph_manager.store.add_edge(
        "USER:adm_aanoush", 
        "HOST:ENG-WS-01", 
        {"type": "AUTHENTICATES_TO", "timestamp": "2026-07-14T09:01:00Z", "risk": 0.94, "source_detector": "IDENTITY"}
    )
    
    # Give background thread a moment to process Evidence Bus queue
    time.sleep(0.5)
    
    # Build context for the target host
    context = framework.build_context("HOST:ENG-WS-01")
    
    # Assertions on CorrelationContext fields
    assert context is not None
    assert context.entity == "HOST:ENG-WS-01"
    
    # Verify related entities contain the interacting USER
    assert "USER:adm_aanoush" in context.related_entities
    
    # Verify all detectors/domains appear in the supporting evidence
    assert len(context.supporting_evidence) > 0
    
    # Verify timeline is sorted chronologically
    assert len(context.timeline) > 0
    timestamps = [t["timestamp"] for t in context.timeline]
    assert timestamps == sorted(timestamps)
    
    # Verify Threat Intelligence FAISS RAG enrichment
    assert len(context.threat_intel) > 0
    assert any(ti.get("technique_id") is not None for ti in context.threat_intel)
    
    # Verify Monitoring Snapshot fields
    assert context.monitoring_snapshot != {}
    assert "pipeline_status" in context.monitoring_snapshot
    assert "evidence_counts" in context.monitoring_snapshot
    
    # Verify markdown serialization doesn't fail
    md = context.to_markdown()
    assert "# Correlation Security Context" in md
    
    framework.shutdown()
