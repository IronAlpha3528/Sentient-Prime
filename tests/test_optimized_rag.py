import os
import faiss
import tempfile
import pytest
import datetime
from typing import Dict, Any, List
import sentinel_prime.ai.agents.rag.query as query
from sentinel_prime.ai.agents.rag.providers.bm25 import BM25Index
from sentinel_prime.ai.agents.rag.providers.attack import AttackProvider
from sentinel_prime.ai.agents.rag.providers.generic import GenericProvider
from sentinel_prime.ai.agents.rag.providers.historical_incident import HistoricalIncidentProvider
from sentinel_prime.ai.agents.rag.knowledge_manager import (
    insert_cti_document,
    delete_cti_document,
    update_cti_document,
    upsert_cti_document
)

def test_trust_scoring():
    # Verify trust score calculation rules (Part D)
    doc_official = {
        "source": "attack",
        "confidence": 0.9,
        "description": "Standard threat technique",
        "tags": ["mitre_attack"],
        "references": ["url1"],
        "version": "1.0"
    }
    config = {
        "trust_weights": {
            "official_source": 0.6,
            "community_source": 0.4,
            "internal_knowledge": 0.5,
            "confidence_factor": 0.1,
            "completeness_factor": 0.1
        }
    }
    score_off = query.compute_trust_score(doc_official, config)
    assert 0.0 <= score_off <= 1.0
    
    # Community sources should get lower trust
    doc_comm = doc_official.copy()
    doc_comm["source"] = "sigma"
    score_comm = query.compute_trust_score(doc_comm, config)
    assert score_comm < score_off

def test_freshness_scoring():
    # Verify freshness score categories (Part E)
    config = {
        "freshness_thresholds": {
            "fresh_max_days": 180,
            "stale_max_days": 365
        }
    }
    
    # 1. Fresh document (10 days old)
    now = datetime.datetime.now(datetime.timezone.utc)
    ts_fresh = (now - datetime.timedelta(days=10)).isoformat()
    doc_fresh = {"updated_at": ts_fresh, "tags": []}
    score_f, cat_f, _ = query.compute_freshness(doc_fresh, config)
    assert cat_f == "fresh"
    assert score_f >= 0.7
    
    # 2. Stale document (200 days old)
    ts_stale = (now - datetime.timedelta(days=200)).isoformat()
    doc_stale = {"updated_at": ts_stale, "tags": []}
    score_s, cat_s, _ = query.compute_freshness(doc_stale, config)
    assert cat_s == "stale"
    assert 0.4 <= score_s < 0.7
    
    # 3. Deprecated document (400 days old)
    ts_dep = (now - datetime.timedelta(days=400)).isoformat()
    doc_dep = {"updated_at": ts_dep, "tags": []}
    score_d, cat_d, _ = query.compute_freshness(doc_dep, config)
    assert cat_d == "deprecated"
    assert score_d < 0.4
    
    # 4. Explicitly deprecated status
    doc_explicit = {"updated_at": ts_fresh, "status": "deprecated"}
    score_e, cat_e, _ = query.compute_freshness(doc_explicit, config)
    assert cat_e == "deprecated"
    assert score_e == 0.0

def test_cross_encoder_reranking_mock(monkeypatch):
    # Verify re-ranking works and falls back cleanly (Part A)
    candidates = [
        {"title": "SSH login", "description": "SSH brute force attempt", "rrf_score": 0.5, "similarity_score": 0.2, "document_id": "T1110"},
        {"title": "PowerShell Script", "description": "Encoded powershell execution", "rrf_score": 0.8, "similarity_score": 0.1, "document_id": "T1059.001"}
    ]
    
    # If Cross-Encoder is not loaded, it should fall back to original RRF/similarity scores
    monkeypatch.setattr(query, "_cross_encoder", None)
    reranked = query.rerank_candidates("SSH brute forcing", candidates, limit=2)
    assert len(reranked) == 2
    assert "cross_encoder_score" in reranked[0]
    
    # Mocking Cross-Encoder predictions
    class MockCrossEncoder:
        def predict(self, pairs):
            # Let's say SSH query matches SSH login much better
            return [1.5, -2.5]
            
    monkeypatch.setattr(query, "_cross_encoder", MockCrossEncoder())
    reranked_mocked = query.rerank_candidates("SSH brute forcing", candidates, limit=2)
    assert len(reranked_mocked) == 2
    assert reranked_mocked[0]["document_id"] == "T1110"  # Match SSH first
    assert reranked_mocked[0]["cross_encoder_score"] == 1.0
    assert reranked_mocked[1]["cross_encoder_score"] == 0.0

def test_citation_generation():
    # Verify citation fields populated (Part C)
    doc = {
        "source": "sigma",
        "document_id": "SIG-001",
        "title": "SSH Rule",
        "description": "Rule to detect SSH brute force",
        "created_at": "2026-07-18T10:00:00Z"
    }
    config = {
        "trust_weights": {},
        "freshness_thresholds": {}
    }
    # Insert the mock document before search
    insert_cti_document("sigma", doc)
    try:
        # Temporarily set configuration
        original_config = query._graph_config.copy()
        query._graph_config.update(config)
    
        results = query.search("SSH Rule", top_k=1, enabled_providers=["sigma"])
        query._graph_config = original_config
    
        # Assert citation fields present on search hit
        if results:
            hit = results[0] if isinstance(results, list) else results["results"][0]
            assert hit["provider"] == "sigma"
            assert hit["rank"] == 1
            assert "citation_identifier" in hit
            assert "[sigma:SIG-001]" in hit["citation_identifier"]
            
            # Verify score conversion fields to resolve ContextBuilder float TypeError
            assert isinstance(hit["similarity_score"], float)
            assert isinstance(hit["distance"], float)
            assert isinstance(hit["score"], float)
    finally:
        delete_cti_document("sigma", "SIG-001")

def test_incremental_knowledge_management(tmp_path, monkeypatch):
    # Verify incremental CRUD inserts, deletes, updates, and upserts (Part B)
    provider = GenericProvider("sigma", str(tmp_path))
    
    # Mock model
    import numpy as np
    class MockModel:
        def encode(self, texts, **kwargs):
            return np.zeros((len(texts), 384), dtype="float32")
    provider._model = MockModel()
    
    # Setup initial mock DB
    provider._index = faiss.IndexFlatL2(384)
    provider._metadata = []
    provider._bm25 = BM25Index()
    
    doc1 = {
        "id": "SIG-TEST-01",
        "name": "Initial Sigma Rule",
        "description": "Rule content descriptions",
        "confidence": 0.8,
        "version": "1.0",
        "tags": ["test"]
    }
    
    # 1. Insert doc incrementally
    provider.insert_document(doc1, sync_index=False)
    assert len(provider._metadata) == 1
    assert provider._metadata[0]["document_id"] == "SIG-TEST-01"
    
    # 2. Update doc incrementally
    doc1_up = doc1.copy()
    doc1_up["name"] = "Updated Name"
    provider.update_document(doc1_up, sync_index=False)
    assert len(provider._metadata) == 1
    assert provider._metadata[0]["title"] == "Updated Name"
    
    # 3. Duplicate detection during upsert/insert
    provider.upsert_document(doc1_up, sync_index=False)
    assert len(provider._metadata) == 1
    
    # 4. Delete doc incrementally
    provider.delete_document("SIG-TEST-01", sync_index=False)
    assert len(provider._metadata) == 0
