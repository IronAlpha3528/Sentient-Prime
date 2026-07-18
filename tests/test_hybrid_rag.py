import os
import json
import pytest
import faiss
import tempfile
from typing import Dict, Any, List
import sentinel_prime.ai.agents.rag.query as query
from sentinel_prime.ai.agents.rag.providers.bm25 import BM25Index, tokenize
from sentinel_prime.ai.agents.rag.providers.attack import AttackProvider
from sentinel_prime.ai.agents.rag.providers.generic import GenericProvider
from sentinel_prime.ai.agents.rag.providers.historical_incident import HistoricalIncidentProvider

def test_query_normalization_tokenizer():
    # Test cases for query normalization and exact ID preservation (Step 3)
    text = "Detect CVE-2023-38606 using T1059.001 PowerShell scripts on 192.168.1.100 or hash 5e8887a5eb2c2937180120264785b0cb"
    tokens = tokenize(text)
    
    # Verify exact IDs preserved
    assert "cve-2023-38606" in tokens
    assert "t1059.001" in tokens
    assert "192.168.1.100" in tokens
    assert "5e8887a5eb2c2937180120264785b0cb" in tokens
    
    # Verify suffix stemming and stop words filtering
    assert "detect" in tokens
    assert "script" in tokens  # "scripts" stemmed to "script"
    assert "using" not in tokens  # Stop word removed

def test_bm25_indexing_and_retrieval(tmp_path):
    index_file = str(tmp_path / "test_index.bm25")
    bm25 = BM25Index()
    
    # Index test documents
    doc1 = {
        "source": "sigma",
        "document_id": "SIG-001",
        "title": "SSH Brute Force",
        "description": "Detects login brute forcing on SSH services",
        "tags": ["ssh", "auth"]
    }
    doc2 = {
        "source": "sigma",
        "document_id": "SIG-002",
        "title": "PowerShell Script execution",
        "description": "Detects encoded base64 powershell script launch",
        "tags": ["powershell", "execution"]
    }
    
    bm25.add_document("SIG-001", "SSH Brute Force logins", doc1)
    bm25.add_document("SIG-002", "PowerShell Script execution base64", doc2)
    
    assert bm25.doc_count == 2
    
    # Test retrieval
    results = bm25.search("SSH login attempts", limit=1)
    assert len(results) == 1
    assert results[0]["document_id"] == "SIG-001"
    
    # Test filtering (Step 2)
    filtered = bm25.search("attempts", limit=2, filters={"tags": ["powershell"]})
    assert len(filtered) == 0  # "attempts" matches doc1 but tag filter matches doc2 only

    # Save and Load persistence (Step 2)
    bm25.save(index_file)
    assert os.path.exists(index_file)
    
    loaded_bm25 = BM25Index.load(index_file)
    assert loaded_bm25.doc_count == 2
    assert "SIG-001" in loaded_bm25.docs

def test_reciprocal_rank_fusion():
    dense = [
        {"source": "attack", "document_id": "T1110", "title": "Brute Force", "confidence": 0.9, "similarity_score": 0.1},
        {"source": "attack", "document_id": "T1059.001", "title": "PowerShell", "confidence": 0.8, "similarity_score": 0.2}
    ]
    lexical = [
        {"source": "attack", "document_id": "T1059.001", "title": "PowerShell", "confidence": 0.8, "bm25_score": 12.0},
        {"source": "attack", "document_id": "T1110", "title": "Brute Force", "confidence": 0.9, "bm25_score": 8.0}
    ]
    
    fused = query.reciprocal_rank_fusion(
        dense, lexical, limit=2, k=60, dense_weight=1.0, lexical_weight=1.0
    )
    
    assert len(fused) == 2
    # Verify metadata normalized (Step 8)
    for doc in fused:
        assert "dense_score" in doc
        assert "bm25_score" in doc
        assert "rrf_score" in doc
        assert "retrieval_method" in doc
        assert "provider" in doc
        assert "similarity" in doc
        
    # T1059.001 (Dense rank 2, Lexical rank 1) vs T1110 (Dense rank 1, Lexical rank 2)
    # Since confidence/weights match, their scores will be identical, tie breaking on id
    assert fused[0]["document_id"] in ["T1110", "T1059.001"]

def test_attack_provider_hybrid_search(tmp_path, monkeypatch):
    # Setup mock config
    monkeypatch.setattr(query, "_graph_config", {
        "enable_dense": True,
        "enable_bm25": True,
        "enable_hybrid": True,
        "rrf_k": 60,
        "dense_weight": 1.0,
        "bm25_weight": 0.8,
        "enabled_providers": ["attack"],
        "max_documents": 5,
        "per_provider_limit": 2
    })
    
    # Initialize AttackProvider with tmp path
    provider = AttackProvider(str(tmp_path))
    
    # Mock resources for provider to bypass file loading
    provider._index = faiss.IndexFlatL2(384)
    import numpy as np
    mock_vec = np.zeros((1, 384), dtype="float32")
    provider._index.add(mock_vec)
    
    provider._metadata = [{
        "technique_id": "T1110",
        "name": "Brute Force",
        "description": "Brute forcing authentication services."
    }]
    
    from sentence_transformers import SentenceTransformer
    class MockModel:
        def encode(self, texts, **kwargs):
            return np.zeros((len(texts), 384), dtype="float32")
    provider._model = MockModel()
    
    # Setup mock BM25
    bm25 = BM25Index()
    bm25.add_document("T1110", "Brute Force login", {
        "source": "attack",
        "document_id": "T1110",
        "title": "Brute Force",
        "description": "Brute forcing authentication services."
    })
    provider._bm25 = bm25
    
    # Test Dense, BM25, and Hybrid
    dense_res = provider.dense_search("SSH attempts", limit=1)
    assert len(dense_res) == 1
    assert dense_res[0]["document_id"] == "T1110"
    
    bm25_res = provider.bm25_search("login", limit=1)
    assert len(bm25_res) == 1
    assert bm25_res[0]["document_id"] == "T1110"
    
    hybrid_res = provider.search("login", limit=1)
    assert len(hybrid_res) == 1
    assert hybrid_res[0]["document_id"] == "T1110"
    assert hybrid_res[0]["retrieval_method"] == "hybrid"

def test_query_orchestrator_parallel_hybrid(monkeypatch):
    # Setup orchestrator mocks
    monkeypatch.setattr(query, "_graph_config", {
        "enable_dense": True,
        "enable_bm25": True,
        "enable_hybrid": True,
        "rrf_k": 60,
        "dense_weight": 1.0,
        "bm25_weight": 0.8,
        "enabled_providers": ["attack"],
        "max_documents": 5,
        "per_provider_limit": 2
    })
    
    class MockAttackProvider:
        def dense_search(self, q, lim, filters=None):
            return [{"source": "attack", "document_id": "T1110", "title": "Brute Force", "similarity_score": 0.1, "confidence": 1.0}]
        def bm25_search(self, q, lim, filters=None):
            return [{"source": "attack", "document_id": "T1110", "title": "Brute Force", "bm25_score": 10.0, "confidence": 1.0}]
        def search(self, q, lim, filters=None):
            return self.dense_search(q, lim)
            
    monkeypatch.setitem(query._providers, "attack", MockAttackProvider())
    
    # Run Orchestrator search
    results = query.search("SSH login", top_k=2)
    assert len(results) == 1
    assert results[0]["document_id"] == "T1110"
    assert results[0]["retrieval_method"] == "hybrid"
    
    # Verify performance metrics captured (Step 9)
    perf = query._performance_metrics
    assert perf["query_count"] > 0
    assert perf["fusion_time_ms"] >= 0.0
    assert "cache_hit_rate" in perf
