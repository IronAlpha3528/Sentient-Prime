import os
import tempfile
import time
from pathlib import Path
import pytest

from sentinel_prime.detection.correlation.meta_classifier import MetaClassifier
from sentinel_prime.core.context.context_schema import CorrelationContext
from sentinel_prime.core.context.context_builder import ContextBuilder
from sentinel_prime.core.graph.graph_manager import GraphManager
from sentinel_prime.core.evidence.base_evidence import BaseEvidence
from sentinel_prime.core.framework import Framework

def test_meta_classifier_fallback_mode():
    # Test classifier running in fallback mode when no model file exists
    temp_model_path = Path("non_existent_directory_123/meta_lightgbm.pkl")
    classifier = MetaClassifier(model_path=str(temp_model_path))
    assert classifier.fallback_mode is True
    
    # 1. Benign Scenario
    benign_feats = {
        "network_score": 0.1,
        "network_confidence": 0.9,
        "identity_score": 0.05,
        "identity_confidence": 1.0,
        "endpoint_score": 0.15,
        "endpoint_confidence": 0.95,
        "ot_score": 0.0,
        "ot_confidence": 1.0,
        "evidence_diversity": 1,
        "honeypot_touched": 0.0
    }
    
    benign_res = classifier.predict(benign_feats)
    assert benign_res["unified_threat_score"] < 0.4
    assert benign_res["risk_level"] == "LOW"
    assert benign_res["model_version"].endswith("-fallback")
    assert "detector_contributions" in benign_res
    
    # 2. Single-detector Critical Scenario
    critical_feats = {
        "network_score": 0.9,
        "network_confidence": 0.95,
        "identity_score": 0.0,
        "endpoint_score": 0.0,
        "ot_score": 0.0,
        "evidence_diversity": 1,
        "honeypot_touched": 0.0
    }
    
    critical_res = classifier.predict(critical_feats)
    assert critical_res["unified_threat_score"] >= 0.75
    assert critical_res["risk_level"] == "CRITICAL"
    
    # 3. Honeypot Touched Scenario (Override)
    honey_feats = {
        "network_score": 0.2,
        "network_confidence": 0.8,
        "identity_score": 0.1,
        "endpoint_score": 0.3,
        "ot_score": 0.0,
        "evidence_diversity": 2,
        "honeypot_touched": 1.0
    }
    
    honey_res = classifier.predict(honey_feats)
    assert honey_res["unified_threat_score"] == 0.95
    assert honey_res["confidence_score"] == 0.99
    assert honey_res["risk_level"] == "CRITICAL"

def test_meta_classifier_training_and_inference():
    # Test classifier training pipeline and model-based inference
    with tempfile.TemporaryDirectory() as tmpdir:
        model_file = Path(tmpdir) / "meta_lightgbm.pkl"
        
        # Build training DataFrame
        import numpy as np
        import pandas as pd
        
        np.random.seed(42)
        n_samples = 100
        
        from sentinel_prime.detection.correlation.meta_classifier import FEATURE_COLUMNS
        
        X_data = {}
        for col in FEATURE_COLUMNS:
            if "confidence" in col:
                X_data[col] = np.random.uniform(0.8, 1.0, n_samples)
            elif "severity" in col:
                X_data[col] = np.random.choice([0.1, 0.3, 0.5, 0.8, 1.0], n_samples)
            else:
                X_data[col] = np.random.uniform(0.0, 1.0, n_samples)
                
        X = pd.DataFrame(X_data)
        
        # Simple threshold for label
        y = (X["network_score"] + X["endpoint_score"] + X["honeypot_touched"] * 2.0 > 1.2).astype(int)
        
        classifier = MetaClassifier(model_path=str(model_file))
        assert classifier.fallback_mode is True
        
        results = classifier.train(X, y)
        assert results["accuracy"] > 0.5
        assert classifier.fallback_mode is False
        assert model_file.exists()
        
        # Run inference using the trained model
        test_feats = {col: 0.8 if "score" in col or "touched" in col else 0.1 for col in FEATURE_COLUMNS}
        test_feats["network_confidence"] = 0.95
        test_feats["identity_confidence"] = 0.95
        test_feats["endpoint_confidence"] = 0.95
        test_feats["ot_confidence"] = 0.95
        
        prediction = classifier.predict(test_feats)
        
        assert 0.0 <= prediction["unified_threat_score"] <= 1.0
        assert 0.0 <= prediction["confidence_score"] <= 1.0
        assert prediction["risk_level"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        assert len(prediction["top_features"]) == 5
        assert len(prediction["detector_contributions"]) == 8
        assert not prediction["model_version"].endswith("-fallback")

def test_context_builder_meta_integration():
    # Test integration of MetaClassifier inside ContextBuilder
    with tempfile.TemporaryDirectory() as tmpdir:
        gm = GraphManager(storage_dir=tmpdir)
        gm.store.clear()
        
        # Connect nodes in the graph
        gm.store.add_node("USER:adm_aanoush", {"node_id": "USER:adm_aanoush", "entity_type": "USER", "display_name": "adm_aanoush", "risk_score": 0.85, "confidence": 0.95, "severity": "HIGH", "timestamp": "2026-07-14T09:00:00Z"})
        gm.store.add_node("HOST:WORKSTATION-A", {"node_id": "HOST:WORKSTATION-A", "entity_type": "HOST", "display_name": "WORKSTATION-A", "risk_score": 0.92, "confidence": 0.98, "severity": "CRITICAL", "timestamp": "2026-07-14T09:01:00Z"})
        
        gm.store.add_edge("USER:adm_aanoush", "HOST:WORKSTATION-A", {"type": "AUTHENTICATES_TO", "timestamp": "2026-07-14T09:01:00Z", "risk": 0.90, "confidence": 0.95, "source_detector": "IDENTITY"})
        
        builder = ContextBuilder(gm, config={"graph_radius": 2, "max_nodes": 10})
        
        # Build context
        context = builder.build_context("USER:adm_aanoush")
        
        if builder.meta_classifier.fallback_mode:
            assert context.unified_threat_score >= 0.75
            assert context.risk_level == "CRITICAL"
            assert context.confidence_score >= 0.75
            assert context.detector_contributions["identity"] > 0.0
        else:
            # Under the trained model, single-detector alerts are classified as benign
            assert context.unified_threat_score < 0.40
            assert context.risk_level == "LOW"
        assert len(context.top_features) == 5

def test_framework_end_to_end():
    # Test complete framework pipeline integration and scoring
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create temp config YAML
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

        framework = Framework(config_path=cfg_file)
        framework.graph_manager.store.clear()

        # Push Network Evidence
        net_ev = BaseEvidence(
            detector="NETWORK",
            entity="192.168.1.1",
            entity_type="HOST",
            timestamp="2026-07-14T09:00:00Z",
            window_start="2026-07-14T09:00:00Z",
            window_end="2026-07-14T09:10:00Z",
            confidence=0.9,
            risk_score=0.85,
            severity="HIGH",
            top_reasons=["Infiltration attempt"]
        )
        framework.push(net_ev)
        
        time.sleep(0.1)
        
        context = framework.build_context("HOST:192.168.1.1")
        
        # Check if running in fallback mode
        is_fallback = framework.context_builder.meta_classifier.fallback_mode
        if is_fallback:
            assert context.unified_threat_score > 0.7
            assert context.risk_level in ["HIGH", "CRITICAL"]
            assert context.confidence_score > 0.5
        else:
            # Under the trained model, single-detector alerts are classified as benign
            assert context.unified_threat_score < 0.40
            assert context.risk_level == "LOW"
        assert "network" in context.detector_contributions
        assert context.detector_contributions["network"] > 0.0
        
        # Test markdown output contains threat score
        md = context.to_markdown()
        assert "Unified Threat Assessment" in md
        assert "Unified Threat Score" in md
        assert "Assessed Risk Level" in md
        
        framework.shutdown()
