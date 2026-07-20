import json
import logging
import numpy as np
import pandas as pd
from pathlib import Path
from sentinel_prime.detection.correlation.meta_classifier import MetaClassifier
from sentinel_prime.soar.orchestrator.policy_gate import PolicyGate
import matplotlib.pyplot as plt

logging.basicConfig(level=logging.INFO)

def main():
    data_path = Path("data/eval_ground_truth.json")
    if not data_path.exists():
        print(f"File not found: {data_path}")
        return

    meta = MetaClassifier()
    gate = PolicyGate()
    
    # Track statistics
    stats = {
        "network_score": [],
        "identity_score": [],
        "endpoint_score": [],
        "ot_score": [],
        "meta_probability": [],
        "risk_score": [],
        "confidence_score": [],
        "decisions": []
    }
    
    print("====== PIPELINE TRACE (First 5 Items) ======")
    with open(data_path, "r", encoding="utf-8") as f:
        dataset = json.load(f)
        
    for i, row in enumerate(dataset):
        features = row.get("features", {})
        if not features:
            features = row
            
        result = meta.predict(features)
        
        score_meta = result.get("unified_threat_score", 0.0)
        conf_meta = result.get("confidence_score", 0.0)
        
        # Simulating eval_pipeline mapping
        risk_score = score_meta * 100
        
        incident = {
            "incident_id": f"TEST-{i}",
            "risk_score": risk_score,
            "confidence": conf_meta,
            "asset": "Unknown",
            "asset_type": "Unknown"
        }
        
        dry_run = {"passes": True, "blast_radius": "LOW"}
        
        decision = gate.evaluate(incident, dry_run)
        
        stats["network_score"].append(features.get("network_score", 0.0))
        stats["identity_score"].append(features.get("identity_score", 0.0))
        stats["endpoint_score"].append(features.get("endpoint_score", 0.0))
        stats["ot_score"].append(features.get("ot_score", 0.0))
        stats["meta_probability"].append(score_meta)
        stats["risk_score"].append(risk_score)
        stats["confidence_score"].append(conf_meta)
        stats["decisions"].append(decision["decision"])
        
        if i < 5:
            print(f"\n--- Incident {i} ---")
            print("1. Raw Features:")
            for k in ["network_score", "identity_score", "endpoint_score", "ot_score"]:
                print(f"   {k}: {features.get(k, 0.0)}")
            print(f"2. Meta-Classifier Output:")
            print(f"   Probability (unified_threat_score): {score_meta}")
            print(f"   Confidence: {conf_meta}")
            print(f"3. Risk Calculation (pipeline):")
            print(f"   Risk Score: {risk_score}")
            print(f"4. Policy Gate Output:")
            print(f"   Decision: {decision['decision']} ({decision['reason']})")
    
    print("\n====== DISTRIBUTION SUMMARY ======")
    for key, values in stats.items():
        if key == "decisions":
            continue
        valid_vals = [v for v in values if v is not None]
        if not valid_vals:
            continue
        print(f"\n{key}:")
        print(f"  Mean: {np.mean(valid_vals):.4f}")
        print(f"  Min:  {np.min(valid_vals):.4f}")
        print(f"  Max:  {np.max(valid_vals):.4f}")
        
        # Text histogram
        hist, bins = np.histogram(valid_vals, bins=10)
        print("  Histogram:")
        for count, edge in zip(hist, bins):
            bar = "#" * int((count / len(valid_vals)) * 50)
            print(f"    {edge:7.4f} | {bar} ({count})")

    print("\nPolicy Gate Decisions:")
    escalate_count = stats["decisions"].count("ESCALATE")
    auto_count = stats["decisions"].count("AUTO")
    print(f"  ESCALATE: {escalate_count} ({escalate_count/len(stats['decisions'])*100:.1f}%)")
    print(f"  AUTO:     {auto_count} ({auto_count/len(stats['decisions'])*100:.1f}%)")

if __name__ == "__main__":
    main()
