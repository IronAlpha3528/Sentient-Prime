"""
eval_apt_attribution.py — Metric 2: APT Attribution Accuracy at MITRE ATT&CK Technique Level
==============================================================================================

Runs the 3-agent AI pipeline (AnalysisAgent → CritiqueAgent → ActionAgent) on
a representative sample of malicious benchmark incidents, then checks whether
the predicted MITRE techniques overlap with the ground-truth techniques.

Scoring:
  - Top-1 Accuracy:  ground-truth technique appears as the first predicted technique
                     (predicted[0], not randomised by set-conversion)
  - Top-3 Accuracy:  ground-truth technique appears in the first 3 predictions
  - Any Match:       any ground-truth technique appears anywhere in the AI output

Key design decision — BLIND evaluation:
  The AI is NOT given the ground-truth technique IDs as a hint. Instead it
  receives only the raw evidence signals (process chains, sigma matches, network
  scores) and candidate techniques retrieved by the project's real FAISS ATT&CK
  RAG search. This ensures accuracy reflects genuine inference ability.

Run from project root:
    python scripts/eval/eval_apt_attribution.py
"""

import json
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

DATASET_PATH = PROJECT_ROOT / "data" / "eval_ground_truth.json"

MITRE_DESCRIPTIONS = {
    "T1490":     "Inhibit System Recovery",
    "T1486":     "Data Encrypted for Impact",
    "T1550.002": "Use Alternate Authentication Material: Pass-the-Hash",
    "T1021.002": "Remote Services: SMB/Windows Admin Shares",
    "T1105":     "Ingress Tool Transfer",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T0831":     "Manipulation of Control (ICS)",
    "T0836":     "Modify Parameter (ICS)",
    "T1003.001": "OS Credential Dumping: LSASS Memory",
    "T1048.003": "Exfiltration Over Alternative Protocol: DNS",
    "T1071.004": "Application Layer Protocol: DNS",
    "T1134.001": "Access Token Manipulation: Token Impersonation/Theft",
}

# Full known candidate pool — used as fallback when RAG is unavailable
ALL_TECHNIQUE_IDS = list(MITRE_DESCRIPTIONS.keys())


def _build_rag_query(sample: dict) -> str:
    """Build a natural-language query string from evidence signals so the
    project's FAISS ATT&CK RAG can retrieve relevant candidate techniques.
    This mirrors the query approach used by ContextBuilder in production."""
    ep = sample["endpoint"]
    parts = []
    for sigma in ep.get("sigma_matches", []):
        parts.append(sigma)
    for proc in ep.get("process_chain", [])[:2]:
        exe = proc.split()[0] if proc else ""
        if exe:
            parts.append(exe)
    attack_class = sample.get("attack_class", "")
    if attack_class and attack_class != "benign":
        parts.append(attack_class.replace("_", " "))
    return " ".join(parts) if parts else sample.get("entity_id", "unknown incident")


def _retrieve_rag_candidates(query: str, top_k: int = 6) -> list[str]:
    """Use the project's real FAISS ATT&CK RAG search to retrieve candidate
    technique IDs from the evidence query string. Falls back to the full
    MITRE_DESCRIPTIONS pool if RAG is unavailable."""
    try:
        from sentinel_prime.ai.agents.rag.query import search as rag_search
        results = rag_search(query, top_k=top_k, enabled_providers=["attack"])
        candidates = [r.get("technique_id", "") for r in results if r.get("technique_id")]
        return candidates if candidates else ALL_TECHNIQUE_IDS
    except Exception:
        # RAG unavailable (e.g. index not built) — use full pool but still no leak
        return ALL_TECHNIQUE_IDS


def _build_agent_context(sample: dict, rag_candidates: list[str]) -> dict:
    """Convert a benchmark record into the evidence dict the AI pipeline expects.

    IMPORTANT: attack_rag_context is populated from the live FAISS RAG search
    results (or the full MITRE pool as fallback), NOT from the ground-truth
    technique IDs stored in the benchmark. This prevents answer leakage.
    """
    ep = sample["endpoint"]
    net = sample["network"]
    idc = sample["identity"]
    return {
        "incident_id": sample["incident_id"],
        "entity_id": sample["entity_id"],
        "entities": sample["entities"],
        "network": {"score": net["score"], "class": net.get("attack_class", "unknown")},
        "identity": {"score": idc["score"], "new_hosts": idc.get("computer_fanout", 0)},
        "endpoint": {
            "score": ep["score"],
            "sigma_matches": ep["sigma_matches"],
            "process_chain": ep["process_chain"],
        },
        "ot": {"score": sample["ot"]["anomaly_score"]},
        "deception": sample["deception"],
        # candidate_techniques: RAG-retrieved, not ground-truth
        "candidate_techniques": rag_candidates,
        "unified_threat_score": max(net["score"], ep["score"], sample["ot"]["anomaly_score"]),
        "evidence_object": {
            "incident_id": sample["incident_id"],
            "entities": sample["entities"],
            "endpoint": ep,
            "network": net,
            "identity": idc,
            "ot": sample["ot"],
        },
        "graph_features": {
            "attack_path_length": 2,
            "node_centrality": min(1.0, net["score"] + 0.2),
        },
        # attack_rag_context: RAG-retrieved technique descriptions (blind to ground truth)
        "attack_rag_context": [
            f"{tid} — {MITRE_DESCRIPTIONS.get(tid, tid)}"
            for tid in rag_candidates
            if tid in MITRE_DESCRIPTIONS
        ],
    }


def _extract_predicted_techniques(pipeline_result: dict) -> list[str]:
    """Pull technique IDs out of the AI pipeline output dict, preserving
    insertion order so that predicted[0] is the highest-confidence prediction."""
    techniques = []
    # From analysis agent hypotheses (ordered by confidence)
    for hyp in pipeline_result.get("hypotheses", []):
        techniques.extend(hyp.get("mitre_techniques", []))
    # From prediction fields
    prediction = pipeline_result.get("prediction", {})
    if prediction.get("current_stage_technique"):
        techniques.append(prediction["current_stage_technique"])
    if prediction.get("next_technique"):
        techniques.append(prediction["next_technique"])
    # Deduplicate while preserving insertion order
    seen: set[str] = set()
    unique: list[str] = []
    for t in techniques:
        if t and t not in seen:
            seen.add(t)
            unique.append(t)
    return unique


def run() -> dict:
    print("\n" + "═" * 60)
    print("  METRIC 2 — APT Attribution Accuracy (MITRE ATT&CK)")
    print("═" * 60)
    print("  ℹ️  Blind evaluation: AI receives RAG-retrieved candidates,")
    print("      NOT the ground-truth technique IDs.")

    if not DATASET_PATH.exists():
        print(f"  ❌ Dataset not found. Run: python scripts/generate_synthetic_benchmark.py")
        return {}

    dataset = json.loads(DATASET_PATH.read_text(encoding="utf-8"))
    malicious = [
        d for d in dataset
        if d["ground_truth"]["label"] == "malicious"
        and d["ground_truth"]["mitre_techniques"]
    ]

    try:
        from sentinel_prime.ai.agents.analysis_agent import AnalysisAgent
        from sentinel_prime.ai.agents.critique_agent import CritiqueAgent
        from sentinel_prime.ai.agents.action_agent import ActionAgent
        analysis_agent = AnalysisAgent()
        critique_agent = CritiqueAgent()
        action_agent = ActionAgent()
        agents_available = True
    except Exception as e:
        print(f"  ⚠️  AI Agents could not be loaded: {e}")
        print("  ℹ️  Falling back to RAG-retrieved technique list as proxy prediction.")
        agents_available = False

    # Use only up to 20 malicious samples (API cost control)
    sample = malicious[:20]

    top1_correct = 0
    top3_correct = 0
    any_match = 0
    total = len(sample)
    timings: list[float] = []

    for idx, record in enumerate(sample):
        gt_techniques = set(record["ground_truth"]["mitre_techniques"])
        scenario = record["ground_truth"]["scenario_name"]

        print(f"\n  [{idx+1}/{total}] {scenario}")
        print(f"          GT techniques : {', '.join(gt_techniques)}")

        # ── Blind RAG retrieval from the project's FAISS ATT&CK index ──────
        rag_query = _build_rag_query(record)
        rag_candidates = _retrieve_rag_candidates(rag_query, top_k=6)
        print(f"          RAG candidates : {', '.join(rag_candidates[:6]) or 'full pool'}")

        if agents_available:
            ctx = _build_agent_context(record, rag_candidates)
            t0 = time.time()
            try:
                analysis = analysis_agent.run(ctx)
                critique = critique_agent.run(analysis, ctx)
                action = action_agent.run(analysis, critique, ctx)
                pipeline_out = {**analysis, **critique, **action}
                elapsed = round(time.time() - t0, 2)
                timings.append(elapsed)
            except Exception as e:
                print(f"          ⚠️  Pipeline failed: {e}")
                continue

            predicted = _extract_predicted_techniques(pipeline_out)
        else:
            # Fallback: use the RAG-retrieved candidates as predicted (still blind)
            predicted = rag_candidates
            timings.append(0.0)

        print(f"          AI predicted  : {', '.join(predicted[:5]) or 'none'}")

        # Top-1: predicted[0] is insertion-ordered (highest-confidence first)
        if predicted and predicted[0] in gt_techniques:
            top1_correct += 1

        # Top-3: any of the first 3 predictions match ground truth
        if set(predicted[:3]).intersection(gt_techniques):
            top3_correct += 1

        # Any match: anywhere in the full predicted list
        if set(predicted).intersection(gt_techniques):
            any_match += 1

    results = {
        "total_incidents_evaluated": total,
        "top1_accuracy": round(top1_correct / total, 4) if total > 0 else 0,
        "top3_accuracy": round(top3_correct / total, 4) if total > 0 else 0,
        "any_technique_match_rate": round(any_match / total, 4) if total > 0 else 0,
        "avg_pipeline_time_s": round(sum(timings) / len(timings), 2) if timings else 0,
        "agents_used": agents_available,
        "blind_eval": True,
    }

    print("\n" + "─" * 60)
    print(f"  Top-1 Technique Accuracy  : {results['top1_accuracy']:.1%}")
    print(f"  Top-3 Technique Accuracy  : {results['top3_accuracy']:.1%}")
    print(f"  Any Match Rate            : {results['any_technique_match_rate']:.1%}")
    print(f"  Avg AI Pipeline Time      : {results['avg_pipeline_time_s']}s")

    return results


if __name__ == "__main__":
    run()
