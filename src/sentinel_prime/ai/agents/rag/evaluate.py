import time
import math
import numpy as np
from typing import List, Dict, Any, Tuple
import sentinel_prime.ai.agents.rag.query as query

# Ground truth dataset for evaluation (Step 11)
EVAL_DATASET = [
    {
        "query": "SSH brute force attempts on server logging services",
        "ground_truth": [("attack", "T1110"), ("historical_incident", "INC-2024-089")]
    },
    {
        "query": "PowerShell base64 script execution containment",
        "ground_truth": [("attack", "T1059.001")]
    },
    {
        "query": "Log correlation rule for active directory changes",
        "ground_truth": [("sigma", "SIG-001")]
    },
    {
        "query": "CVE vulnerability exploit in web applications",
        "ground_truth": [("cve", "CVE-2023-38606")]
    }
]

def calculate_precision_recall_at_k(retrieved: List[Tuple[str, str]], ground_truth: List[Tuple[str, str]], k: int) -> Tuple[float, float]:
    """Computes Precision@K and Recall@K."""
    if not ground_truth:
        return 0.0, 0.0
    ret_k = retrieved[:k]
    hits = sum(1 for doc in ret_k if doc in ground_truth)
    precision = hits / k if k > 0 else 0.0
    recall = hits / len(ground_truth)
    return precision, recall

def calculate_mrr(retrieved: List[Tuple[str, str]], ground_truth: List[Tuple[str, str]]) -> float:
    """Computes Mean Reciprocal Rank (MRR)."""
    for rank, doc in enumerate(retrieved, start=1):
        if doc in ground_truth:
            return 1.0 / rank
    return 0.0

def calculate_ndcg(retrieved: List[Tuple[str, str]], ground_truth: List[Tuple[str, str]], k: int) -> float:
    """Computes Normalized Discounted Cumulative Gain (NDCG) at K."""
    ret_k = retrieved[:k]
    dcg = 0.0
    for rank, doc in enumerate(ret_k, start=1):
        if doc in ground_truth:
            dcg += 1.0 / math.log2(rank + 1)
            
    # Ideal DCG (all ground truth items placed at top)
    idcg = sum(1.0 / math.log2(i + 1) for i in range(1, min(len(ground_truth), k) + 1))
    return dcg / idcg if idcg > 0.0 else 0.0

def run_evaluation_for_config(config_settings: Dict[str, Any], k: int = 5) -> Dict[str, float]:
    """Runs evaluation queries over the RAG pipeline under a specific configuration."""
    # Temporarily override configuration settings
    original_config = query._graph_config.copy()
    query._graph_config.update(config_settings)
    
    precisions = []
    recalls = []
    mrrs = []
    ndcgs = []
    latencies = []
    
    provider_hits = {}
    
    for case in EVAL_DATASET:
        q_str = case["query"]
        gt = case["ground_truth"]
        
        # Invalidate cache for evaluation consistency
        query._search_cache.clear()
        
        start_time = time.time()
        results = query.search(q_str, top_k=k)
        duration = (time.time() - start_time) * 1000.0
        
        # Check standard list format
        if isinstance(results, dict):
            results_list = results.get("results", [])
        else:
            results_list = results
            
        retrieved_keys = [(r.get("source"), r.get("document_id")) for r in results_list]
        
        # Compute metrics
        prec, rec = calculate_precision_recall_at_k(retrieved_keys, gt, k)
        mrr = calculate_mrr(retrieved_keys, gt)
        ndcg = calculate_ndcg(retrieved_keys, gt, k)
        
        precisions.append(prec)
        recalls.append(rec)
        mrrs.append(mrr)
        ndcgs.append(ndcg)
        latencies.append(duration)
        
        # Track provider contributions
        for r in results_list:
            if (r.get("source"), r.get("document_id")) in gt:
                provider_hits[r.get("source")] = provider_hits.get(r.get("source"), 0) + 1
                
    # Restore original config
    query._graph_config = original_config
    
    return {
        "precision": float(np.mean(precisions)),
        "recall": float(np.mean(recalls)),
        "mrr": float(np.mean(mrrs)),
        "ndcg": float(np.mean(ndcgs)),
        "latency_ms": float(np.mean(latencies)),
        "hits": provider_hits
    }

def evaluate_all():
    """Executes Dense, Lexical, Hybrid, and Re-ranked configurations, compiling results (Step 11 & 12)."""
    print("Initializing RAG Retrieval Evaluation Engine...")
    query.load_resources()
    
    # 1. Evaluate Dense Only
    dense_cfg = {"enable_dense": True, "enable_bm25": False, "enable_hybrid": False, "enable_reranking": False}
    dense_metrics = run_evaluation_for_config(dense_cfg)
    
    # 2. Evaluate Lexical Only
    lexical_cfg = {"enable_dense": False, "enable_bm25": True, "enable_hybrid": False, "enable_reranking": False}
    lexical_metrics = run_evaluation_for_config(lexical_cfg)
    
    # 3. Evaluate Hybrid
    hybrid_cfg = {"enable_dense": True, "enable_bm25": True, "enable_hybrid": True, "enable_reranking": False}
    hybrid_metrics = run_evaluation_for_config(hybrid_cfg)
    
    # 4. Evaluate Re-ranked (Hybrid + Cross-Encoder)
    rerank_cfg = {"enable_dense": True, "enable_bm25": True, "enable_hybrid": True, "enable_reranking": True}
    rerank_metrics = run_evaluation_for_config(rerank_cfg)
    
    print("\n==========================================================================================")
    print("                              RAG OPTIMIZATION REPORT                                     ")
    print("==========================================================================================")
    print(f"{'Metric':<18} | {'Dense Only':<12} | {'BM25 Only':<12} | {'Hybrid (RRF)':<14} | {'Re-ranked (CE)':<15}")
    print("-" * 90)
    print(f"{'Precision@5':<18} | {dense_metrics['precision']:.4f}       | {lexical_metrics['precision']:.4f}       | {hybrid_metrics['precision']:.4f}       | {rerank_metrics['precision']:.4f}")
    print(f"{'Recall@5':<18} | {dense_metrics['recall']:.4f}       | {lexical_metrics['recall']:.4f}       | {hybrid_metrics['recall']:.4f}       | {rerank_metrics['recall']:.4f}")
    print(f"{'MRR':<18} | {dense_metrics['mrr']:.4f}       | {lexical_metrics['mrr']:.4f}       | {hybrid_metrics['mrr']:.4f}       | {rerank_metrics['mrr']:.4f}")
    print(f"{'NDCG@5':<18} | {dense_metrics['ndcg']:.4f}       | {lexical_metrics['ndcg']:.4f}       | {hybrid_metrics['ndcg']:.4f}       | {rerank_metrics['ndcg']:.4f}")
    print(f"{'Avg Latency':<18} | {dense_metrics['latency_ms']:.2f}ms        | {lexical_metrics['latency_ms']:.2f}ms        | {hybrid_metrics['latency_ms']:.2f}ms        | {rerank_metrics['latency_ms']:.2f}ms")
    print("==========================================================================================")
    
    # Compute relative improvements (Step 12)
    print("\n[+] RE-RANKING IMPROVEMENT OVER HYBRID (RRF):")
    mrr_diff = ((rerank_metrics["mrr"] - hybrid_metrics["mrr"]) / hybrid_metrics["mrr"] * 100.0) if hybrid_metrics["mrr"] > 0 else 0.0
    ndcg_diff = ((rerank_metrics["ndcg"] - hybrid_metrics["ndcg"]) / hybrid_metrics["ndcg"] * 100.0) if hybrid_metrics["ndcg"] > 0 else 0.0
    print(f"  - MRR Relative Gain: +{mrr_diff:.2f}%")
    print(f"  - NDCG@5 Relative Gain: +{ndcg_diff:.2f}%")
    
    print("\n[+] HYBRID + RE-RANKING OVER DENSE-ONLY (Cumulative Gain):")
    mrr_cum = ((rerank_metrics["mrr"] - dense_metrics["mrr"]) / dense_metrics["mrr"] * 100.0) if dense_metrics["mrr"] > 0 else 0.0
    ndcg_cum = ((rerank_metrics["ndcg"] - dense_metrics["ndcg"]) / dense_metrics["ndcg"] * 100.0) if dense_metrics["ndcg"] > 0 else 0.0
    print(f"  - MRR Cumulative Gain: +{mrr_cum:.2f}%")
    print(f"  - NDCG@5 Cumulative Gain: +{ndcg_cum:.2f}%")
    
    print("\n[+] PROVIDER CONTRIBUTION ANALYSIS (Hits count in Re-ranked mode):")
    for prov, hits in rerank_metrics["hits"].items():
        print(f"  - {prov}: {hits} successful ground-truth hits retrieved.")
        
    print("==========================================================================================")

if __name__ == "__main__":
    evaluate_all()
