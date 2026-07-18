import os
import pickle
import faiss
import yaml
import time
import datetime
import concurrent.futures
import networkx as nx
from typing import Union, Dict, Any, List, Optional
from sentence_transformers import SentenceTransformer, CrossEncoder

# Constants
INDEX_DIR = os.path.join(os.path.dirname(__file__), "index")
INDEX_PATH = os.path.join(INDEX_DIR, "attack.index")
CHUNKS_PATH = os.path.join(INDEX_DIR, "chunks.pkl")

# Global variables for lazy loading
_index = None
_metadata = None
_model = None
_graph = None
_graph_config = {}
_ext_to_stix_cache = None
_providers = {}
_search_cache = {}
_cross_encoder = None

# Performance statistics tracker (Step 8)
_performance_metrics = {
    "query_count": 0,
    "cache_hits": 0,
    "total_latency_ms": 0.0,
    "provider_latencies_ms": {},
    "documents_searched": 0,
    "documents_returned": 0,
    "fusion_time_ms": 0.0,
    "cache_hit_rate": 0.0
}

def load_config():
    """Loads GraphRAG and Multi-Source configuration settings from sentinel_config.yaml."""
    global _graph_config
    
    # Default settings
    _graph_config = {
        "traversal_depth": 2,
        "expansion_size": 5,
        "max_related_entities": 20,
        "enable_graph_expansion": True,
        "cache_size": 1000,
        "graph_file_path": os.path.join(INDEX_DIR, "attack_graph.pkl"),
        "enabled_providers": ["attack", "d3fend", "sigma", "yara", "cve", "kev", "playbook", "policy", "threat_report"],
        "provider_weights": {
            "attack": 1.0,
            "d3fend": 1.0,
            "sigma": 0.8,
            "yara": 0.8,
            "cve": 0.9,
            "kev": 0.9,
            "playbook": 1.0,
            "policy": 0.9,
            "threat_report": 0.8
        },
        "max_documents": 15,
        "per_provider_limit": 5,
        "cache_ttl_seconds": 300,
        "timeout_seconds": 3.0
    }
    
    possible_paths = [
        "config/sentinel_config.yaml",
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "..", "config", "sentinel_config.yaml"))
    ]
    
    for path in possible_paths:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    cfg = yaml.safe_load(f)
                    if cfg and "graph_rag" in cfg:
                        _graph_config.update(cfg["graph_rag"])
                        break
            except Exception as e:
                print(f"Warning: Failed to load config from {path}: {e}")

def load_resources():
    """Lazily loads the FAISS index, metadata, embedding model, ATT&CK graph, and providers."""
    global _index, _metadata, _model, _graph, _graph_config, _providers, _cross_encoder
    
    if not _graph_config:
        load_config()
        
    if _index is None:
        if not os.path.exists(INDEX_PATH):
            raise FileNotFoundError(f"FAISS index not found at {INDEX_PATH}. Please run build_index.py first.")
        print("Loading FAISS index...")
        _index = faiss.read_index(INDEX_PATH)
        
    if _metadata is None:
        if not os.path.exists(CHUNKS_PATH):
            raise FileNotFoundError(f"Metadata not found at {CHUNKS_PATH}. Please run build_index.py first.")
        print("Loading metadata...")
        with open(CHUNKS_PATH, "rb") as f:
            _metadata = pickle.load(f)
            
    if _model is None:
        print("Loading SentenceTransformer model...")
        _model = SentenceTransformer('all-MiniLM-L6-v2')
        
    if _cross_encoder is None and _graph_config.get("enable_reranking", True):
        model_name = _graph_config.get("reranking_model", "cross-encoder/ms-marco-MiniLM-L-6-v2")
        print(f"Loading CrossEncoder re-ranking model '{model_name}'...")
        try:
            _cross_encoder = CrossEncoder(model_name)
        except Exception as e:
            print(f"Warning: Failed to load CrossEncoder model '{model_name}': {e}. Re-ranking will fall back to hybrid search scores.")
            _cross_encoder = None
            
    if _graph is None:
        graph_path = _graph_config.get("graph_file_path")
        if not graph_path or not os.path.exists(graph_path):
            graph_path = os.path.join(INDEX_DIR, "attack_graph.pkl")
            
        if graph_path and os.path.exists(graph_path):
            print(f"Loading ATT&CK graph from {graph_path}...")
            with open(graph_path, "rb") as f:
                _graph = pickle.load(f)
        else:
            print(f"Warning: ATT&CK threat graph not found at {graph_path}. ATT&CK expansion will be bypassed.")

    # Lazy-load secondary CTI providers (Step 1)
    from sentinel_prime.ai.agents.rag.providers.generic import GenericProvider
    from sentinel_prime.ai.agents.rag.providers.historical_incident import HistoricalIncidentProvider
    
    enabled = _graph_config.get("enabled_providers", [])
    for p_name in enabled:
        if p_name == "attack":
            continue
        if p_name == "historical_incident":
            if p_name not in _providers:
                try:
                    db_path = _graph_config.get("storage_path")
                    _providers[p_name] = HistoricalIncidentProvider(INDEX_DIR, db_path)
                except Exception as e:
                    print(f"Warning: Failed to load provider '{p_name}': {e}")
            continue
            
        if p_name not in _providers:
            try:
                _providers[p_name] = GenericProvider(p_name, INDEX_DIR)
            except Exception as e:
                print(f"Warning: Failed to load provider '{p_name}': {e}")

def _get_stix_node_by_ext_id(ext_id: str) -> Optional[str]:
    """Resolves an external technique ID (e.g. T1110) to its internal STIX ID in the graph."""
    global _ext_to_stix_cache, _graph
    if _graph is None:
        return None
        
    if _ext_to_stix_cache is None:
        _ext_to_stix_cache = {}
        for node, attrs in _graph.nodes(data=True):
            node_ext_id = attrs.get("external_id")
            if node_ext_id:
                _ext_to_stix_cache[node_ext_id.upper()] = node
                
    return _ext_to_stix_cache.get(ext_id.upper())

def traverse_and_expand_technique(start_stix_id: str, max_depth: int = 2) -> Dict[str, Any]:
    """
    Traverses the ATT&CK graph starting from a technique node.
    Collects related entities within max_depth hops and returns categorized entities.
    """
    global _graph
    if _graph is None or start_stix_id not in _graph:
        return {}
        
    expanded = {
        "groups": [],
        "software": [],
        "mitigations": [],
        "campaigns": [],
        "tactics": [],
        "subtechniques": [],
        "parent_technique": None,
        "traversal_paths": []
    }
    
    visited = {start_stix_id}
    queue = [(start_stix_id, 0, [])]  # (node, depth, path_accumulated)
    
    while queue:
        node, depth, path = queue.pop(0)
        
        if depth > 0:
            attrs = _graph.nodes[node]
            entity_type = attrs.get("type")
            item = {
                "id": attrs.get("external_id"),
                "stix_id": node,
                "name": attrs.get("name"),
                "type": entity_type,
                "description": attrs.get("description"),
                "graph_depth": depth,
                "confidence": round(max(0.1, 1.0 - (depth * 0.2)), 2)
            }
            
            if path:
                item["relationship_source"] = path[-1]["type"]
                
            if entity_type == "group":
                expanded["groups"].append(item)
            elif entity_type in ["malware", "tool"]:
                expanded["software"].append(item)
            elif entity_type == "mitigation":
                expanded["mitigations"].append(item)
            elif entity_type == "campaign":
                expanded["campaigns"].append(item)
            elif entity_type == "tactic":
                expanded["tactics"].append(item)
            elif entity_type == "sub-technique":
                expanded["subtechniques"].append(item)
            elif entity_type == "technique" and path and path[-1]["type"] == "subtechnique-of":
                expanded["parent_technique"] = item
                
        if depth >= max_depth:
            continue
            
        for successor in _graph.successors(node):
            if successor not in visited:
                edge_data = _graph.get_edge_data(node, successor)
                rel_type = edge_data.get("relationship_type", "related-to")
                visited.add(successor)
                new_path = path + [{"source": node, "target": successor, "type": rel_type}]
                queue.append((successor, depth + 1, new_path))
                expanded["traversal_paths"].append(new_path)
                
        for predecessor in _graph.predecessors(node):
            if predecessor not in visited:
                edge_data = _graph.get_edge_data(predecessor, node)
                rel_type = edge_data.get("relationship_type", "related-to")
                visited.add(predecessor)
                new_path = path + [{"source": predecessor, "target": node, "type": f"reverse-{rel_type}"}]
                queue.append((predecessor, depth + 1, new_path))
                expanded["traversal_paths"].append(new_path)
                
    return expanded

def _search_attack_internal(query_str: str, limit: int) -> List[Dict[str, Any]]:
    """Internal search execution specifically querying the MITRE ATT&CK vector/graph engine."""
    global _index, _metadata, _model, _graph, _graph_config
    
    query_vector = _model.encode([query_str])
    distances, indices = _index.search(query_vector, limit)
    
    traversal_depth = _graph_config.get("traversal_depth", 2)
    expansion_limit = _graph_config.get("expansion_size", 5)
    enable_expansion = _graph_config.get("enable_graph_expansion", True)
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    results = []
    for i, idx in enumerate(indices[0]):
        if idx != -1 and idx < len(_metadata):
            result = _metadata[idx].copy()
            dist = float(distances[0][i])
            
            # Map standard schema (Step 7)
            result["source"] = "attack"
            result["document_id"] = result["technique_id"]
            result["title"] = result["name"]
            result["entity_type"] = "technique"
            result["confidence"] = round(max(0.1, 1.0 - (dist / 10.0)), 2)
            result["similarity_score"] = dist
            result["graph_distance"] = 0.0
            result["graph_depth"] = 0
            result["relationship_source"] = "vector_search"
            result["version"] = "1.0"
            result["created_at"] = now_iso
            result["updated_at"] = now_iso
            result["tags"] = ["mitre_attack"]
            result["references"] = []
            result["citation"] = f"MITRE ATT&CK Technique {result['technique_id']}"
            
            # Graph properties
            result["parent_technique"] = None
            result["connected_software"] = []
            result["connected_groups"] = []
            result["connected_campaigns"] = []
            result["connected_mitigations"] = []
            result["connected_subtechniques"] = []
            
            if enable_expansion and _graph is not None:
                stix_id = _get_stix_node_by_ext_id(result["technique_id"])
                if stix_id:
                    expanded = traverse_and_expand_technique(stix_id, max_depth=traversal_depth)
                    
                    groups = expanded.get("groups", [])[:expansion_limit]
                    software = expanded.get("software", [])[:expansion_limit]
                    mitigations = expanded.get("mitigations", [])[:expansion_limit]
                    campaigns = expanded.get("campaigns", [])[:expansion_limit]
                    subtechs = expanded.get("subtechniques", [])[:expansion_limit]
                    
                    result["connected_groups"] = groups
                    result["connected_software"] = software
                    result["connected_mitigations"] = mitigations
                    result["connected_campaigns"] = campaigns
                    result["connected_subtechniques"] = subtechs
                    result["parent_technique"] = expanded.get("parent_technique")
                    
                    # Markdown summary append
                    rag_md = "\n\n### ATT&CK GraphRAG Enrichment"
                    if result["parent_technique"]:
                        rag_md += f"\n* **Parent Technique**: [{result['parent_technique']['id']}] {result['parent_technique']['name']}"
                    if subtechs:
                        rag_md += f"\n* **Sub-techniques**: " + ", ".join([f"[{s['id']}] {s['name']}" for s in subtechs])
                    if groups:
                        rag_md += f"\n* **Threat Groups**: " + ", ".join([f"[{g['id']}] {g['name']}" for g in groups])
                    if software:
                        rag_md += f"\n* **Malware & Tools**: " + ", ".join([f"[{s['id']}] {s['name']}" for s in software])
                    if mitigations:
                        rag_md += f"\n* **Mitigations**: " + ", ".join([f"[{m['id']}] {m['name']}" for m in mitigations])
                    if campaigns:
                        rag_md += f"\n* **Campaigns**: " + ", ".join([f"[{c['id']}] {c['name']}" for c in campaigns])
                        
                    result["description"] += rag_md
            
            # backward compatibility alias (Step 10)
            result["distance"] = dist
            result["score"] = dist
            
            results.append(result)
            
    return results

def route_query(query_str: str) -> List[str]:
    """Intelligently routes the query string to relevant threat intel providers based on keywords (Step 5)."""
    query_lower = query_str.lower()
    providers = []
    
    if "cve-" in query_lower or "cve" in query_lower or "vulnerability" in query_lower or "exploit" in query_lower:
        providers.extend(["cve", "kev"])
    if "mitigat" in query_lower or "defend" in query_lower or "prevent" in query_lower or "d3fend" in query_lower:
        providers.append("d3fend")
    if "yara" in query_lower or "signature" in query_lower:
        providers.append("yara")
    if "sigma" in query_lower or "log" in query_lower or "detect" in query_lower:
        providers.append("sigma")
    if "playbook" in query_lower or "remediat" in query_lower or "containment" in query_lower:
        providers.append("playbook")
    if "policy" in query_lower or "corporate" in query_lower or "compliance" in query_lower:
        providers.append("policy")
    if "report" in query_lower or "intel" in query_lower or "actor" in query_lower:
        providers.append("threat_report")
    if "past" in query_lower or "history" in query_lower or "previous" in query_lower or "incident" in query_lower:
        providers.append("historical_incident")
        
    # Default to attack technique lookup if general or matching specific terms
    if not providers or any(k in query_lower for k in ["technique", "t1", "ssh", "power", "login", "malicious", "attack"]):
        providers.append("attack")
        
    return list(set(providers))

def compute_trust_score(doc: Dict[str, Any], config: Dict[str, Any]) -> float:
    """Computes a dynamic Trust Score for a retrieved document (Step 12)."""
    weights = config.get("trust_weights", {})
    official_w = weights.get("official_source", 1.0)
    community_w = weights.get("community_source", 0.8)
    internal_w = weights.get("internal_knowledge", 0.95)
    conf_factor = weights.get("confidence_factor", 0.2)
    comp_factor = weights.get("completeness_factor", 0.1)
    
    source = doc.get("source", "generic")
    
    if source in ["attack", "d3fend", "cve", "kev"]:
        base_trust = official_w
    elif source in ["sigma", "yara"]:
        base_trust = community_w
    elif source in ["playbook", "policy", "historical_incident"]:
        base_trust = internal_w
    else:
        base_trust = 0.8
        
    doc_conf = float(doc.get("confidence", 1.0))
    
    required_keys = ["description", "tags", "references", "version"]
    non_empty = sum(1 for k in required_keys if doc.get(k))
    completeness = non_empty / len(required_keys)
    
    val_status = doc.get("validation_status", "validated")
    val_factor = 1.0 if val_status == "validated" else 0.7
    
    score = (base_trust * val_factor) + (doc_conf * conf_factor) + (completeness * comp_factor)
    return float(round(min(1.0, max(0.0, score)), 4))

def compute_freshness(doc: Dict[str, Any], config: Dict[str, Any]) -> tuple:
    """Evaluates the Freshness Score, Freshness Category, and Last Updated date (Step 12)."""
    thresholds = config.get("freshness_thresholds", {})
    fresh_max = thresholds.get("fresh_max_days", 180)
    stale_max = thresholds.get("stale_max_days", 365)
    
    last_updated_str = doc.get("updated_at") or doc.get("created_at") or doc.get("timestamp")
    
    tags = [t.lower() for t in doc.get("tags", [])]
    status = doc.get("status", "").lower()
    
    if "deprecated" in tags or status == "deprecated":
        return 0.0, "deprecated", last_updated_str or ""
        
    now = datetime.datetime.now(datetime.timezone.utc)
    
    if last_updated_str:
        try:
            cleaned_str = last_updated_str.replace("Z", "+00:00")
            dt = datetime.datetime.fromisoformat(cleaned_str)
            age_days = (now - dt).days
        except Exception:
            age_days = 90
    else:
        age_days = 90
        
    if age_days <= fresh_max:
        category = "fresh"
        score = 1.0 - (0.3 * (age_days / fresh_max))
    elif age_days <= stale_max:
        category = "stale"
        score = 0.7 - (0.3 * ((age_days - fresh_max) / (stale_max - fresh_max)))
    else:
        category = "deprecated"
        score = max(0.0, 0.4 - (0.4 * ((age_days - stale_max) / 730)))
        
    return float(round(score, 4)), category, last_updated_str or ""

def rerank_candidates(query_str: str, candidates: List[Dict[str, Any]], limit: int) -> List[Dict[str, Any]]:
    """Re-ranks retrieved candidates using a Cross-Encoder model (Step 12)."""
    global _cross_encoder
    if not candidates:
        return []
        
    if _cross_encoder is None:
        for doc in candidates:
            doc["cross_encoder_score"] = float(doc.get("rrf_score", 0.0))
        return candidates[:limit]
        
    pairs = []
    for doc in candidates:
        title = doc.get("title") or doc.get("name") or ""
        desc = doc.get("description", "")
        pairs.append((query_str, f"{title} {desc}"))
        
    try:
        raw_scores = _cross_encoder.predict(pairs)
    except Exception as e:
        print(f"Error during Cross-Encoder prediction: {e}. Bypassing re-ranking.")
        for doc in candidates:
            doc["cross_encoder_score"] = float(doc.get("rrf_score", 0.0))
        return candidates[:limit]
        
    if len(raw_scores) > 1:
        min_s = min(raw_scores)
        max_s = max(raw_scores)
        diff = max_s - min_s
        if diff > 0.0:
            norm_scores = [(s - min_s) / diff for s in raw_scores]
        else:
            norm_scores = [1.0] * len(raw_scores)
    else:
        norm_scores = [1.0] if len(raw_scores) == 1 else []
        
    for i, doc in enumerate(candidates):
        doc["cross_encoder_score"] = float(round(norm_scores[i], 4))
        
    def sorting_key(doc):
        ce_score = doc.get("cross_encoder_score", 0.0)
        sim = -doc.get("similarity_score", doc.get("distance", 999.0))
        doc_id = doc.get("document_id", "")
        return (ce_score, sim, doc_id)
        
    sorted_docs = sorted(candidates, key=sorting_key, reverse=True)
    return sorted_docs[:limit]

def reciprocal_rank_fusion(
    dense_results: List[Dict[str, Any]],
    lexical_results: List[Dict[str, Any]],
    limit: int,
    k: int = 60,
    dense_weight: float = 1.0,
    lexical_weight: float = 0.8,
    provider_weights: Optional[Dict[str, float]] = None
) -> List[Dict[str, Any]]:
    """
    Executes Reciprocal Rank Fusion (RRF) on retrieved dense and lexical document hits (Step 6 & 7).
    """
    rrf_scores = {}
    doc_map = {}
    
    # 1. Rank dense results
    for rank, doc in enumerate(dense_results, start=1):
        key = (doc.get("source"), doc.get("document_id"))
        doc_map[key] = doc
        doc_weight = doc.get("confidence", 1.0)
        rrf_scores[key] = rrf_scores.get(key, 0.0) + dense_weight * doc_weight / (k + rank)
        
    # 2. Rank lexical results
    for rank, doc in enumerate(lexical_results, start=1):
        key = (doc.get("source"), doc.get("document_id"))
        if key not in doc_map:
            doc_map[key] = doc
        else:
            existing = doc_map[key]
            if "bm25_score" not in existing:
                existing["bm25_score"] = doc.get("bm25_score")
            # Merge list metadata
            for field in ["tags", "references"]:
                if field in doc and field in existing:
                    existing[field] = list(set(existing[field] + doc[field]))
                    
        doc_weight = doc.get("confidence", 1.0)
        rrf_scores[key] = rrf_scores.get(key, 0.0) + lexical_weight * doc_weight / (k + rank)
        
    # 3. Apply provider weighting (Step 6)
    p_weights = provider_weights or {}
    for key in rrf_scores.keys():
        source = key[0]
        p_weight = p_weights.get(source, 1.0)
        rrf_scores[key] *= p_weight
        
    # 4. Tie-breaking sorting (Step 6)
    def sorting_key(item):
        key, rrf_score = item
        doc = doc_map[key]
        sim = -doc.get("similarity_score", doc.get("distance", 999.0))
        bm25 = doc.get("bm25_score", 0.0)
        doc_id = doc.get("document_id", "")
        return (rrf_score, sim, bm25, doc_id)
        
    sorted_items = sorted(rrf_scores.items(), key=sorting_key, reverse=True)
    
    # 5. Populate ranking metadata (Step 8)
    fused_results = []
    for key, rrf_score in sorted_items[:limit]:
        doc = doc_map[key].copy()
        
        has_dense = any(d.get("document_id") == doc["document_id"] and d.get("source") == doc["source"] for d in dense_results)
        has_lexical = any(l.get("document_id") == doc["document_id"] and l.get("source") == doc["source"] for l in lexical_results)
        
        if has_dense and has_lexical:
            ret_method = "hybrid"
        elif has_dense:
            ret_method = "dense"
        else:
            ret_method = "lexical"
            
        doc["dense_score"] = float(doc.get("similarity_score", doc.get("distance", 999.0)))
        doc["bm25_score"] = float(doc.get("bm25_score", 0.0))
        doc["rrf_score"] = float(rrf_score)
        doc["retrieval_method"] = ret_method
        doc["provider"] = doc.get("source")
        doc["similarity"] = float(doc.get("similarity_score", doc.get("distance", 999.0)))
        
        fused_results.append(doc)
        
    return fused_results

def _query_dense_provider(provider_name: str, query_str: str, limit: int) -> List[Dict[str, Any]]:
    """Helper to retrieve dense semantic documents from a specific provider (Step 4 & 5)."""
    global _providers
    if provider_name == "attack":
        if "attack" not in _providers:
            from sentinel_prime.ai.agents.rag.providers.attack import AttackProvider
            _providers["attack"] = AttackProvider(INDEX_DIR)
        return _providers["attack"].dense_search(query_str, limit)
    elif provider_name in _providers:
        if hasattr(_providers[provider_name], "dense_search"):
            return _providers[provider_name].dense_search(query_str, limit)
        return _providers[provider_name].search(query_str, limit)
    return []

def _query_bm25_provider(provider_name: str, query_str: str, limit: int) -> List[Dict[str, Any]]:
    """Helper to retrieve lexical documents from a specific provider (Step 5)."""
    global _providers
    if provider_name == "attack":
        if "attack" not in _providers:
            from sentinel_prime.ai.agents.rag.providers.attack import AttackProvider
            _providers["attack"] = AttackProvider(INDEX_DIR)
        return _providers["attack"].bm25_search(query_str, limit)
    elif provider_name in _providers:
        if hasattr(_providers[provider_name], "bm25_search"):
            return _providers[provider_name].bm25_search(query_str, limit)
    return []

def merge_and_deduplicate(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Fuses multiple source answers, prioritizing scores while removing duplicate documents (Step 7)."""
    seen = set()
    deduped = []
    
    results_sorted = sorted(results, key=lambda x: x.get("similarity_score", 999.0))
    for item in results_sorted:
        key = (item.get("source"), item.get("document_id"))
        if key not in seen:
            seen.add(key)
            # Ensure standard fields are populated
            doc = item.copy()
            doc["dense_score"] = float(doc.get("similarity_score", doc.get("distance", 999.0)))
            doc["bm25_score"] = float(doc.get("bm25_score", 0.0))
            doc["rrf_score"] = 0.0
            doc["retrieval_method"] = doc.get("retrieval_method", "dense")
            doc["provider"] = doc.get("source")
            doc["similarity"] = float(doc.get("similarity_score", doc.get("distance", 999.0)))
            deduped.append(doc)
            
    return deduped

def search(
    query: str,
    top_k: int = 5,
    include_graph_details: bool = False,
    traversal_depth: Optional[int] = None,
    enable_expansion: Optional[bool] = None,
    enabled_providers: Optional[List[str]] = None
) -> Union[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Optimized Orchestrator: normalizes, routes, parallel retrieves, RRF merges, re-ranks (CrossEncoder),
    generates trust/freshness scores, citations, and caches results (Step 12).
    """
    start_search_time = time.time()
    global _performance_metrics, _search_cache
    
    cache_key = (query, top_k, include_graph_details, traversal_depth, enable_expansion, tuple(enabled_providers) if enabled_providers else None)
    now_time = time.time()
    
    load_resources()
    ttl = _graph_config.get("cache_ttl_seconds", 300)
    
    if cache_key in _search_cache:
        cached_val, timestamp = _search_cache[cache_key]
        if now_time - timestamp < ttl:
            _performance_metrics["cache_hits"] += 1
            _performance_metrics["query_count"] += 1
            _performance_metrics["cache_hit_rate"] = _performance_metrics["cache_hits"] / _performance_metrics["query_count"]
            return cached_val
            
    _performance_metrics["query_count"] += 1
    
    if enabled_providers is None:
        routed_sources = route_query(query)
        active_config_providers = _graph_config.get("enabled_providers", ["attack"])
        enabled_providers = [p for p in routed_sources if p in active_config_providers]
        
    if not enabled_providers:
        enabled_providers = ["attack"]
        
    # Read optimization configurations
    enable_reranking = _graph_config.get("enable_reranking", True)
    reranking_top_n = _graph_config.get("reranking_top_n", 15)
    final_top_k = _graph_config.get("final_top_k", top_k)
    
    # Candidate retrieval limit
    candidate_limit = reranking_top_n if enable_reranking else final_top_k
    
    per_provider_limit = _graph_config.get("per_provider_limit", 5)
    timeout = _graph_config.get("timeout_seconds", 3.0)
    
    enable_dense = _graph_config.get("enable_dense", True)
    enable_bm25 = _graph_config.get("enable_bm25", True)
    enable_hybrid = _graph_config.get("enable_hybrid", True)
    
    all_dense = []
    all_lexical = []
    
    # Parallel dispatch
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(enabled_providers) * 2) as executor:
        dense_futures = {}
        lexical_futures = {}
        
        if enable_dense:
            dense_futures = {
                executor.submit(_query_dense_provider, p_name, query, per_provider_limit): p_name
                for p_name in enabled_providers
            }
        if enable_bm25:
            lexical_futures = {
                executor.submit(_query_bm25_provider, p_name, query, per_provider_limit): p_name
                for p_name in enabled_providers
            }
            
        if dense_futures:
            try:
                for future in concurrent.futures.as_completed(dense_futures, timeout=timeout):
                    p_name = dense_futures[future]
                    try:
                        all_dense.extend(future.result())
                    except Exception as e:
                        print(f"Error querying dense provider '{p_name}': {e}")
            except concurrent.futures.TimeoutError:
                print("Warning: Dense search timed out.")
                
        if lexical_futures:
            try:
                for future in concurrent.futures.as_completed(lexical_futures, timeout=timeout):
                    p_name = lexical_futures[future]
                    try:
                        all_lexical.extend(future.result())
                    except Exception as e:
                        print(f"Error querying lexical provider '{p_name}': {e}")
            except concurrent.futures.TimeoutError:
                print("Warning: Lexical search timed out.")
                
    # Hybrid fusion
    start_fusion_time = time.time()
    fusion_time = 0.0
    
    if enable_hybrid and enable_dense and enable_bm25:
        merged_results = reciprocal_rank_fusion(
            all_dense,
            all_lexical,
            candidate_limit,
            k=_graph_config.get("rrf_k", 60),
            dense_weight=_graph_config.get("dense_weight", 1.0),
            lexical_weight=_graph_config.get("bm25_weight", 0.8),
            provider_weights=_graph_config.get("provider_weights", {})
        )
        fusion_time = (time.time() - start_fusion_time) * 1000.0
    elif enable_dense:
        merged_results = merge_and_deduplicate(all_dense)[:candidate_limit]
    elif enable_bm25:
        merged_results = merge_and_deduplicate(all_lexical)[:candidate_limit]
    else:
        merged_results = []
        
    # Re-ranking using Cross-Encoder (Part A)
    if enable_reranking and _cross_encoder is not None:
        merged_results = rerank_candidates(query, merged_results, final_top_k)
    else:
        merged_results = merged_results[:final_top_k]
        
    # Populate freshness, trust, and citation metadata (Part C, D, E)
    final_results = []
    for rank_idx, doc in enumerate(merged_results, start=1):
        doc_copy = doc.copy()
        
        trust_score = compute_trust_score(doc_copy, _graph_config)
        fresh_score, fresh_cat, last_updated = compute_freshness(doc_copy, _graph_config)
        
        doc_copy["trust_score"] = trust_score
        doc_copy["freshness_score"] = fresh_score
        doc_copy["freshness_category"] = fresh_cat
        doc_copy["last_updated"] = last_updated
        
        doc_copy["provider"] = doc_copy.get("source")
        doc_copy["timestamp"] = last_updated or doc_copy.get("created_at") or ""
        doc_copy["rank"] = rank_idx
        doc_copy["citation_identifier"] = f"[{doc_copy['provider']}:{doc_copy['document_id']}]"
        
        refs = doc_copy.get("references", [])
        doc_copy["original_url"] = refs[0] if refs else ""
        if not doc_copy["original_url"] and doc_copy["provider"] == "attack":
            doc_copy["original_url"] = f"https://attack.mitre.org/techniques/{doc_copy['document_id']}/"
            
        # Standard score conversion aliases (crucial to prevent downstream NoneType typeerrors)
        sim_score = float(doc_copy.get("similarity_score", doc_copy.get("distance", 999.0)))
        doc_copy["similarity_score"] = sim_score
        doc_copy["distance"] = sim_score
        doc_copy["score"] = sim_score
        doc_copy["name"] = doc_copy.get("title", "")
        doc_copy["technique_id"] = doc_copy.get("document_id", "")
        
        final_results.append(doc_copy)
        
    total_duration = (time.time() - start_search_time) * 1000.0
    
    _performance_metrics["total_latency_ms"] = total_duration
    _performance_metrics["fusion_time_ms"] = fusion_time
    _performance_metrics["documents_searched"] = len(all_dense) + len(all_lexical)
    _performance_metrics["documents_returned"] = len(final_results)
    _performance_metrics["cache_hit_rate"] = _performance_metrics["cache_hits"] / _performance_metrics["query_count"]
    
    # Formulate explanation response
    if include_graph_details:
        explanation_list = [
            f"Provider '{r['source']}' matched [{r['document_id']}] {r['title']} (Score: {r['similarity_score']:.4f}, Method: {r['retrieval_method']})"
            for r in final_results
        ]
        
        all_connected = []
        all_paths = []
        for r in final_results:
            if r.get("source") == "attack":
                all_connected.extend(
                    r.get("connected_software", []) +
                    r.get("connected_groups", []) +
                    r.get("connected_mitigations", []) +
                    r.get("connected_campaigns", [])
                )
                
        original_exps = []
        for r in final_results:
            if r.get("source") == "attack":
                groups_len = len(r.get("connected_groups", []))
                software_len = len(r.get("connected_software", []))
                mitigations_len = len(r.get("connected_mitigations", []))
                
                parts = []
                if groups_len > 0:
                    parts.append(f"{groups_len} group(s)")
                if software_len > 0:
                    parts.append(f"{software_len} software item(s)")
                if mitigations_len > 0:
                    parts.append(f"{mitigations_len} mitigation(s)")
                
                expl = f"Candidate [{r['technique_id']}] {r['title']} points to: "
                expl += (", ".join(parts) if parts else "0 related objects") + "."
                original_exps.append(expl)
                
        combined_expls = explanation_list + original_exps
        
        output_data = {
            "results": final_results,
            "connected_entities": all_connected[:_graph_config.get("max_related_entities", 20)],
            "traversal_explanation": " | ".join(combined_expls),
            "traversal_paths": all_paths,
            "performance": _performance_metrics.copy(),
            "graph": {
                "nodes": [{"stix_id": n, **_graph.nodes[n]} for n in _graph.nodes] if _graph else [],
                "edges": [{"source": u, "target": v, **_graph.get_edge_data(u, v)} for u, v in _graph.edges] if _graph else []
            }
        }
    else:
        output_data = final_results
        
    _search_cache[cache_key] = (output_data, time.time())
    
    return output_data

if __name__ == "__main__":
    try:
        print("Testing Multi-Source RAG search query routing...")
        print("\nQuery: failed SSH logins (Expected: attack or sigma)")
        res1 = search("failed SSH logins", top_k=2)
        for r in res1:
            print(f"  - [{r['source'].upper()}] ID: {r['document_id']} | Title: {r['title']}")
            
        print("\nQuery: CVE vulnerability (Expected: cve or kev)")
        res2 = search("CVE vulnerability", top_k=2)
        for r in res2:
            print(f"  - [{r['source'].upper()}] ID: {r['document_id']} | Title: {r['title']}")
            
        print("\nQuery: Policy deployment CNI (Expected: policy)")
        res3 = search("Policy deployment CNI", top_k=2)
        for r in res3:
            print(f"  - [{r['source'].upper()}] ID: {r['document_id']} | Title: {r['title']}")
            
    except Exception as e:
        print(f"Error during Multi-Source test: {e}")


