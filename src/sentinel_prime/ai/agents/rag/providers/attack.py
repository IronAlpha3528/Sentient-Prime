import os
import pickle
import datetime
import faiss
from typing import List, Dict, Any, Optional
from sentence_transformers import SentenceTransformer
from sentinel_prime.ai.agents.rag.providers.base import BaseProvider
from sentinel_prime.ai.agents.rag.providers.bm25 import BM25Index

class AttackProvider(BaseProvider):
    """
    Retrieval provider for MITRE ATT&CK Enterprise Matrix data,
    supporting Dense, Lexical, Hybrid, and GraphRAG expansion (Step 1).
    """
    def __init__(self, index_dir: str):
        self.name = "attack"
        self.index_dir = index_dir
        self.index_path = os.path.join(index_dir, "attack.index")
        self.chunks_path = os.path.join(index_dir, "chunks.pkl")
        self.bm25_path = os.path.join(index_dir, "attack.bm25")
        self.graph_path = os.path.join(index_dir, "attack_graph.pkl")
        
        self._index = None
        self._metadata = None
        self._model = None
        self._bm25 = None
        self._graph = None

    def _load_resources(self):
        """Lazily loads models, FAISS, Graph, and BM25 index."""
        from sentinel_prime.ai.agents.rag.resource_manager import ResourceManager
        mgr = ResourceManager()
        
        if self._index is None:
            self._index = mgr.get_faiss_index(self.index_path)
            
        if self._metadata is None:
            self._metadata = mgr.get_metadata(self.chunks_path)
                
        if self._model is None:
            self._model = mgr.get_sentence_transformer('all-MiniLM-L6-v2')
            
        if self._bm25 is None:
            self._bm25 = mgr.get_bm25_index(self.bm25_path)
                
        if self._graph is None:
            self._graph = mgr.get_graph(self.graph_path)

    def ingest(self, raw_data_path: str) -> None:
        """Indexes parsed MITRE techniques lexically using BM25Index (Step 2)."""
        if not os.path.exists(self.chunks_path):
            raise FileNotFoundError(f"MITRE ATT&CK chunks metadata not found at {self.chunks_path}")
            
        with open(self.chunks_path, "rb") as f:
            techniques = pickle.load(f)
            
        bm25_idx = BM25Index()
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        for t in techniques:
            doc_id = t.get("technique_id")
            doc_metadata = {
                "source": "attack",
                "document_id": doc_id,
                "title": t.get("name"),
                "description": t.get("description"),
                "entity_type": "technique",
                "confidence": 1.0,
                "version": "1.0",
                "created_at": now_iso,
                "updated_at": now_iso,
                "tags": ["mitre_attack"],
                "references": [],
                "citation": f"MITRE ATT&CK Technique {doc_id}",
                # Graph specific fields
                "parent_technique": None,
                "connected_software": [],
                "connected_groups": [],
                "connected_campaigns": [],
                "connected_mitigations": [],
                "connected_subtechniques": [],
                # Backward-compatible fields
                "technique_id": doc_id,
                "name": t.get("name"),
                "description": t.get("description")
            }
            text = f"Title: {t.get('name')}\nDescription: {t.get('description')}"
            bm25_idx.add_document(doc_id, text, doc_metadata)
            
        bm25_idx.save(self.bm25_path)
        self._bm25 = bm25_idx

    def dense_search(self, query: str, limit: int) -> List[Dict[str, Any]]:
        """Queries the MITRE ATT&CK FAISS dense index with GraphRAG traversal (Step 4 & 5)."""
        self._load_resources()
        
        query_vector = self._model.encode([query])
        distances, indices = self._index.search(query_vector, limit)
        
        from sentinel_prime.ai.agents.rag.query import _graph_config
        traversal_depth = _graph_config.get("traversal_depth", 2)
        expansion_limit = _graph_config.get("expansion_size", 5)
        enable_expansion = _graph_config.get("enable_graph_expansion", True)
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        results = []
        for i, idx in enumerate(indices[0]):
            if idx != -1 and idx < len(self._metadata):
                t = self._metadata[idx]
                doc_id = t.get("technique_id")
                
                result = {
                    "source": "attack",
                    "document_id": doc_id,
                    "title": t.get("name"),
                    "description": t.get("description"),
                    "entity_type": "technique",
                    "confidence": float(round(max(0.1, 1.0 - (float(distances[0][i]) / 10.0)), 2)),
                    "similarity_score": float(distances[0][i]),
                    "graph_distance": 0.0,
                    "graph_depth": 0,
                    "relationship_source": "vector_search",
                    "version": "1.0",
                    "created_at": now_iso,
                    "updated_at": now_iso,
                    "tags": ["mitre_attack"],
                    "references": [],
                    "citation": f"MITRE ATT&CK Technique {doc_id}",
                    # Graph attributes
                    "parent_technique": None,
                    "connected_software": [],
                    "connected_groups": [],
                    "connected_campaigns": [],
                    "connected_mitigations": [],
                    "connected_subtechniques": [],
                    # Backward-compatible fields
                    "technique_id": doc_id,
                    "name": t.get("name"),
                    "distance": float(distances[0][i]),
                    "score": float(distances[0][i])
                }
                
                # Perform NetworkX Graph Expansion
                if enable_expansion and self._graph is not None:
                    from sentinel_prime.ai.agents.rag.query import _get_stix_node_by_ext_id, traverse_and_expand_technique
                    stix_id = _get_stix_node_by_ext_id(doc_id)
                    if stix_id:
                        expanded = traverse_and_expand_technique(stix_id, max_depth=traversal_depth)
                        
                        subtechs = expanded.get("subtechniques", [])[:expansion_limit]
                        groups = expanded.get("groups", [])[:expansion_limit]
                        software = expanded.get("software", [])[:expansion_limit]
                        mitigations = expanded.get("mitigations", [])[:expansion_limit]
                        campaigns = expanded.get("campaigns", [])[:expansion_limit]
                        
                        result["connected_subtechniques"] = subtechs
                        result["connected_groups"] = groups
                        result["connected_software"] = software
                        result["connected_mitigations"] = mitigations
                        result["connected_campaigns"] = campaigns
                        result["parent_technique"] = expanded.get("parent_technique")
                        
                        # Append the standard ATT&CK graph details directly into description
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
                        
                results.append(result)
                
        return results

    def bm25_search(self, query: str, limit: int, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Queries the MITRE ATT&CK lexical BM25 index with GraphRAG traversal (Step 5)."""
        self._load_resources()
        
        bm25_results = self._bm25.search(query, limit, filters)
        
        from sentinel_prime.ai.agents.rag.query import _graph_config
        traversal_depth = _graph_config.get("traversal_depth", 2)
        expansion_limit = _graph_config.get("expansion_size", 5)
        enable_expansion = _graph_config.get("enable_graph_expansion", True)
        
        results = []
        for r in bm25_results:
            doc_id = r.get("document_id")
            
            result = r.copy()
            # Default fallback score for similarity
            result["similarity_score"] = 999.0
            result["graph_distance"] = 0.0
            result["graph_depth"] = 0
            result["relationship_source"] = "bm25_search"
            
            # Perform NetworkX Graph Expansion for lexical results too
            if enable_expansion and self._graph is not None:
                from sentinel_prime.ai.agents.rag.query import _get_stix_node_by_ext_id, traverse_and_expand_technique
                stix_id = _get_stix_node_by_ext_id(doc_id)
                if stix_id:
                    expanded = traverse_and_expand_technique(stix_id, max_depth=traversal_depth)
                    
                    subtechs = expanded.get("subtechniques", [])[:expansion_limit]
                    groups = expanded.get("groups", [])[:expansion_limit]
                    software = expanded.get("software", [])[:expansion_limit]
                    mitigations = expanded.get("mitigations", [])[:expansion_limit]
                    campaigns = expanded.get("campaigns", [])[:expansion_limit]
                    
                    result["connected_subtechniques"] = subtechs
                    result["connected_groups"] = groups
                    result["connected_software"] = software
                    result["connected_mitigations"] = mitigations
                    result["connected_campaigns"] = campaigns
                    result["parent_technique"] = expanded.get("parent_technique")
                    
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
                    
            results.append(result)
            
        return results

    def search(self, query: str, limit: int) -> List[Dict[str, Any]]:
        """Unified Hybrid search endpoint combining dense, lexical, and RRF rankings (Step 1)."""
        self._load_resources()
        
        from sentinel_prime.ai.agents.rag.query import _graph_config
        enable_dense = _graph_config.get("enable_dense", True)
        enable_bm25 = _graph_config.get("enable_bm25", True)
        enable_hybrid = _graph_config.get("enable_hybrid", True)
        
        if enable_hybrid and enable_dense and enable_bm25:
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                dense_future = executor.submit(self.dense_search, query, limit)
                bm25_future = executor.submit(self.bm25_search, query, limit)
                
                dense_res = dense_future.result()
                bm25_res = bm25_future.result()
                
            from sentinel_prime.ai.agents.rag.query import reciprocal_rank_fusion
            return reciprocal_rank_fusion(
                dense_res,
                bm25_res,
                limit,
                k=_graph_config.get("rrf_k", 60),
                dense_weight=_graph_config.get("dense_weight", 1.0),
                lexical_weight=_graph_config.get("bm25_weight", 0.8),
                provider_weights=_graph_config.get("provider_weights", {})
            )
        elif enable_dense:
            return self.dense_search(query, limit)
        elif enable_bm25:
            return self.bm25_search(query, limit)
        else:
            return []

    def _save_indexes(self) -> None:
        """Saves current state of FAISS index, metadata, graph, and BM25 index to disk (Step 2)."""
        if self._index is not None:
            faiss.write_index(self._index, self.index_path)
        if self._metadata is not None:
            with open(self.chunks_path, "wb") as f:
                pickle.dump(self._metadata, f)
        if self._graph is not None:
            with open(self.graph_path, "wb") as f:
                pickle.dump(self._graph, f)
        if self._bm25 is not None:
            self._bm25.save(self.bm25_path)

    def insert_document(self, item: Dict[str, Any], sync_index: bool = True) -> None:
        """Inserts a single ATT&CK technique incrementally (Step 2)."""
        self._load_resources()
        
        doc_id = item.get("technique_id") or item.get("document_id")
        if any(t.get("technique_id") == doc_id for t in self._metadata):
            self.update_document(item, sync_index)
            return
            
        name = item.get("name") or item.get("title", "")
        description = item.get("description", "")
        chunk_text = f"Technique ID: {doc_id}\nName: {name}\nDescription: {description}"
        
        new_embedding = self._model.encode([chunk_text], show_progress_bar=False)
        
        t = {
            "technique_id": doc_id,
            "name": name,
            "description": description,
            "chunk_text": chunk_text,
            "stix_id": f"attack-pattern--{doc_id}",
            "_embedding": new_embedding[0].tolist()
        }
        self._metadata.append(t)
        
        self._index.add(new_embedding)
        
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        doc_metadata = {
            "source": "attack",
            "document_id": doc_id,
            "title": name,
            "description": description,
            "entity_type": "technique",
            "confidence": 1.0,
            "version": item.get("version", "1.0"),
            "created_at": now_iso,
            "updated_at": now_iso,
            "tags": ["mitre_attack"],
            "references": item.get("references", []),
            "citation": f"MITRE ATT&CK Technique {doc_id}",
            "parent_technique": None,
            "connected_software": [],
            "connected_groups": [],
            "connected_campaigns": [],
            "connected_mitigations": [],
            "connected_subtechniques": [],
            "technique_id": doc_id,
            "name": name,
            "description": description
        }
        text = f"Title: {name}\nDescription: {description}"
        self._bm25.add_document(doc_id, text, doc_metadata)
        
        # Incremental dynamic graph update
        if self._graph is not None:
            self._graph.add_node(
                t["stix_id"],
                stix_id=t["stix_id"],
                external_id=doc_id,
                name=name,
                type="technique",
                description=description,
                platforms=item.get("platforms", []),
                phase_names=item.get("phase_names", [])
            )
            
        if sync_index:
            self._save_indexes()

    def delete_document(self, doc_id: str, sync_index: bool = True) -> None:
        """Deletes a single ATT&CK technique incrementally (Step 2)."""
        self._load_resources()
        
        found_idx = -1
        for idx, t in enumerate(self._metadata):
            if t.get("technique_id") == doc_id:
                found_idx = idx
                break
                
        if found_idx == -1:
            return
            
        removed_t = self._metadata.pop(found_idx)
        
        import numpy as np
        if self._metadata:
            embeddings_list = [t["_embedding"] for t in self._metadata if "_embedding" in t]
            if embeddings_list:
                embeddings_arr = np.array(embeddings_list, dtype="float32")
                dimension = embeddings_arr.shape[1]
                self._index = faiss.IndexFlatL2(dimension)
                self._index.add(embeddings_arr)
        else:
            self._index = faiss.IndexFlatL2(384)
            
        self._bm25.remove_document(doc_id)
            
        if self._graph is not None and removed_t.get("stix_id") in self._graph:
            self._graph.remove_node(removed_t["stix_id"])
            
        if sync_index:
            self._save_indexes()

    def update_document(self, item: Dict[str, Any], sync_index: bool = True) -> None:
        """Updates an existing ATT&CK technique incrementally (Step 2)."""
        self._load_resources()
        
        doc_id = item.get("technique_id") or item.get("document_id")
        found_t = None
        for t in self._metadata:
            if t.get("technique_id") == doc_id:
                found_t = t
                break
                
        if found_t is None:
            self.insert_document(item, sync_index)
            return
            
        name = item.get("name") or item.get("title", found_t.get("name"))
        description = item.get("description", found_t.get("description"))
        chunk_text = f"Technique ID: {doc_id}\nName: {name}\nDescription: {description}"
        
        found_t["name"] = name
        found_t["description"] = description
        found_t["chunk_text"] = chunk_text
        
        new_embedding = self._model.encode([chunk_text], show_progress_bar=False)
        found_t["_embedding"] = new_embedding[0].tolist()
        
        import numpy as np
        embeddings_list = [t["_embedding"] for t in self._metadata if "_embedding" in t]
        embeddings_arr = np.array(embeddings_list, dtype="float32")
        dimension = embeddings_arr.shape[1]
        self._index = faiss.IndexFlatL2(dimension)
        self._index.add(embeddings_arr)
        
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        doc_metadata = {
            "source": "attack",
            "document_id": doc_id,
            "title": name,
            "description": description,
            "entity_type": "technique",
            "confidence": 1.0,
            "version": item.get("version", "1.0"),
            "created_at": now_iso,
            "updated_at": now_iso,
            "tags": ["mitre_attack"],
            "references": item.get("references", []),
            "citation": f"MITRE ATT&CK Technique {doc_id}",
            "parent_technique": None,
            "connected_software": [],
            "connected_groups": [],
            "connected_campaigns": [],
            "connected_mitigations": [],
            "connected_subtechniques": [],
            "technique_id": doc_id,
            "name": name,
            "description": description
        }
        text = f"Title: {name}\nDescription: {description}"
        self._bm25.add_document(doc_id, text, doc_metadata)
        
        if self._graph is not None and found_t.get("stix_id") in self._graph:
            node = self._graph.nodes[found_t["stix_id"]]
            node["name"] = name
            node["description"] = description
            if "platforms" in item:
                node["platforms"] = item["platforms"]
            if "phase_names" in item:
                node["phase_names"] = item["phase_names"]
                
        if sync_index:
            self._save_indexes()

    def upsert_document(self, item: Dict[str, Any], sync_index: bool = True) -> None:
        """Upserts a single document incrementally (Step 2)."""
        self.update_document(item, sync_index)
