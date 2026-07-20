import os
import json
import pickle
import datetime
import faiss
from typing import List, Dict, Any, Optional
from sentence_transformers import SentenceTransformer
from sentinel_prime.ai.agents.rag.providers.base import BaseProvider
from sentinel_prime.ai.agents.rag.providers.bm25 import BM25Index

class HistoricalIncidentProvider(BaseProvider):
    """
    Structured Historical Incident Memory & Retrieval Provider.
    Implements persistent storage in a JSON database, semantic retrieval with FAISS,
    lexical retrieval with BM25, and hybrid fusion using RRF (Step 1).
    """
    def __init__(self, index_dir: str, json_db_path: Optional[str] = None):
        self.name = "historical_incident"
        self.index_dir = index_dir
        
        if json_db_path:
            self.json_db_path = json_db_path
        else:
            self.json_db_path = os.path.join(index_dir, "historical_incidents_db.json")
            
        self.index_path = os.path.join(index_dir, "historical_incident.index")
        self.bm25_path = os.path.join(index_dir, "historical_incident.bm25")
        
        self._index = None
        self._incidents = []
        self._model = None
        self._bm25 = None
        
        self._load_db()

    def _load_db(self):
        """Loads incidents from the persistent JSON file and compiles indexes if missing."""
        if not os.path.exists(self.index_dir):
            os.makedirs(self.index_dir)
            
        if os.path.exists(self.json_db_path):
            try:
                with open(self.json_db_path, "r", encoding="utf-8") as f:
                    self._incidents = json.load(f)
            except Exception as e:
                print(f"Error loading historical incidents database: {e}")
                self._incidents = []
        else:
            self._incidents = []
            
        # Re-initialize index if needed
        self._sync_index()

    def _save_db(self):
        """Saves incidents list back to the structured JSON file."""
        try:
            with open(self.json_db_path, "w", encoding="utf-8") as f:
                json.dump(self._incidents, f, indent=2, default=str)
        except Exception as e:
            print(f"Error saving historical incidents database: {e}")

    def _load_model(self):
        """Lazily loads SentenceTransformer model."""
        if self._model is None:
            from sentinel_prime.ai.agents.rag.resource_manager import ResourceManager
            self._model = ResourceManager().get_sentence_transformer('all-MiniLM-L6-v2')

    def _get_embedding_text(self, incident: Dict[str, Any]) -> str:
        """Helper to build text description for embedding generation."""
        summary = incident.get("attack_summary", "")
        timeline = " | ".join(incident.get("timeline", []))
        techniques = ", ".join(incident.get("attack_techniques", []))
        groups = ", ".join(incident.get("threat_groups", []))
        malware = ", ".join(incident.get("malware", []))
        lessons = incident.get("lessons_learned", "")
        
        return f"Summary: {summary}\nTimeline: {timeline}\nTechniques: {techniques}\nGroups: {groups}\nMalware: {malware}\nLessons: {lessons}"

    def _sync_index(self):
        """Compiles or loads the FAISS & BM25 indexes in sync with loaded memory JSON records."""
        # 1. Sync BM25 lexical index (Step 2)
        bm25_idx = BM25Index()
        for inc in self._incidents:
            text = self._get_embedding_text(inc)
            doc_metadata = inc.copy()
            doc_metadata["source"] = self.name
            doc_metadata["document_id"] = inc.get("incident_id")
            doc_metadata["title"] = inc.get("resolved_threat", "")
            doc_metadata["description"] = inc.get("attack_summary", "")
            bm25_idx.add_document(inc.get("incident_id"), text, doc_metadata)
            
        bm25_idx.save(self.bm25_path)
        self._bm25 = bm25_idx

        # 2. Sync Dense FAISS index
        if not self._incidents:
            self._index = None
            if os.path.exists(self.index_path):
                try:
                    os.remove(self.index_path)
                except:
                    pass
            return
            
        import numpy as np
        self._load_model()
        
        # Check if any incident lacks a cached embedding, and generate if missing
        db_changed = False
        for inc in self._incidents:
            if "_embedding" not in inc:
                text = self._get_embedding_text(inc)
                embedding = self._model.encode([text], show_progress_bar=False)
                inc["_embedding"] = embedding[0].tolist()
                db_changed = True
                
        if db_changed:
            self._save_db()
            
        # Reconstruct FAISS using cached embeddings (zero re-embedding cost)
        embeddings_list = [inc["_embedding"] for inc in self._incidents]
        embeddings_arr = np.array(embeddings_list, dtype="float32")
        dimension = embeddings_arr.shape[1]
        
        self._index = faiss.IndexFlatL2(dimension)
        self._index.add(embeddings_arr)
        
        dir_name = os.path.dirname(self.index_path)
        if dir_name and not os.path.exists(dir_name):
            os.makedirs(dir_name, exist_ok=True)
        faiss.write_index(self._index, self.index_path)

    def ingest(self, raw_data_path: str) -> None:
        """Bridges BaseProvider raw ingestion command. Loads the raw JSON into memory."""
        if not os.path.exists(raw_data_path):
            raise FileNotFoundError(f"Raw historical database not found at {raw_data_path}")
            
        with open(raw_data_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        if isinstance(data, list):
            self._incidents = data
            self._save_db()
            self._sync_index()
            print(f"Ingested {len(self._incidents)} historical incidents.")

    def insert(self, incident: Dict[str, Any]) -> None:
        """Incremental Ingestion: Adds an incident, encodes it, and updates both FAISS & BM25 indices (Step 2)."""
        self._load_model()
        
        doc_id = incident.get("incident_id")
        if not doc_id:
            doc_id = f"INC-{int(datetime.datetime.now().timestamp())}"
            incident["incident_id"] = doc_id
        if "timestamp" not in incident:
            incident["timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if "version" not in incident:
            incident["version"] = "1.0"
            
        text = self._get_embedding_text(incident)
        vector = self._model.encode([text])
        incident["_embedding"] = vector[0].tolist()
        
        self._incidents.append(incident)
        self._save_db()
        
        if self._index is None:
            dimension = vector.shape[1]
            self._index = faiss.IndexFlatL2(dimension)
            
        self._index.add(vector)
        faiss.write_index(self._index, self.index_path)
        
        doc_metadata = incident.copy()
        doc_metadata["source"] = self.name
        doc_metadata["document_id"] = doc_id
        doc_metadata["title"] = incident.get("resolved_threat", "")
        doc_metadata["description"] = incident.get("attack_summary", "")
        
        if self._bm25 is None:
            self._bm25 = BM25Index()
            
        self._bm25.add_document(doc_id, text, doc_metadata)
        self._bm25.save(self.bm25_path)

    def update(self, incident_id: str, updated_incident: Dict[str, Any]) -> bool:
        """Updates incident metadata in persistent JSON database and rebuilds index."""
        found_idx = -1
        for idx, inc in enumerate(self._incidents):
            if inc.get("incident_id") == incident_id:
                found_idx = idx
                break
                
        if found_idx == -1:
            return False
            
        self._load_model()
        updated_incident["incident_id"] = incident_id
        if "timestamp" not in updated_incident:
            updated_incident["timestamp"] = self._incidents[found_idx].get("timestamp")
            
        text = self._get_embedding_text(updated_incident)
        vector = self._model.encode([text])
        updated_incident["_embedding"] = vector[0].tolist()
        
        self._incidents[found_idx] = updated_incident
        self._save_db()
        
        import numpy as np
        embeddings_list = [inc["_embedding"] for inc in self._incidents]
        embeddings_arr = np.array(embeddings_list, dtype="float32")
        dimension = embeddings_arr.shape[1]
        
        self._index = faiss.IndexFlatL2(dimension)
        self._index.add(embeddings_arr)
        faiss.write_index(self._index, self.index_path)
        
        doc_metadata = updated_incident.copy()
        doc_metadata["source"] = self.name
        doc_metadata["document_id"] = incident_id
        doc_metadata["title"] = updated_incident.get("resolved_threat", "")
        doc_metadata["description"] = updated_incident.get("attack_summary", "")
        
        self._bm25.add_document(incident_id, text, doc_metadata)
        self._bm25.save(self.bm25_path)
        
        return True

    def delete(self, incident_id: str) -> bool:
        """Deletes incident from persistent JSON database and rebuilds index."""
        found_idx = -1
        for idx, inc in enumerate(self._incidents):
            if inc.get("incident_id") == incident_id:
                found_idx = idx
                break
                
        if found_idx == -1:
            return False
            
        self._incidents.pop(found_idx)
        self._save_db()
        
        import numpy as np
        if self._incidents:
            embeddings_list = [inc["_embedding"] for inc in self._incidents]
            embeddings_arr = np.array(embeddings_list, dtype="float32")
            dimension = embeddings_arr.shape[1]
            
            self._index = faiss.IndexFlatL2(dimension)
            self._index.add(embeddings_arr)
            faiss.write_index(self._index, self.index_path)
        else:
            self._index = None
            if os.path.exists(self.index_path):
                try:
                    os.remove(self.index_path)
                except:
                    pass
                    
        self._bm25.remove_document(incident_id)
        self._bm25.save(self.bm25_path)
            
        return True

    def insert_document(self, item: Dict[str, Any], sync_index: bool = True) -> None:
        """Standardized interface to insert incrementally."""
        # Translate to incident format
        incident = item.copy()
        if "incident_id" not in incident:
            incident["incident_id"] = item.get("document_id") or item.get("id")
        if "resolved_threat" not in incident:
            incident["resolved_threat"] = item.get("title")
        if "attack_summary" not in incident:
            incident["attack_summary"] = item.get("description")
        self.insert(incident)

    def delete_document(self, doc_id: str, sync_index: bool = True) -> None:
        """Standardized interface to delete incrementally."""
        self.delete(doc_id)

    def update_document(self, item: Dict[str, Any], sync_index: bool = True) -> None:
        """Standardized interface to update incrementally."""
        doc_id = item.get("document_id") or item.get("id") or item.get("incident_id")
        incident = item.copy()
        if "resolved_threat" not in incident:
            incident["resolved_threat"] = item.get("title")
        if "attack_summary" not in incident:
            incident["attack_summary"] = item.get("description")
        self.update(doc_id, incident)

    def upsert_document(self, item: Dict[str, Any], sync_index: bool = True) -> None:
        """Standardized interface to upsert incrementally."""
        doc_id = item.get("document_id") or item.get("id") or item.get("incident_id")
        if any(inc.get("incident_id") == doc_id for inc in self._incidents):
            self.update_document(item, sync_index)
        else:
            self.insert_document(item, sync_index)

    def _matches_historical_filters(self, incident: Dict[str, Any], filters: Optional[Dict[str, Any]]) -> bool:
        """Applies specific metadata filters (tags, risk scores, technique links) to historical records (Step 5)."""
        if not filters:
            return True
        for k, v in filters.items():
            if k == "tags":
                if not any(tag.lower() in [t.lower() for t in incident.get("tags", [])] for tag in (v if isinstance(v, list) else [v])):
                    return False
            elif k == "risk_level":
                if incident.get("unified_threat_score", 0.0) < float(v):
                    return False
            elif k == "attack_techniques":
                if not any(t.lower() == v.lower() for t in incident.get("attack_techniques", [])):
                    return False
        return True

    def _map_to_standard_schema(self, incident: Dict[str, Any], dist: float) -> Dict[str, Any]:
        """Maps an incident's custom parameters to the target standardized RAG schema (Step 8)."""
        result = {
            "source": "historical_incident",
            "document_id": incident.get("incident_id"),
            "incident_id": incident.get("incident_id"),
            "title": incident.get("resolved_threat", ""),
            "resolved_threat": incident.get("resolved_threat", ""),
            "description": incident.get("attack_summary", ""),
            "summary": incident.get("attack_summary", ""),
            "attack_summary": incident.get("attack_summary", ""),
            "similarity_score": dist,
            "graph_distance": 0.0,
            "graph_depth": 0,
            "relationship_source": "vector_search" if dist < 990 else "bm25_search",
            "timestamp": incident.get("timestamp"),
            "timeline": incident.get("timeline", []),
            "timeline_summary": incident.get("timeline_summary", " | ".join(incident.get("timeline", []))),
            "evidence": incident.get("evidence", []),
            "evidence_summary": incident.get("evidence_summary", ""),
            "affected_assets": incident.get("affected_assets", []),
            "attack_techniques": incident.get("attack_techniques", []),
            "mitre_techniques": incident.get("attack_techniques", []),
            "threat_groups": incident.get("threat_groups", []),
            "threat_actor": ", ".join(incident.get("threat_groups", [])) or "Unknown",
            "malware": incident.get("malware", []),
            "detection_scores": incident.get("detection_scores", {}),
            "graph_snapshot": incident.get("graph_snapshot", {}),
            "unified_threat_score": float(incident.get("unified_threat_score", 0.0)),
            "confidence": float(incident.get("confidence", 1.0)),
            "soar_actions": incident.get("soar_actions", []),
            "response_actions": incident.get("soar_actions", []),
            "containment_status": incident.get("containment_status", "Resolved"),
            "resolution": incident.get("resolution", ""),
            "outcome": incident.get("resolution", ""),
            "recovery_time": incident.get("recovery_time", ""),
            "lessons_learned": incident.get("lessons_learned", ""),
            "tags": incident.get("tags", []),
            "version": incident.get("version", "1.0"),
            "references": incident.get("references", []),
            "citation": f"Historical Incident Recall: {incident.get('incident_id')}"
        }
        
        # Append backward compatible aliases
        result["technique_id"] = incident.get("incident_id")
        result["name"] = incident.get("resolved_threat")
        result["distance"] = dist
        result["score"] = dist
        
        return result

    def dense_search(self, query: str, limit: int, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Queries historical incidents using FAISS semantic search and optional metadata filters (Step 4 & 5)."""
        if not self._incidents or self._index is None:
            return []
            
        self._load_model()
        query_vector = self._model.encode([query])
        
        distances, indices = self._index.search(query_vector, len(self._incidents))
        
        results = []
        for i, idx in enumerate(indices[0]):
            if idx != -1 and idx < len(self._incidents):
                incident = self._incidents[idx]
                
                # Check filters
                if not self._matches_historical_filters(incident, filters):
                    continue
                    
                dist = float(distances[0][i])
                results.append(self._map_to_standard_schema(incident, dist))
                
                if len(results) >= limit:
                    break
                    
        return results

    def bm25_search(self, query: str, limit: int, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Queries historical incidents using BM25 lexical search and optional metadata filters (Step 5)."""
        if not self._incidents or self._bm25 is None:
            return []
            
        bm25_res = self._bm25.search(query, len(self._incidents), filters)
        results = []
        for r in bm25_res:
            incident = next((inc for inc in self._incidents if inc.get("incident_id") == r.get("document_id")), None)
            if incident:
                # Apply historical specific filters
                if not self._matches_historical_filters(incident, filters):
                    continue
                    
                mapped = self._map_to_standard_schema(incident, 999.0)
                mapped["bm25_score"] = r.get("bm25_score", 0.0)
                results.append(mapped)
                
                if len(results) >= limit:
                    break
                    
        return results

    def search(self, query: str, limit: int = 3, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Queries using configured dense, lexical, or fused hybrid search (Step 1)."""
        from sentinel_prime.ai.agents.rag.query import _graph_config
        enable_dense = _graph_config.get("enable_dense", True)
        enable_bm25 = _graph_config.get("enable_bm25", True)
        enable_hybrid = _graph_config.get("enable_hybrid", True)

        if enable_hybrid and enable_dense and enable_bm25:
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                dense_future = executor.submit(self.dense_search, query, limit, filters)
                bm25_future = executor.submit(self.bm25_search, query, limit, filters)
                
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
            return self.dense_search(query, limit, filters)
        elif enable_bm25:
            return self.bm25_search(query, limit, filters)
        else:
            return []
