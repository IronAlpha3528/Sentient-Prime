import os
import json
import pickle
import datetime
import faiss
from typing import List, Dict, Any, Optional
from sentence_transformers import SentenceTransformer
from sentinel_prime.ai.agents.rag.providers.base import BaseProvider
from sentinel_prime.ai.agents.rag.providers.bm25 import BM25Index

class GenericProvider(BaseProvider):
    """
    A parameterized retrieval provider implementing the common BaseProvider interface.
    Handles Dense, Lexical, and Hybrid search for specific CTI databases (Step 1).
    """
    def __init__(self, name: str, index_dir: str):
        self.name = name
        self.index_dir = index_dir
        self.index_path = os.path.join(index_dir, f"{name}.index")
        self.chunks_path = os.path.join(index_dir, f"{name}_chunks.pkl")
        self.bm25_path = os.path.join(index_dir, f"{name}.bm25")
        
        self._index = None
        self._metadata = None
        self._model = None
        self._bm25 = None

    def _load_resources(self):
        """Lazily loads vector indexes, model files, and BM25 index."""
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

    def ingest(self, raw_data_path: str) -> None:
        """Parses raw JSON, generates dense embeddings, builds BM25 lexical index, and persists both (Step 2)."""
        if not os.path.exists(raw_data_path):
            raise FileNotFoundError(f"Raw CTI source data not found at {raw_data_path}")

        print(f"Ingesting raw source data for provider '{self.name}' from {raw_data_path}...")
        with open(raw_data_path, "r", encoding="utf-8") as f:
            raw_items = json.load(f)

        if not os.path.exists(self.index_dir):
            os.makedirs(self.index_dir)

        # Standardize metadata objects list
        standardized_chunks = []
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Build BM25 Lexical Index
        bm25_idx = BM25Index()

        for item in raw_items:
            standardized = {
                "source": self.name,
                "document_id": item.get("id"),
                "title": item.get("name", ""),
                "description": item.get("description", ""),
                "entity_type": item.get("entity_type", "threat_intel"),
                "confidence": float(item.get("confidence", 1.0)),
                "version": item.get("version", "1.0"),
                "created_at": item.get("created_at", now_iso),
                "updated_at": item.get("updated_at", now_iso),
                "tags": item.get("tags", []),
                "references": item.get("references", []),
                "citation": f"Source: {self.name} ({item.get('id')})"
            }
            standardized_chunks.append(standardized)
            
            # Index document lexically
            doc_text = f"Title: {standardized['title']}\nDescription: {standardized['description']}\nTags: {', '.join(standardized['tags'])}"
            bm25_idx.add_document(standardized["document_id"], doc_text, standardized)

        if not standardized_chunks:
            print(f"Warning: No items ingested for provider '{self.name}'")
            return

        # Initialize SentenceTransformer and generate dense embeddings
        model = SentenceTransformer('all-MiniLM-L6-v2')
        texts = [f"Title: {c['title']}\nDescription: {c['description']}\nTags: {', '.join(c['tags'])}" for c in standardized_chunks]
        
        embeddings = model.encode(texts, show_progress_bar=False)
        dimension = embeddings.shape[1]

        # Attach embeddings to metadata for incremental caching
        for i, c in enumerate(standardized_chunks):
            c["_embedding"] = embeddings[i].tolist()

        # Save FAISS index
        index = faiss.IndexFlatL2(dimension)
        index.add(embeddings)
        faiss.write_index(index, self.index_path)

        # Save metadata store
        with open(self.chunks_path, "wb") as f:
            pickle.dump(standardized_chunks, f)
            
        # Save BM25 index
        bm25_idx.save(self.bm25_path)

        print(f"Provider '{self.name}' ingestion complete. Ingested {len(standardized_chunks)} items.")

    def _save_indexes(self) -> None:
        """Saves current state of FAISS index, metadata, and BM25 index to disk (Step 2)."""
        if self._index is not None:
            faiss.write_index(self._index, self.index_path)
        if self._metadata is not None:
            with open(self.chunks_path, "wb") as f:
                pickle.dump(self._metadata, f)
        if self._bm25 is not None:
            self._bm25.save(self.bm25_path)

    def insert_document(self, item: Dict[str, Any], sync_index: bool = True) -> None:
        """Inserts a single document incrementally (Step 2)."""
        self._load_resources()
        
        doc_id = item.get("id") or item.get("document_id")
        if any(d.get("document_id") == doc_id for d in self._metadata):
            self.update_document(item, sync_index)
            return
            
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        standardized = {
            "source": self.name,
            "document_id": doc_id,
            "title": item.get("name") or item.get("title", ""),
            "description": item.get("description", ""),
            "entity_type": item.get("entity_type", "threat_intel"),
            "confidence": float(item.get("confidence", 1.0)),
            "version": item.get("version", "1.0"),
            "created_at": item.get("created_at", now_iso),
            "updated_at": item.get("updated_at", now_iso),
            "tags": item.get("tags", []),
            "references": item.get("references", []),
            "citation": item.get("citation") or f"Source: {self.name} ({doc_id})"
        }
        
        doc_text = f"Title: {standardized['title']}\nDescription: {standardized['description']}\nTags: {', '.join(standardized['tags'])}"
        new_embedding = self._model.encode([doc_text], show_progress_bar=False)
        
        standardized["_embedding"] = new_embedding[0].tolist()
        self._metadata.append(standardized)
        
        self._index.add(new_embedding)
        self._bm25.add_document(standardized["document_id"], doc_text, standardized)
        
        if sync_index:
            self._save_indexes()

    def delete_document(self, doc_id: str, sync_index: bool = True) -> None:
        """Deletes a single document incrementally (Step 2)."""
        self._load_resources()
        
        found_idx = -1
        for idx, d in enumerate(self._metadata):
            if d.get("document_id") == doc_id:
                found_idx = idx
                break
                
        if found_idx == -1:
            return
            
        self._metadata.pop(found_idx)
        
        import numpy as np
        if self._metadata:
            embeddings_list = [d["_embedding"] for d in self._metadata]
            embeddings_arr = np.array(embeddings_list, dtype="float32")
            dimension = embeddings_arr.shape[1]
            self._index = faiss.IndexFlatL2(dimension)
            self._index.add(embeddings_arr)
        else:
            self._index = faiss.IndexFlatL2(384)
            
        self._bm25.remove_document(doc_id)
            
        if sync_index:
            self._save_indexes()

    def update_document(self, item: Dict[str, Any], sync_index: bool = True) -> None:
        """Updates an existing document incrementally (Step 2)."""
        self._load_resources()
        
        doc_id = item.get("id") or item.get("document_id")
        found_doc = None
        for d in self._metadata:
            if d.get("document_id") == doc_id:
                found_doc = d
                break
                
        if found_doc is None:
            self.insert_document(item, sync_index)
            return
            
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        found_doc["title"] = item.get("name") or item.get("title", found_doc.get("title"))
        found_doc["description"] = item.get("description", found_doc.get("description"))
        found_doc["entity_type"] = item.get("entity_type", found_doc.get("entity_type"))
        found_doc["confidence"] = float(item.get("confidence", found_doc.get("confidence")))
        found_doc["version"] = item.get("version", found_doc.get("version"))
        found_doc["updated_at"] = now_iso
        found_doc["tags"] = item.get("tags", found_doc.get("tags"))
        found_doc["references"] = item.get("references", found_doc.get("references"))
        
        doc_text = f"Title: {found_doc['title']}\nDescription: {found_doc['description']}\nTags: {', '.join(found_doc['tags'])}"
        new_embedding = self._model.encode([doc_text], show_progress_bar=False)
        found_doc["_embedding"] = new_embedding[0].tolist()
        
        import numpy as np
        embeddings_list = [d["_embedding"] for d in self._metadata]
        embeddings_arr = np.array(embeddings_list, dtype="float32")
        dimension = embeddings_arr.shape[1]
        self._index = faiss.IndexFlatL2(dimension)
        self._index.add(embeddings_arr)
        
        self._bm25.add_document(doc_id, doc_text, found_doc)
        
        if sync_index:
            self._save_indexes()

    def upsert_document(self, item: Dict[str, Any], sync_index: bool = True) -> None:
        """Upserts a single document incrementally (Step 2)."""
        self.update_document(item, sync_index)

    def dense_search(self, query: str, limit: int, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Queries the provider's FAISS index for dense semantic matching (Step 4 & 5)."""
        try:
            self._load_resources()
        except Exception as e:
            print(f"Bypassing provider '{self.name}' dense query: resources load error: {e}")
            return []

        # Embed query
        query_vector = self._model.encode([query])
        
        # Search FAISS index
        distances, indices = self._index.search(query_vector, limit)
        
        results = []
        for i, idx in enumerate(indices[0]):
            if idx != -1 and idx < len(self._metadata):
                result = self._metadata[idx].copy()
                
                # Check filter matching
                if filters and not self._bm25._matches_filters(result, filters):
                    continue
                    
                dist = float(distances[0][i])
                result["similarity_score"] = dist
                result["graph_distance"] = 0.0
                result["graph_depth"] = 0
                result["relationship_source"] = "vector_search"
                
                # Append backward-compatible keys
                result["technique_id"] = result["document_id"]
                result["name"] = result["title"]
                result["distance"] = dist
                result["score"] = dist
                
                results.append(result)
                
        return results

    def bm25_search(self, query: str, limit: int, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Queries the provider's BM25 index for keyword/lexical matching (Step 5)."""
        try:
            self._load_resources()
        except Exception as e:
            print(f"Bypassing provider '{self.name}' lexical query: resources load error: {e}")
            return []

        bm25_res = self._bm25.search(query, limit, filters)
        results = []
        for r in bm25_res:
            result = r.copy()
            # Default fallback score for similarity
            result["similarity_score"] = 999.0
            result["graph_distance"] = 0.0
            result["graph_depth"] = 0
            result["relationship_source"] = "bm25_search"
            
            # Backward-compatible keys
            result["technique_id"] = result["document_id"]
            result["name"] = result["title"]
            result["distance"] = 999.0
            result["score"] = 999.0
            
            results.append(result)
            
        return results

    def search(self, query: str, limit: int, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Queries using configured dense, lexical, or fused hybrid search (Step 1)."""
        try:
            self._load_resources()
        except Exception as e:
            print(f"Bypassing provider '{self.name}' search: resources load error: {e}")
            return []

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
