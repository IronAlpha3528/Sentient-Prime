import os
import pickle
import threading
from typing import Dict, Any, Optional

import numpy as np

class CachedSentenceTransformer:
    def __init__(self, model):
        self._model = model
        self._cache = {}
        self._lock = threading.Lock()

    def encode(self, sentences, *args, **kwargs):
        if isinstance(sentences, str):
            with self._lock:
                if sentences not in self._cache:
                    self._cache[sentences] = self._model.encode(sentences, *args, **kwargs)
                return self._cache[sentences]
        elif isinstance(sentences, list):
            results = []
            to_encode = []
            indices = []
            with self._lock:
                for idx, s in enumerate(sentences):
                    if isinstance(s, str) and s in self._cache:
                        results.append(self._cache[s])
                    else:
                        results.append(None)
                        to_encode.append(s)
                        indices.append(idx)
            if to_encode:
                encoded = self._model.encode(to_encode, *args, **kwargs)
                with self._lock:
                    for idx, val in zip(indices, encoded):
                        results[idx] = val
                        if isinstance(sentences[idx], str):
                            self._cache[sentences[idx]] = val
            return np.array(results)
        else:
            return self._model.encode(sentences, *args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._model, name)

class CachedCrossEncoder:
    def __init__(self, model):
        self._model = model
        self._cache = {}
        self._lock = threading.Lock()

    def predict(self, pairs, *args, **kwargs):
        if not pairs:
            return []
        results = []
        to_predict = []
        indices = []
        with self._lock:
            for idx, pair in enumerate(pairs):
                cache_key = (pair[0], pair[1])
                if cache_key in self._cache:
                    results.append(self._cache[cache_key])
                else:
                    results.append(None)
                    to_predict.append(pair)
                    indices.append(idx)
        if to_predict:
            predicted = self._model.predict(to_predict, *args, **kwargs)
            if isinstance(predicted, (float, int, np.float32, np.float64)):
                predicted = [predicted]
            with self._lock:
                for idx, val in zip(indices, predicted):
                    results[idx] = val
                    cache_key = (pairs[idx][0], pairs[idx][1])
                    self._cache[cache_key] = val
        return np.array(results)

    def __getattr__(self, name):
        return getattr(self._model, name)

class ResourceManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super(ResourceManager, cls).__new__(cls, *args, **kwargs)
                    cls._instance._init_resources()
        return cls._instance

    def _init_resources(self):
        self._models = {}
        self._indexes = {}
        self._graphs = {}
        self._metadata = {}
        self._bm25_indexes = {}
        self._lock = threading.Lock()

    def get_sentence_transformer(self, model_name: str = 'all-MiniLM-L6-v2'):
        if model_name not in self._models:
            with self._lock:
                if model_name not in self._models:
                    from sentence_transformers import SentenceTransformer
                    print(f"Loading SentenceTransformer model '{model_name}' (Shared Singleton)...")
                    raw_model = SentenceTransformer(model_name)
                    self._models[model_name] = CachedSentenceTransformer(raw_model)
        return self._models[model_name]

    def get_cross_encoder(self, model_name: str):
        if model_name not in self._models:
            with self._lock:
                if model_name not in self._models:
                    from sentence_transformers import CrossEncoder
                    print(f"Loading CrossEncoder model '{model_name}' (Shared Singleton)...")
                    raw_model = CrossEncoder(model_name)
                    self._models[model_name] = CachedCrossEncoder(raw_model)
        return self._models[model_name]

    def get_faiss_index(self, index_path: str):
        abs_path = os.path.abspath(index_path)
        if abs_path not in self._indexes:
            with self._lock:
                if abs_path not in self._indexes:
                    import faiss
                    if not os.path.exists(abs_path):
                        raise FileNotFoundError(f"FAISS index not found at {abs_path}")
                    print(f"Loading FAISS index from {abs_path} (Shared Singleton)...")
                    self._indexes[abs_path] = faiss.read_index(abs_path)
        return self._indexes[abs_path]

    def get_metadata(self, chunks_path: str):
        abs_path = os.path.abspath(chunks_path)
        if abs_path not in self._metadata:
            with self._lock:
                if abs_path not in self._metadata:
                    if not os.path.exists(abs_path):
                        raise FileNotFoundError(f"Metadata not found at {abs_path}")
                    print(f"Loading metadata from {abs_path} (Shared Singleton)...")
                    with open(abs_path, "rb") as f:
                        self._metadata[abs_path] = pickle.load(f)
        return self._metadata[abs_path]

    def get_graph(self, graph_path: str):
        abs_path = os.path.abspath(graph_path)
        if abs_path not in self._graphs:
            with self._lock:
                if abs_path not in self._graphs:
                    if not os.path.exists(abs_path):
                        self._graphs[abs_path] = None
                    else:
                        print(f"Loading Graph from {abs_path} (Shared Singleton)...")
                        with open(abs_path, "rb") as f:
                            self._graphs[abs_path] = pickle.load(f)
        return self._graphs[abs_path]

    def get_bm25_index(self, bm25_path: str):
        abs_path = os.path.abspath(bm25_path)
        if abs_path not in self._bm25_indexes:
            with self._lock:
                if abs_path not in self._bm25_indexes:
                    from sentinel_prime.ai.agents.rag.providers.bm25 import BM25Index
                    if os.path.exists(abs_path):
                        print(f"Loading BM25 Index from {abs_path} (Shared Singleton)...")
                        self._bm25_indexes[abs_path] = BM25Index.load(abs_path)
                    else:
                        self._bm25_indexes[abs_path] = BM25Index()
        return self._bm25_indexes[abs_path]
