from abc import ABC, abstractmethod
from typing import List, Dict, Any

class BaseProvider(ABC):
    """The standard abstract interface for all Multi-Source RAG knowledge providers."""

    @abstractmethod
    def ingest(self, raw_data_path: str) -> None:
        """Loads raw JSON source data, generates embeddings, and compiles FAISS/metadata index."""
        pass

    @abstractmethod
    def search(self, query: str, limit: int) -> List[Dict[str, Any]]:
        """Queries the source-specific index and returns metadata standardized threat intel dicts."""
        pass
