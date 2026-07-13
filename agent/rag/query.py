import os
import pickle
import faiss
from sentence_transformers import SentenceTransformer

# Constants
INDEX_DIR = os.path.join(os.path.dirname(__file__), "index")
INDEX_PATH = os.path.join(INDEX_DIR, "attack.index")
CHUNKS_PATH = os.path.join(INDEX_DIR, "chunks.pkl")

# Global variables for lazy loading
_index = None
_metadata = None
_model = None

def load_resources():
    """Lazily loads the FAISS index, metadata, and embedding model."""
    global _index, _metadata, _model
    
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

def search(query: str, top_k: int = 5) -> list[dict]:
    """
    Searches the FAISS index for the most relevant MITRE ATT&CK techniques.
    
    Args:
        query (str): The search query (e.g., an alert description).
        top_k (int): Number of results to return.
        
    Returns:
        list[dict]: A list of metadata dicts for the matched techniques.
    """
    load_resources()
    
    # Embed the query
    query_vector = _model.encode([query])
    
    # Search
    distances, indices = _index.search(query_vector, top_k)
    
    results = []
    for i, idx in enumerate(indices[0]):
        if idx != -1 and idx < len(_metadata):
            result = _metadata[idx].copy()
            result['distance'] = float(distances[0][i])
            results.append(result)
            
    return results

if __name__ == "__main__":
    # Test the query module
    try:
        print("Testing FAISS query...")
        results = search("12 failed SSH login attempts in 40 seconds", top_k=3)
        for r in results:
            print(f"[{r['technique_id']}] {r['name']} (Distance: {r['distance']:.4f})")
    except Exception as e:
        print(f"Error during test: {e}")
