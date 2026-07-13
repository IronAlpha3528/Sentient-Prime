import os
import json
import urllib.request
import pickle
import faiss
from sentence_transformers import SentenceTransformer

# Constants
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data")
ATTACK_JSON_PATH = os.path.join(DATA_DIR, "enterprise-attack.json")
INDEX_DIR = os.path.join(os.path.dirname(__file__), "index")
INDEX_PATH = os.path.join(INDEX_DIR, "attack.index")
CHUNKS_PATH = os.path.join(INDEX_DIR, "chunks.pkl")

# URL for STIX 2.1 MITRE ATT&CK Enterprise Data
ATTACK_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"

def download_attack_data():
    """Downloads enterprise-attack.json if it doesn't exist."""
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
        
    if not os.path.exists(ATTACK_JSON_PATH):
        print(f"Downloading MITRE ATT&CK data from {ATTACK_URL}...")
        try:
            urllib.request.urlretrieve(ATTACK_URL, ATTACK_JSON_PATH)
            print("Download complete.")
        except Exception as e:
            print(f"Error downloading data: {e}")
            raise
    else:
        print("MITRE ATT&CK data already exists.")

def parse_attack_data():
    """Parses the STIX JSON and extracts techniques."""
    print("Parsing ATT&CK data...")
    with open(ATTACK_JSON_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    techniques = []
    
    for obj in data.get("objects", []):
        if obj.get("type") == "attack-pattern":
            # Extract External ID (T-number)
            external_refs = obj.get("external_references", [])
            technique_id = None
            for ref in external_refs:
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id")
                    break
            
            if technique_id:
                name = obj.get("name", "")
                description = obj.get("description", "")
                # Create a rich text chunk
                chunk_text = f"Technique ID: {technique_id}\nName: {name}\nDescription: {description}"
                
                techniques.append({
                    "technique_id": technique_id,
                    "name": name,
                    "description": description,
                    "chunk_text": chunk_text
                })
    
    print(f"Extracted {len(techniques)} techniques.")
    return techniques

def build_index():
    """Embeds the chunks and builds the FAISS index."""
    download_attack_data()
    techniques = parse_attack_data()
    
    if not os.path.exists(INDEX_DIR):
        os.makedirs(INDEX_DIR)
        
    print("Loading SentenceTransformer model 'all-MiniLM-L6-v2'...")
    model = SentenceTransformer('all-MiniLM-L6-v2')
    
    texts = [t["chunk_text"] for t in techniques]
    
    print("Encoding texts...")
    embeddings = model.encode(texts, show_progress_bar=True)
    
    dimension = embeddings.shape[1]
    print(f"Building FAISS index with dimension {dimension}...")
    index = faiss.IndexFlatL2(dimension)
    index.add(embeddings)
    
    print(f"Saving index to {INDEX_PATH}")
    faiss.write_index(index, INDEX_PATH)
    
    print(f"Saving metadata to {CHUNKS_PATH}")
    with open(CHUNKS_PATH, "wb") as f:
        pickle.dump(techniques, f)
        
    print("Build complete.")

if __name__ == "__main__":
    build_index()
