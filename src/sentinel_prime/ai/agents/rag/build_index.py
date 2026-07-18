import os
import json
import urllib.request
import pickle
import faiss
import networkx as nx
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
    """Parses the STIX JSON and extracts techniques, tactics, groups, software, and relationships to build a NetworkX graph."""
    print("Parsing ATT&CK data...")
    with open(ATTACK_JSON_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    techniques = []
    G = nx.DiGraph()
    stix_nodes = {}
    relationships = []
    
    # 1. Parse all objects and add nodes to the graph
    for obj in data.get("objects", []):
        stix_id = obj.get("id")
        obj_type = obj.get("type")
        
        if not stix_id or not obj_type:
            continue
            
        if obj_type == "relationship":
            relationships.append(obj)
            continue
            
        # Ignore irrelevant administrative/marking objects
        if obj_type in ["marking-definition", "identity"]:
            continue
            
        # Extract MITRE ATT&CK external reference ID (e.g., T1110, G0096)
        external_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") in ["mitre-attack", "mitre-mobile-attack"]:
                external_id = ref.get("external_id")
                break
                
        if not external_id and obj_type == "x-mitre-tactic":
            external_id = obj.get("x_mitre_shortname")
            
        name = obj.get("name", "")
        description = obj.get("description", "")
        
        # Determine cleaned category type for GraphRAG
        clean_type = obj_type
        if obj_type == "attack-pattern":
            if obj.get("x_mitre_is_subtechnique"):
                clean_type = "sub-technique"
            else:
                clean_type = "technique"
        elif obj_type == "intrusion-set":
            clean_type = "group"
        elif obj_type == "course-of-action":
            clean_type = "mitigation"
        elif obj_type == "x-mitre-data-source":
            clean_type = "data-source"
        elif obj_type == "x-mitre-tactic":
            clean_type = "tactic"
            
        node_attrs = {
            "stix_id": stix_id,
            "external_id": external_id,
            "name": name,
            "type": clean_type,
            "description": description,
            "platforms": obj.get("x_mitre_platforms", []),
            "phase_names": [p.get("phase_name") for p in obj.get("kill_chain_phases", [])] if obj.get("kill_chain_phases") else []
        }
        
        G.add_node(stix_id, **node_attrs)
        stix_nodes[stix_id] = node_attrs
        
        # Keep techniques list for FAISS (techniques and sub-techniques)
        if clean_type in ["technique", "sub-technique"]:
            if external_id:
                chunk_text = f"Technique ID: {external_id}\nName: {name}\nDescription: {description}"
                techniques.append({
                    "technique_id": external_id,
                    "name": name,
                    "description": description,
                    "chunk_text": chunk_text
                })
                
    # 2. Add relationship edges to the graph
    edge_count = 0
    for rel in relationships:
        source_ref = rel.get("source_ref")
        target_ref = rel.get("target_ref")
        rel_type = rel.get("relationship_type")
        
        if source_ref in G and target_ref in G:
            G.add_edge(
                source_ref,
                target_ref,
                relationship_type=rel_type,
                id=rel.get("id"),
                description=rel.get("description", "")
            )
            edge_count += 1
            
    print(f"Graph constructed: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges.")
    print(f"Extracted {len(techniques)} techniques for semantic indexing.")
    return techniques, G

def build_index():
    """Embeds the chunks, builds the FAISS index, and serializes the NetworkX graph."""
    download_attack_data()
    techniques, G = parse_attack_data()
    
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
    
    # Save metadata with embedded vectors for caching
    for i, t in enumerate(techniques):
        t["_embedding"] = embeddings[i].tolist()
        
    print(f"Saving metadata to {CHUNKS_PATH}")
    with open(CHUNKS_PATH, "wb") as f:
        pickle.dump(techniques, f)
        
    # Compile static threat graph alongside index
    GRAPH_PATH = os.path.join(INDEX_DIR, "attack_graph.pkl")
    print(f"Saving static threat graph to {GRAPH_PATH}...")
    with open(GRAPH_PATH, "wb") as f:
        pickle.dump(G, f)
        
    # Compile lexical index for primary MITRE ATT&CK
    from sentinel_prime.ai.agents.rag.providers.attack import AttackProvider
    try:
        attack_prov = AttackProvider(INDEX_DIR)
        attack_prov.ingest("")
    except Exception as e:
        print(f"Error compiling BM25 index for ATT&CK: {e}")
        
    # Compile indices for secondary Threat Intelligence providers
    from sentinel_prime.ai.agents.rag.providers.generic import GenericProvider
    
    THREAT_INTEL_DATA_DIR = os.path.join(DATA_DIR, "threat_intel")
    providers_info = {
        "d3fend": "d3fend.json",
        "sigma": "sigma.json",
        "yara": "yara.json",
        "cve": "cve.json",
        "kev": "kev.json",
        "playbook": "playbooks.json",
        "policy": "policies.json",
        "threat_report": "threat_reports.json"
    }
    
    for provider_name, filename in providers_info.items():
        raw_path = os.path.join(THREAT_INTEL_DATA_DIR, filename)
        if os.path.exists(raw_path):
            try:
                prov = GenericProvider(provider_name, INDEX_DIR)
                prov.ingest(raw_path)
            except Exception as e:
                print(f"Error compiling index for provider '{provider_name}': {e}")
        else:
            print(f"Warning: Raw threat intel data not found for '{provider_name}' at {raw_path}. Skipping provider index compilation.")
            
    print("Build complete.")

if __name__ == "__main__":
    build_index()
