import os
import json
import yaml
import networkx as nx
import google.generativeai as genai
from typing import Dict, Any
from .rag.query import search

# Ensure API key is configured
genai.configure(api_key=os.environ.get("GEMINI_API_KEY", ""))
MODEL_NAME = "gemini-1.5-flash"

# Constants
CONFIG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config")
TOPOLOGY_PATH = os.path.join(CONFIG_DIR, "topology.yaml")

SYSTEM_PROMPT = """
You are the APT Attribution & Prediction Agent for Sentient-Prime.
Your task is to take the most likely hypothesis and evidence, and output an attribution and prediction JSON.

CRITICAL RULES:
1. Attribute the behavior to a known threat actor group (e.g., APT41, Lazarus) based on the MITRE ATT&CK context provided.
2. Predict 1-2 likely next techniques the attacker will use.
3. Output MUST be valid, raw JSON exactly matching the schema. Do NOT include markdown blocks.

Output Schema Example:
{
  "attributed_actor": "APT41",
  "actor_origin": "China",
  "attribution_confidence": 0.65,
  "reasoning": "T1110 usage pattern matches APT41 TTPs against government infrastructure",
  "predicted_next_techniques": [
    {"technique_id": "T1078", "name": "Valid Accounts", "likelihood": 0.80, "timeframe": "2-6 hours"}
  ],
  "recommended_watch_points": ["Monitor new logins from source IP"]
}
"""

def load_topology_graph() -> nx.Graph:
    """Loads the topology from config/topology.yaml and builds a NetworkX graph."""
    with open(TOPOLOGY_PATH, "r") as f:
        topology_data = yaml.safe_load(f)
        
    G = nx.Graph()
    for node in topology_data.get("nodes", []):
        G.add_node(node["id"], criticality=node["criticality"])
        
    for edge in topology_data.get("edges", []):
        G.add_edge(edge["source"], edge["target"])
        
    return G

def compute_blast_radius(graph: nx.Graph, compromised_nodes: list[str], cutoff: int = 2) -> dict:
    """Computes the blast radius for the compromised assets."""
    total_score = 0
    reaches_ot = False
    reachable_assets = []
    
    for start_node in compromised_nodes:
        if start_node not in graph:
            continue
            
        # Get all nodes within 'cutoff' hops
        paths = nx.single_source_shortest_path_length(graph, start_node, cutoff=cutoff)
        
        for node_id, hops in paths.items():
            criticality = graph.nodes[node_id].get("criticality", 0)
            
            # Prevent double counting if multiple compromised nodes reach the same asset
            if not any(a["asset"] == node_id for a in reachable_assets):
                reachable_assets.append({
                    "asset": node_id,
                    "hops": hops,
                    "criticality": criticality
                })
                total_score += criticality
                if criticality >= 8:
                    reaches_ot = True

    return {
        "assets": reachable_assets,
        "score": total_score,
        "reaches_ot": reaches_ot
    }

def attribute_and_predict(hypothesis: dict, evidence: dict) -> dict:
    """
    Block 2: Performs APT attribution, predicts next steps, and calculates blast radius.
    """
    # 1. Gather context
    tech_id = hypothesis.get("technique_id")
    query_str = f"Threat actors using {tech_id} and what techniques usually follow {tech_id}"
    
    try:
        rag_results = search(query_str, top_k=3)
        rag_context = "\n".join([f"- {r['technique_id']}: {r['name']} - {r['description'][:200]}..." for r in rag_results])
    except Exception as e:
        rag_context = f"RAG context unavailable: {e}"

    user_prompt = f"""
    Top Hypothesis:
    {json.dumps(hypothesis, indent=2)}
    
    Original Evidence:
    {json.dumps(evidence, indent=2)}
    
    Relevant MITRE ATT&CK Context:
    {rag_context}
    
    Generate the attribution and prediction JSON.
    """
    
    model = genai.GenerativeModel(
        model_name=MODEL_NAME,
        system_instruction=SYSTEM_PROMPT
    )
    
    try:
        response = model.generate_content(user_prompt)
        text_output = response.text.replace("```json", "").replace("```", "").strip()
        result = json.loads(text_output)
    except Exception as e:
        print(f"Error in attribution: {e}")
        # Fallback dictionary
        result = {
            "attributed_actor": "Unknown",
            "actor_origin": "Unknown",
            "attribution_confidence": 0.0,
            "reasoning": f"Failed to parse AI response: {e}",
            "predicted_next_techniques": [],
            "recommended_watch_points": []
        }
        
    # 2. Compute blast radius based on graph
    # Try to map evidence entities to graph nodes. If none match, assume "internet" or "dmz_server" as entry.
    # In a real scenario, this mapping would be sophisticated. Here we use basic matching.
    G = load_topology_graph()
    compromised_assets = []
    
    # Check if hosts are specified in the evidence
    hosts = evidence.get("entities", {}).get("hosts", [])
    for host in hosts:
        # Simplistic matching for demo
        for node in G.nodes():
            if node.lower() in host.lower():
                compromised_assets.append(node)
                
    if not compromised_assets:
        # Fallback for demo scenario based on target_asset if it exists
        if "target_asset" in evidence:
            compromised_assets.append(evidence["target_asset"])
        else:
            compromised_assets = ["dmz_server"] # Safe default entry point
            
    blast_radius_info = compute_blast_radius(G, compromised_assets, cutoff=2)
    
    # Combine results
    result["blast_radius"] = blast_radius_info
    
    return result

if __name__ == "__main__":
    mock_hypothesis = {
      "hypothesis": "APT41 initial credential access attempt",
      "technique_id": "T1110",
      "technique_name": "Brute Force"
    }
    mock_evidence = {
      "target_asset": "app_server",
      "entities": {}
    }
    
    if os.environ.get("GEMINI_API_KEY"):
        print("Testing APT Attribution Agent...")
        result = attribute_and_predict(mock_hypothesis, mock_evidence)
        print(json.dumps(result, indent=2))
    else:
        print("Set GEMINI_API_KEY to test the Gemini API call.")
        # But we can still test the blast radius graph logic
        print("Testing Blast Radius only...")
        G = load_topology_graph()
        br = compute_blast_radius(G, ["app_server"])
        print(json.dumps(br, indent=2))
