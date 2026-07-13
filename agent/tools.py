import json
from typing import Dict, Any

def fetch_correlation_context(incident_id: str) -> Dict[str, Any]:
    """
    Simulates Route B: Fetching all required context for the Correlation Agent.
    In a real implementation, this would query Elasticsearch, the BaselineStore, 
    the Cyber Entity Graph (NetworkX), and the FAISS ATT&CK vector DB.
    """
    return {
        "evidence_object": {
            "incident_id": incident_id,
            "entities": {"users": ["U101"], "hosts": ["ENG-WS-01", "SERVER-07"], "ips": ["10.0.1.20"]},
            "network": {"score": 0.82, "class": "infiltration"},
            "identity": {"score": 0.94, "new_hosts": 12},
            "endpoint": {"score": 0.97, "process_chain": ["WINWORD.EXE", "powershell.exe", "rundll32.exe"], "sigma_matches": ["Encoded PowerShell"]},
            "unified_threat_score": 0.91
        },
        "graph_features": {
            "attack_path_length": 2,
            "hop_count_to_critical_asset": 1,
            "node_centrality_ENG-WS-01": 0.85
        },
        "attack_rag_context": [
            "T1059.001 - Command and Scripting Interpreter: PowerShell is often used to execute malicious payloads.",
            "T1218 - System Binary Proxy Execution: rundll32.exe can be used to bypass application control."
        ]
    }

def fetch_prediction_context() -> Dict[str, Any]:
    """
    Fetches the MITRE ATT&CK Knowledge Graph relationships for the Prediction Agent.
    """
    return {
        "graph_topology": {
            "ENG-WS-01": ["SERVER-07", "10.0.1.20"],
            "SERVER-07": ["DB-01", "DC-01"]
        },
        "critical_assets": ["DB-01", "DC-01"]
    }
