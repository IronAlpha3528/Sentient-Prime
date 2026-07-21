"""Predefined synthetic telemetry scenarios for the Sentient-Prime demonstration.
These scenarios mimic the CSE-CIC-IDS2018 processed format expected by Phase1Pipeline.
"""

def get_scenario_event(scenario_name: str, index: int = 0) -> dict:
    """Return a single event for the given scenario."""
    
    base_network_features = {
        "Dst Port": 80,
        "Protocol": 6,
        "Flow Duration": 1000,
        "Tot Fwd Pkts": 5,
        "Tot Bwd Pkts": 5,
        "TotLen Fwd Pkts": 500,
        "TotLen Bwd Pkts": 500,
        "Fwd Pkt Len Max": 100,
        "Fwd Pkt Len Min": 0,
        "Fwd Pkt Len Mean": 50,
        "Fwd Pkt Len Std": 10,
        "Bwd Pkt Len Max": 100,
        "Bwd Pkt Len Min": 0,
        "Bwd Pkt Len Mean": 50,
        "Bwd Pkt Len Std": 10,
        "Flow Byts/s": 1000,
        "Flow Pkts/s": 10,
        "Flow IAT Mean": 100,
        "Flow IAT Std": 10,
        "Flow IAT Max": 200,
        "Flow IAT Min": 10,
        "Fwd IAT Tot": 500,
        "Fwd IAT Mean": 100,
        "Fwd IAT Std": 10,
        "Fwd IAT Max": 200,
        "Fwd IAT Min": 10,
        "Bwd IAT Tot": 500,
        "Bwd IAT Mean": 100,
        "Bwd IAT Std": 10,
        "Bwd IAT Max": 200,
        "Bwd IAT Min": 10,
        "Fwd PSH Flags": 0,
        "Bwd PSH Flags": 0,
        "Fwd URG Flags": 0,
        "Bwd URG Flags": 0,
        "Fwd Header Len": 100,
        "Bwd Header Len": 100,
        "Fwd Pkts/s": 5,
        "Bwd Pkts/s": 5,
        "Pkt Len Min": 0,
        "Pkt Len Max": 100,
        "Pkt Len Mean": 50,
        "Pkt Len Std": 10,
        "Pkt Len Var": 100,
        "FIN Flag Cnt": 0,
        "SYN Flag Cnt": 0,
        "RST Flag Cnt": 0,
        "PSH Flag Cnt": 0,
        "ACK Flag Cnt": 0,
        "URG Flag Cnt": 0,
        "CWE Flag Count": 0,
        "ECE Flag Cnt": 0,
        "Down/Up Ratio": 1,
        "Pkt Size Avg": 50,
        "Fwd Seg Size Avg": 50,
        "Bwd Seg Size Avg": 50,
        "Fwd Byts/b Avg": 0,
        "Fwd Pkts/b Avg": 0,
        "Fwd Blk Rate Avg": 0,
        "Bwd Byts/b Avg": 0,
        "Bwd Pkts/b Avg": 0,
        "Bwd Blk Rate Avg": 0,
        "Subflow Fwd Pkts": 5,
        "Subflow Fwd Byts": 500,
        "Subflow Bwd Pkts": 5,
        "Subflow Bwd Byts": 500,
        "Init Fwd Win Byts": 8192,
        "Init Bwd Win Byts": 8192,
        "Fwd Act Data Pkts": 5,
        "Fwd Seg Size Min": 20,
        "Active Mean": 0,
        "Active Std": 0,
        "Active Max": 0,
        "Active Min": 0,
        "Idle Mean": 0,
        "Idle Std": 0,
        "Idle Max": 0,
        "Idle Min": 0,
    }

    scenarios = {
        "ransomware": {
            "telemetry_type": "network",
            "entity_id": f"HOST-RANSOM-{index}",
            "data": {
                **base_network_features,
                "Dst Port": 445,  # SMB
                "Flow Duration": 5000000,
                "Tot Fwd Pkts": 5000,
                "Tot Bwd Pkts": 5000,
                "Flow Byts/s": 1000000,
                "Label": 1  # Malicious label for synthetic tests if needed
            },
            "context_hints": "Multiple SMB file renames observed."
        },
        "brute_force": {
            "telemetry_type": "network",
            "entity_id": f"HOST-BRUTE-{index}",
            "data": {
                **base_network_features,
                "Dst Port": 22,  # SSH
                "Flow Duration": 1000,
                "Tot Fwd Pkts": 2,
                "Tot Bwd Pkts": 2,
                "Label": 1
            },
            "context_hints": "Rapid successive authentication failures."
        },
        "honeypot_trigger": {
            "telemetry_type": "honeypot",
            "entity_id": f"HONEYPOT-DECOY-{index}",
            "data": {
                "decoy_id": "DECOY-SYNTH-1234",
                "action": "file_read",
                "source_ip": "10.0.0.45",
                "timestamp": "2024-01-01T12:00:00Z"
            }
        },
        "benign": {
            "telemetry_type": "network",
            "entity_id": f"HOST-BENIGN-{index}",
            "data": {
                **base_network_features,
                "Dst Port": 443,  # HTTPS
                "Flow Duration": 200,
                "Label": 0
            }
        }
    }

    if scenario_name not in scenarios:
        raise ValueError(f"Unknown scenario: {scenario_name}")
        
    return scenarios[scenario_name]
