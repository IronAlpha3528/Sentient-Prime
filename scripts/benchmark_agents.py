import os
import json
import time
from dotenv import load_dotenv

# Ensure we're running from the project root
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel_prime.ai.agents.correlation_agent import CorrelationAgent
from sentinel_prime.ai.agents.hypothesis_agent import HypothesisAgent
from sentinel_prime.ai.agents.prediction_agent import PredictionAgent
from sentinel_prime.ai.agents.deception_agent import DeceptionAgent
from sentinel_prime.ai.agents.response_agent import ResponseAgent

# 1. Load the API key from .env
load_dotenv()
if not os.getenv("GEMINI_API_KEY"):
    print("❌ Error: GEMINI_API_KEY not found in .env file or environment variables.")
    sys.exit(1)

# 2. Define our test scenarios
SCENARIOS = {
    "Scenario 1: Blatant Ransomware": {
        "expected_malicious": True,
        "context": {
            "evidence_object": {
                "incident_id": "INC-001",
                "entities": {"users": ["SYSTEM"], "hosts": ["FILE-SERVER-01"]},
                "endpoint": {
                    "score": 0.99, 
                    "process_chain": ["vssadmin.exe delete shadows /all /quiet", "cipher.exe"],
                    "sigma_matches": ["Shadow Copy Deletion", "Mass File Rename"]
                }
            },
            "graph_features": {"attack_path_length": 1, "node_centrality": 0.9},
            "attack_rag_context": ["T1490 - Inhibit System Recovery", "T1486 - Data Encrypted for Impact"]
        }
    },
    "Scenario 2: Benign IT Admin Task": {
        "expected_malicious": False,
        "context": {
            "evidence_object": {
                "incident_id": "INC-002",
                "entities": {"users": ["admin_jsmith"], "hosts": ["ENG-WS-01", "BACKUP-NAS"]},
                "endpoint": {
                    "score": 0.45, 
                    "process_chain": ["powershell.exe -file C:\\scripts\\weekly_backup.ps1"],
                    "sigma_matches": ["PowerShell Execution"]
                },
                "identity": {
                    "score": 0.1,
                    "notes": "Activity occurred during normal working hours from a known admin IP."
                }
            },
            "graph_features": {"attack_path_length": 1},
            "attack_rag_context": ["T1059.001 - Command and Scripting Interpreter: PowerShell"]
        }
    },
    "Scenario 3: Subtle Lateral Movement": {
        "expected_malicious": True,
        "context": {
            "evidence_object": {
                "incident_id": "INC-003",
                "entities": {"users": ["service_account_db"], "hosts": ["WEB-FRONTEND", "DB-BACKEND"]},
                "identity": {
                    "score": 0.92,
                    "notes": "Impossible travel detected. Same service account used from two countries within 5 minutes."
                },
                "network": {
                    "score": 0.75,
                    "class": "SMB Enumeration"
                }
            },
            "graph_features": {"attack_path_length": 3, "hop_count_to_critical_asset": 1},
            "attack_rag_context": ["T1021 - Remote Services", "T1078 - Valid Accounts"]
        }
    }
}

def run_benchmark():
    print("🚀 Initializing Sentinel-Prime AI Agents (Gemini Flash)...\n")
    
    try:
        correlation_agent = CorrelationAgent()
        hypothesis_agent = HypothesisAgent()
        prediction_agent = PredictionAgent()
        deception_agent = DeceptionAgent()
        response_agent = ResponseAgent()
    except Exception as e:
        print(f"Failed to initialize agents: {e}")
        return

    score = 0
    total = len(SCENARIOS)

    for name, data in SCENARIOS.items():
        print(f"\n==================================================")
        print(f"🧪 Testing {name}")
        print(f"==================================================")
        
        start_time = time.time()

        # --- AGENT 1: CORRELATION ---
        print("🧠 1. Running Correlation Agent...")
        prompt = f"Please analyze this context:\n{json.dumps(data['context'], indent=2)}"
        try:
            story_result = correlation_agent.agent.run(prompt)
            print(f"   ✅ Story Summary: {story_result.get('summary')}")
        except Exception as e:
            print(f"   ❌ Correlation Failed: {e}")
            continue

        # --- AGENT 2: HYPOTHESIS ---
        print("🧠 2. Running Hypothesis Agent...")
        try:
            hypothesis_result = hypothesis_agent.run(story_result)
            hypotheses = hypothesis_result.get("hypotheses", [])
            top_hypothesis = sorted(hypotheses, key=lambda x: x.get("confidence", 0), reverse=True)[0]
            
            is_malicious = top_hypothesis.get("is_malicious")
            print(f"   ✅ Top Hypothesis: '{top_hypothesis.get('title')}' (Conf: {top_hypothesis.get('confidence')})")
        except Exception as e:
            print(f"   ❌ Hypothesis Failed: {e}")
            continue

        # --- AGENT 3: PREDICTION ---
        print("🧠 3. Running Prediction Agent...")
        try:
            prediction_result = prediction_agent.run(hypothesis_result)
            print(f"   ✅ Predicted Next Technique: {prediction_result.get('likely_next_technique')}")
            print(f"   ✅ Predicted Target: {prediction_result.get('predicted_target')}")
        except Exception as e:
            print(f"   ❌ Prediction Failed: {e}")
            continue

        # --- AGENT 4: DECEPTION ---
        print("🧠 4. Running Deception Agent...")
        try:
            mock_graph = {"ENG-WS-01": ["SERVER-07"], "WEB-FRONTEND": ["DB-BACKEND"]}
            deception_result = deception_agent.run(hypothesis_result, prediction_result, mock_graph)
            if deception_result.get("is_testable"):
                print(f"   ✅ Proposed Decoy: {deception_result.get('decoy_type')} at {deception_result.get('placement_location')}")
            else:
                print("   ✅ No testable uncertainty found (decoy not needed).")
        except Exception as e:
            print(f"   ❌ Deception Failed: {e}")
            continue

        # --- AGENT 5: RESPONSE ---
        print("🧠 5. Running Response Agent...")
        try:
            mock_criticality = {"FILE-SERVER-01": "High", "DB-BACKEND": "Critical"}
            response_result = response_agent.run(hypothesis_result, prediction_result, mock_criticality)
            actions = response_result.get("recommended_actions", [])
            print(f"   ✅ Top Action: {actions[0].get('action_name') if actions else 'None'}")
        except Exception as e:
            print(f"   ❌ Response Failed: {e}")
            continue
            
        elapsed_time = round(time.time() - start_time, 2)
        print(f"\n⏱️  Pipeline completed in {elapsed_time} seconds.")

        # --- GRADING ---
        if is_malicious == data["expected_malicious"]:
            print(f"🟢 PASS: Agent correctly classified this as {'Malicious' if is_malicious else 'Benign'}.")
            score += 1
        else:
            print(f"🔴 FAIL: Agent classified this as {'Malicious' if is_malicious else 'Benign'}, expected {data['expected_malicious']}.")

    print("\n==================================================")
    print(f"🏁 Benchmark Complete: {score}/{total} Scenarios Passed")
    print("==================================================\n")

if __name__ == "__main__":
    run_benchmark()
