import os
import json
import time
import sys
from pathlib import Path

# Ensure we're running from the project root
sys.path.append(str(Path(__file__).resolve().parents[1]))

from sentinel_prime.core.config_manager import config
from sentinel_prime.ai.agents.analysis_agent import AnalysisAgent
from sentinel_prime.ai.agents.critique_agent import CritiqueAgent
from sentinel_prime.ai.agents.action_agent import ActionAgent

if not config.GEMINI_API_KEY:
    print("❌ Error: GEMINI_API_KEY not found in config.")
    sys.exit(1)

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
    }
}

def run_benchmark():
    print("🚀 Initializing Refactored 3-Stage Sentinel-Prime AI Agents...\n")
    
    try:
        analysis_agent = AnalysisAgent()
        critique_agent = CritiqueAgent()
        action_agent = ActionAgent()
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
        
        context = data["context"]

        # --- STAGE 1: ANALYSIS ---
        print("🧠 1. Running Analysis Agent...")
        try:
            analysis_result = analysis_agent.run(context)
            hypotheses = analysis_result.get("hypotheses", [])
            top_hypothesis = sorted(hypotheses, key=lambda x: x.get("confidence", 0), reverse=True)[0]
            
            print(f"   ✅ Story Summary: {analysis_result.get('story', {}).get('summary')}")
            print(f"   ✅ Top Hypothesis: '{top_hypothesis.get('title')}' (Conf: {top_hypothesis.get('confidence')})")
        except Exception as e:
            print(f"   ❌ Analysis Failed: {e}")
            continue

        # --- STAGE 2: CRITIQUE ---
        print("🧠 2. Running Critique Agent...")
        try:
            critique_result = critique_agent.run(analysis_result, context)
            print(f"   ✅ Critique Valid: {critique_result.get('is_valid')}")
        except Exception as e:
            print(f"   ❌ Critique Failed: {e}")
            continue

        # --- STAGE 3: ACTION ---
        print("🧠 3. Running Action Agent...")
        try:
            action_result = action_agent.run(analysis_result, critique_result, context)
            actions = action_result.get("recommended_actions", [])
            print(f"   ✅ Top Action: {actions[0].get('action_name') if actions else 'None'}")
        except Exception as e:
            print(f"   ❌ Action Failed: {e}")
            continue
            
        elapsed_time = round(time.time() - start_time, 2)
        print(f"\n⏱️  Pipeline completed in {elapsed_time} seconds.")

        # --- GRADING ---
        is_malicious = top_hypothesis.get("is_malicious")
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
