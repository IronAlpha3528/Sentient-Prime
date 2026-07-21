import argparse
import sys
from pathlib import Path

# Add the project root to python path to resolve modules
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.demo.demo_orchestrator import DemoOrchestrator
from scripts.demo.scenarios import get_scenario_event
from scripts.demo.demo_logger import demo_logger

def main():
    parser = argparse.ArgumentParser(description="Sentient-Prime Autonomous Defense Demonstration")
    parser.add_argument("--mode", type=int, choices=[1, 2, 3, 4, 5], default=3,
                        help="1: Single Incident, 2: Multi-stage, 3: Closed Loop (Default), 4: Monitoring, 5: Honeypot")
    args = parser.parse_args()

    orchestrator = DemoOrchestrator()

    if args.mode == 1:
        demo_logger._banner("MODE 1: SINGLE INCIDENT DEMONSTRATION")
        event = get_scenario_event("ransomware", 1)
        orchestrator.run_scenario(event, run_second_loop=False)

    elif args.mode == 2:
        demo_logger._banner("MODE 2: MULTI-STAGE ATTACK DEMONSTRATION")
        event1 = get_scenario_event("brute_force", 1)
        orchestrator.run_scenario(event1, run_second_loop=False)
        demo_logger.info("--- Phase 2 of Attack ---")
        event2 = get_scenario_event("ransomware", 1)
        orchestrator.run_scenario(event2, run_second_loop=False)

    elif args.mode == 3:
        demo_logger._banner("MODE 3: AUTONOMOUS CLOSED LOOP DEMONSTRATION")
        event = get_scenario_event("ransomware", 1)
        orchestrator.run_scenario(event, run_second_loop=True)
        
    elif args.mode == 4:
        demo_logger._banner("MODE 4: CONTINUOUS MONITORING DEMONSTRATION")
        event = get_scenario_event("benign", 1)
        orchestrator.run_scenario(event, run_second_loop=False)
        
    elif args.mode == 5:
        demo_logger._banner("MODE 5: HONEYPOT DEMONSTRATION")
        # Trigger an attack which will deploy the honeypot
        event = get_scenario_event("brute_force", 1)
        orchestrator.run_scenario(event, run_second_loop=True)
        
        # Now simulate honeypot trigger
        hp_event = get_scenario_event("honeypot_trigger", 1)
        demo_logger.step("HONEYPOT TRIGGERED BY ADVERSARY")
        demo_logger.info(f"Received alert from Decoy: {hp_event}")
        demo_logger.success("Adversary identified via Honeypot trap. Initiating immediate isolation.")

if __name__ == "__main__":
    main()
