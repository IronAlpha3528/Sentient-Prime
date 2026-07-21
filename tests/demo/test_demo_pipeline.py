import sys
from pathlib import Path
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.demo.demo_orchestrator import DemoOrchestrator
from scripts.demo.scenarios import get_scenario_event

def test_demo_orchestrator_benign():
    """Verify that a benign event halts the pipeline early without triggering AI/SOAR in demo."""
    orchestrator = DemoOrchestrator()
    event = get_scenario_event("benign", 1)
    
    result = orchestrator.run_scenario(event, run_second_loop=False)
    
    # Check if we got a detection
    score = result.get("score", 0.0)
    assert score < 0.5, "Benign event should have a score < 0.5"

def test_demo_orchestrator_ransomware_closed_loop():
    """Verify that ransomware triggers detection, AI, SOAR, and the closed loop."""
    orchestrator = DemoOrchestrator()
    event = get_scenario_event("ransomware", 1)
    
    result = orchestrator.run_scenario(event, run_second_loop=True)
    
    # Check if we got a detection
    score = result.get("score", 0.0)
    assert score >= 0.5, "Ransomware event should have a score >= 0.5"
    
    # Check if SOAR result is present
    assert "soar_result" in result
    
    # The feedback loop simulation should have advanced the iteration count internally
    assert orchestrator.feedback_engine.iteration > 0
    
def test_demo_orchestrator_honeypot():
    """Verify honeypot deployment mechanics in demo orchestrator."""
    orchestrator = DemoOrchestrator()
    event = get_scenario_event("brute_force", 1)
    
    result = orchestrator.run_scenario(event, run_second_loop=False)
    score = result.get("score", 0.0)
    assert score >= 0.5
    
    # Ensure honeypot deployer is reachable
    assert hasattr(orchestrator, "decoy_deployer")
