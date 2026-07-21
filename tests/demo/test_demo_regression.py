import subprocess
import sys
from pathlib import Path
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

@pytest.mark.slow
def test_production_regression():
    """
    Ensure that the baseline evaluate_all.py script runs without errors, 
    meaning the demo subsystem did not interfere with any production logic.
    """
    eval_script = PROJECT_ROOT / "scripts" / "evaluate_all.py"
    
    assert eval_script.exists(), "evaluate_all.py missing"
    
    # Run the script with --no-ai to avoid expensive LLM calls during regression test,
    # as we only want to ensure the logic isn't broken.
    result = subprocess.run(
        [sys.executable, str(eval_script), "--no-ai"],
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True
    )
    
    assert result.returncode == 0, f"Production evaluation failed! Regressions detected. Output: {result.stderr}\n{result.stdout}"
    
    # Make sure eval_report.md was generated as a sign of success
    report_file = PROJECT_ROOT / "eval_report.md"
    assert report_file.exists(), "eval_report.md was not generated, evaluation may have failed silently."
