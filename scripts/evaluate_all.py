"""
evaluate_all.py — Master Evaluation Orchestrator for Sentient-Prime
====================================================================

Runs all evaluation scripts in sequence and writes a formatted Markdown
report to eval_report.md.

Usage:
    python scripts/evaluate_all.py

    --no-ai    Skip eval_apt_attribution.py (avoids Gemini API calls)
    --json     Also write results to eval_results.json

The report is suitable for direct inclusion in a pitch deck or README.
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

REPORT_PATH = PROJECT_ROOT / "eval_report.md"
JSON_PATH   = PROJECT_ROOT / "eval_results.json"
DATASET_PATH = PROJECT_ROOT / "data" / "eval_ground_truth.json"


def _banner(msg: str) -> None:
    print(f"\n{'━' * 62}")
    print(f"  {msg}")
    print(f"{'━' * 62}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-ai", action="store_true", help="Skip APT attribution (no Gemini API calls)")
    parser.add_argument("--json", action="store_true", help="Also emit eval_results.json")
    args = parser.parse_args()

    _banner("Sentient-Prime — Full Evaluation Suite")

    # ── Step 0: Generate the dataset if missing ───────────────────────────────
    if not DATASET_PATH.exists():
        _banner("Step 0: Generating synthetic benchmark dataset...")
        from generate_synthetic_benchmark import main as gen_main
        gen_main()
    else:
        print(f"\n  ✅ Dataset found: {DATASET_PATH.name}  ({_count_lines(DATASET_PATH)} incidents)")

    # ── Step 1: ML Detectors ──────────────────────────────────────────────────
    _banner("Step 1 / 4 — ML Detection Rate & FPR")
    sys.path.insert(0, str(PROJECT_ROOT / "scripts" / "eval"))
    from eval.eval_ml_detectors import run as run_ml
    ml_results = run_ml()

    # ── Step 2: APT Attribution ───────────────────────────────────────────────
    if args.no_ai:
        print("\n  Skipping APT attribution (--no-ai flag set)")
        apt_results = {"status": "SKIPPED"}
    else:
        _banner("Step 2 / 4 — APT Attribution Accuracy")
        from eval.eval_apt_attribution import run as run_apt
        apt_results = run_apt()

    # ── Step 3: SOAR / Automation ─────────────────────────────────────────────
    _banner("Step 3 / 4 — Automation Coverage & MTTD/MTTR")
    from eval.eval_soar_metrics import run as run_soar
    soar_results = run_soar()

    # ── Step 4: Ledger Auditability ───────────────────────────────────────────
    _banner("Step 4 / 4 — Ledger Auditability")
    from eval.eval_ledger_audit import run as run_ledger
    ledger_results = run_ledger()

    # ── Write Markdown Report ─────────────────────────────────────────────────
    _banner("Writing eval_report.md...")
    report = _build_markdown(ml_results, apt_results, soar_results, ledger_results)
    REPORT_PATH.write_text(report, encoding="utf-8")
    print(f"  ✅ Report written to: {REPORT_PATH}")

    if args.json:
        all_results = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "ml_detectors": ml_results,
            "apt_attribution": apt_results,
            "soar_metrics": soar_results,
            "ledger_audit": ledger_results,
        }
        JSON_PATH.write_text(json.dumps(all_results, indent=2, default=str), encoding="utf-8")
        print(f"  ✅ JSON results written to: {JSON_PATH}")


def _count_lines(path: Path) -> int:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return len(data)
    except Exception:
        return 0


def _fmt(val, suffix="", fmt=".1%") -> str:
    if isinstance(val, float):
        try:
            return format(val, fmt) + suffix
        except (ValueError, TypeError):
            return str(val) + suffix
    return str(val) + suffix


def _build_markdown(ml: dict, apt: dict, soar: dict, ledger: dict) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# Sentient-Prime — Evaluation Report",
        f"\n> Generated: {ts}",
        "\n---\n",

        "## 1. Anomaly Detection Rate & False Positive Rate\n",
        "> Evaluated via Deterministic Threat Injection benchmark.",
        "> Categorical IoCs (process chains, Sigma rules) sourced from MITRE ATT&CK + Atomic Red Team.",
        "> Numerical features sampled from published CIC-IDS2018, LANL, and HAI dataset statistics.\n",
        "| Detector | Detection Rate (Recall) | False Positive Rate | F1 | ROC-AUC |",
        "|---|---|---|---|---|",
    ]

    for name, result in ml.items():
        if isinstance(result, dict) and result.get("status") == "OK":
            lines.append(
                f"| **{name}** | {_fmt(result.get('recall_detection_rate', 0))} "
                f"| {_fmt(result.get('false_positive_rate', 0))} "
                f"| {_fmt(result.get('f1', 0))} "
                f"| {result.get('roc_auc', 'N/A')} |"
            )
        else:
            status = result.get("status", "N/A") if isinstance(result, dict) else str(result)
            lines.append(f"| **{name}** | {status} | — | — | — |")

    lines += [
        "\n---\n",
        "## 2. APT Attribution Accuracy (MITRE ATT&CK Technique Level)\n",
    ]
    if apt.get("status") == "SKIPPED":
        lines.append("> *Skipped (run without --no-ai to evaluate)*")
    else:
        any_match = _fmt(apt.get("any_technique_match_rate", 0))
        top3 = _fmt(apt.get("top3_accuracy", 0))
        top1 = _fmt(apt.get("top1_accuracy", 0))
        n = apt.get("total_incidents_evaluated", 0)
        avg_t = apt.get("avg_pipeline_time_s", 0)
        lines += [
            f"| Metric | Value |",
            "|---|---|",
            f"| Incidents evaluated | {n} |",
            f"| Top-1 Technique Accuracy | **{top1}** |",
            f"| Top-3 Technique Accuracy | **{top3}** |",
            f"| Any Technique Match Rate | **{any_match}** |",
            f"| Avg AI Pipeline Time | {avg_t}s |",
        ]

    lines += [
        "\n---\n",
        "## 3. Incident Response Automation Coverage\n",
    ]
    auto_pct = soar.get("automation_coverage_pct", "N/A")
    auto_n = soar.get("auto_contained", "N/A")
    esc_n = soar.get("escalated_to_human", "N/A")
    total_n = soar.get("total_incidents", "N/A")
    lines += [
        f"| Metric | Value |",
        "|---|---|",
        f"| Total incidents processed | {total_n} |",
        f"| Auto-contained (no human) | {auto_n} (**{auto_pct}%**) |",
        f"| Escalated to approval queue | {esc_n} |",
        f"| Automation coverage | **{auto_pct}%** |",
    ]

    lines += [
        "\n---\n",
        "## 4. MTTD / MTTR Improvement vs Manual SOC Baseline\n",
        "> Baseline: IBM X-Force Threat Intelligence Index 2023 (MTTD ≈ 45 min alert-to-triage),",
        "> IBM Cost of a Data Breach 2023 (MTTR ≈ 12 hours triage-to-contain).\n",
    ]
    mttd_ms = soar.get("avg_mttd_ms", "N/A")
    mttr_ms = soar.get("avg_mttr_ms", "N/A")
    mttd_x = soar.get("mttd_improvement_factor", "N/A")
    mttr_x = soar.get("mttr_improvement_factor", "N/A")
    base_mttd = soar.get("baseline_mttd_minutes", 45)
    base_mttr = soar.get("baseline_mttr_minutes", 720)
    lines += [
        "| | Sentient-Prime | Manual SOC Baseline | Improvement |",
        "|---|---|---|---|",
        f"| MTTD | **{mttd_ms}ms** | {base_mttd} min | **{mttd_x}× faster** |",
        f"| MTTR | **{mttr_ms}ms** | {base_mttr} min | **{mttr_x}× faster** |",
    ]

    lines += [
        "\n---\n",
        "## 5. Ledger Auditability\n",
    ]
    chain_status = ledger.get("status", "N/A")
    audit_pct = ledger.get("auditability_coverage_pct", "N/A")
    n_entries = ledger.get("entries_checked", ledger.get("total_incidents_with_actions", "N/A"))
    errors = ledger.get("hash_errors", 0)
    lines += [
        f"| Metric | Value |",
        "|---|---|",
        f"| Hash chain status | **{chain_status}** |",
        f"| Entries verified | {n_entries} |",
        f"| Hash errors | {errors} |",
        f"| Action traceability coverage | **{audit_pct}%** |",
        "",
        "> Every automated action is logged with a SHA-256 hash linking it to the",
        "> prior AI reasoning block and originating detection event.",
        "\n---\n",
        "_Report auto-generated by `scripts/evaluate_all.py`_",
    ]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    main()
