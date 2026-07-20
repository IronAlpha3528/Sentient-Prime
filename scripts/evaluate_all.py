"""
evaluate_all.py — Master Evaluation Orchestrator for Sentient-Prime
====================================================================

Runs the unified pipeline evaluation, audits the ledger, and writes a
formatted Markdown report to eval_report.md.

Usage:
    python scripts/evaluate_all.py

    --no-ai    Skip eval_apt_attribution.py (avoids Gemini API calls)
    --json     Also write results to eval_results.json
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Force UTF-8 output on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

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


def _build_markdown(ml: dict, apt: dict, soar: dict, ledger: dict, eval_results: dict) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    
    meta_m = eval_results["meta_classifier"]
    meta_cm = meta_m["confusion_matrix"]

    lines = [
        "# Sentient-Prime — Evaluation Report",
        f"\n> Generated: {ts}",
        "\n---\n",

        "## 1. Specialist Detectors Classification Performance (Domain-Specific)\n",
        "> Evaluated via Specialist Detectors against domain-specific labels to measure isolation accuracy.",
        "| Detector | Recall (Detection Rate) | False Positive Rate | F1 | ROC-AUC |",
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
        "\n### Specialist Detectors Confusion Matrices\n",
        "| Detector | True Positives (TP) | False Positives (FP) | True Negatives (TN) | False Negatives (FN) |",
        "|---|---|---|---|---|",
    ]

    for name, result in ml.items():
        if isinstance(result, dict) and "confusion_matrix" in result:
            cm = result["confusion_matrix"]
            lines.append(
                f"| **{name}** | {cm.get('tp', 0)} | {cm.get('fp', 0)} | {cm.get('tn', 0)} | {cm.get('fn', 0)} |"
            )

    lines += [
        "\n---\n",
        "## 2. Meta-Classifier & End-to-End Pipeline Performance (Global Label)\n",
        "> Evaluated against the global benign vs malicious label to measure the complete framework's accuracy.",
        "\n### Meta-Classifier Metrics\n",
        "| Metric | Value |",
        "|---|---|",
        f"| Global Detection Rate (Recall) | **{_fmt(meta_m.get('recall_detection_rate', 0))}** |",
        f"| Global False Positive Rate | **{_fmt(meta_m.get('false_positive_rate', 0))}** |",
        f"| F1 Score | **{_fmt(meta_m.get('f1', 0))}** |",
        f"| ROC-AUC | **{meta_m.get('roc_auc', 'N/A')}** |",
        f"| Precision | **{_fmt(meta_m.get('precision', 0))}** |",
        
        "\n### Meta-Classifier Confusion Matrix\n",
        "| Metric | Value |",
        "|---|---|",
        f"| True Positives (TP) | **{meta_cm.get('tp', 0)}** |",
        f"| False Positives (FP) | **{meta_cm.get('fp', 0)}** |",
        f"| True Negatives (TN) | **{meta_cm.get('tn', 0)}** |",
        f"| False Negatives (FN) | **{meta_cm.get('fn', 0)}** |",
    ]

    lines += [
        "\n---\n",
        "## 3. APT Attribution Accuracy (MITRE ATT&CK Technique Level)\n",
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
        "## 4. Incident Response Automation Coverage\n",
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
        "## 5. MTTD / MTTR Improvement vs Manual SOC Baseline\n",
        "> Baseline: IBM X-Force Threat Intelligence Index 2023 (MTTD ≈ 45 min alert-to-triage),",
        "> IBM Cost of a Data Breach 2023 (MTTR ≈ 12 hours triage-to-contain).\n",
        "> **Scope note:** Sentient-Prime MTTD = time from event intake to detection flag & routing.",
        "> Sentient-Prime MTTR = AI analysis + SOAR dispatch decision latency (not physical containment).\n",
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
        f"| MTTD (alert-to-detection flag) | **{mttd_ms}ms** | {base_mttd} min | **{mttd_x}× faster** |",
        f"| MTTR (AI analysis + dispatch) | **{mttr_ms}ms** | {base_mttr} min | **{mttr_x}× faster (triage only)** |",
    ]

    lines += [
        "\n---\n",
        "## 6. Ledger Auditability\n",
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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-ai", action="store_true", help="Skip APT attribution (no Gemini API calls)")
    parser.add_argument("--json", action="store_true", help="Also emit eval_results.json")
    args = parser.parse_args()

    _banner("Sentient-Prime — Master Evaluation Coordinator")

    _banner("Step 0: Generating synthetic benchmark dataset...")
    if not DATASET_PATH.exists():
        from generate_synthetic_benchmark import main as gen_main
        gen_main()
    else:
        print(f"\n  ✅ Dataset found: {DATASET_PATH.name}  ({_count_lines(DATASET_PATH)} incidents)")

    # Wipe the ledger to ensure a clean hash chain for this evaluation run
    LEDGER_PATH = PROJECT_ROOT / "data" / "audit_ledger.jsonl"
    if LEDGER_PATH.exists():
        LEDGER_PATH.unlink()
        print(f"  🧹 Cleared previous audit ledger: {LEDGER_PATH.name}")

    # ── Step 1: Run Unified Pipeline Evaluation ──────────────────────────────
    _banner("Running Unified Architectural Pipeline Evaluation...")
    sys.path.insert(0, str(PROJECT_ROOT / "scripts" / "eval"))
    from eval.eval_pipeline import get_or_run_eval
    eval_results = get_or_run_eval()

    ml_results = eval_results["specialist_detectors"]
    apt_results = eval_results["apt_attribution"]
    soar_results = eval_results["soar_metrics"]

    if args.no_ai:
        print("\n  Bypassing Agent Attribution Metrics as requested (--no-ai set)")
        apt_results = {"status": "SKIPPED"}

    # ── Step 2: Audit Ledger Traceability ─────────────────────────────────────
    _banner("Auditing Ledger Action Traceability...")
    from eval.eval_ledger_audit import run as run_ledger
    ledger_results = run_ledger()

    # Print results summary to stdout
    print("\n" + "═" * 60)
    print("  EVALUATION SUMMARY")
    print("═" * 60)
    print("\n  Specialist Detectors:")
    for name, result in ml_results.items():
        cm = result.get("confusion_matrix", {})
        print(f"    - {name:<30}: DR={result.get('recall_detection_rate'):.1%} FPR={result.get('false_positive_rate'):.1%} F1={result.get('f1'):.1%} (TP={cm.get('tp')} FP={cm.get('fp')} TN={cm.get('tn')} FN={cm.get('fn')})")

    meta_m = eval_results["meta_classifier"]
    meta_cm = meta_m.get("confusion_matrix", {})
    print(f"\n  Meta-Classifier (End-to-End):")
    print(f"    - Global Detection Rate (Recall) : {meta_m.get('recall_detection_rate'):.1%}")
    print(f"    - Global False Positive Rate     : {meta_m.get('false_positive_rate'):.1%}")
    print(f"    - F1 Score                       : {meta_m.get('f1'):.1%}")
    print(f"    - Confusion Matrix               : TP={meta_cm.get('tp')} FP={meta_cm.get('fp')} TN={meta_cm.get('tn')} FN={meta_cm.get('fn')}")

    # ── Write Markdown Report ─────────────────────────────────────────────────
    _banner("Writing eval_report.md...")
    report = _build_markdown(ml_results, apt_results, soar_results, ledger_results, eval_results)
    REPORT_PATH.write_text(report, encoding="utf-8")
    print(f"  ✅ Report written to: {REPORT_PATH}")

    if args.json:
        all_results = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "ml_detectors": ml_results,
            "meta_classifier": meta_m,
            "apt_attribution": apt_results,
            "soar_metrics": soar_results,
            "ledger_audit": ledger_results,
        }
        JSON_PATH.write_text(json.dumps(all_results, indent=2, default=str), encoding="utf-8")
        print(f"  ✅ JSON results written to: {JSON_PATH}")


if __name__ == "__main__":
    main()
