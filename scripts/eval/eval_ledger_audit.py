"""
eval_ledger_audit.py — Metric 5: Full Auditability of Every Automated Action
=============================================================================

Reads data/audit_ledger.jsonl and verifies:
  1. SHA-256 hash chain integrity (tamper-evidence).
  2. Completeness: every ACTION event has a traceable predecessor chain
     (DETECTION → AI_REASONING → POLICY_DECISION → ACTION).
  3. Coverage: percentage of recorded actions that are fully auditable.

Run from project root:
    python scripts/eval/eval_ledger_audit.py
"""

import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

LEDGER_PATH = PROJECT_ROOT / "data" / "audit_ledger.jsonl"

# Event types that represent a forward audit chain
DETECTION_EVENTS = {"detection", "telemetry", "evidence_published"}
AI_EVENTS = {"ai_correlation", "ai_hypotheses", "ai_prediction", "ai_deception", "ai_response"}
POLICY_EVENTS = {"policy_decision", "dry_run"}
ACTION_EVENTS = {"action_execution", "monitor_outcome", "escalation"}


def _read_ledger() -> list[dict]:
    if not LEDGER_PATH.exists():
        return []
    entries = []
    for line in LEDGER_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return entries


def verify_hash_chain(entries: list[dict]) -> dict:
    """Verify the SHA-256 hash chain: each entry's 'prev_hash' must equal the
    SHA-256 of the previous entry's serialised canonical form."""
    if not entries:
        return {"status": "NO_ENTRIES", "valid": True, "entries_checked": 0}

    errors = []
    genesis_ok = True

    # First entry should have prev_hash = "0" * 64 or null
    first = entries[0]
    if first.get("prev_hash") not in (None, "0" * 64, "genesis"):
        genesis_ok = False
        errors.append(f"Entry 0: unexpected genesis prev_hash = {first.get('prev_hash')!r}")

    for i in range(1, len(entries)):
        prev_entry = entries[i - 1]
        curr_entry = entries[i]

        # Recompute hash of prev_entry (excluding its own 'hash' field to avoid circularity)
        prev_for_hash = {k: v for k, v in prev_entry.items() if k != "hash"}
        canonical = json.dumps(prev_for_hash, sort_keys=True, ensure_ascii=False)
        expected_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        actual_prev_hash = curr_entry.get("prev_hash", "")
        # Also verify the stored 'hash' field on the previous entry
        stored_hash = prev_entry.get("hash", "")

        if stored_hash and stored_hash != expected_hash:
            errors.append(
                f"Entry {i-1} hash mismatch: stored={stored_hash[:12]}... expected={expected_hash[:12]}..."
            )
        if actual_prev_hash and actual_prev_hash != expected_hash:
            errors.append(
                f"Entry {i} prev_hash mismatch: stored={actual_prev_hash[:12]}... expected={expected_hash[:12]}..."
            )

    chain_intact = (len(errors) == 0) and genesis_ok
    return {
        "status": "VALID" if chain_intact else "TAMPERED",
        "valid": chain_intact,
        "entries_checked": len(entries),
        "hash_errors": len(errors),
        "error_details": errors[:5],  # show first 5 only
    }


def verify_traceability(entries: list[dict]) -> dict:
    """Check that every action_execution entry has a prior AI event and
    detection event for the same incident_id."""

    # Group event types by incident_id
    by_incident: dict[str, set] = defaultdict(set)
    for entry in entries:
        iid = entry.get("incident_id") or "UNASSIGNED"
        etype = str(entry.get("event_type", "")).lower()
        by_incident[iid].add(etype)

    action_incidents = [
        iid for iid, etypes in by_incident.items()
        if any(e in ACTION_EVENTS for e in etypes)
    ]

    fully_traceable = 0
    partially_traceable = 0
    untraced = 0
    untraced_ids = []

    for iid in action_incidents:
        etypes = by_incident[iid]
        has_ai = bool(etypes.intersection(AI_EVENTS))
        has_policy = bool(etypes.intersection(POLICY_EVENTS))
        has_detection = bool(etypes.intersection(DETECTION_EVENTS))

        if has_detection and has_ai and has_policy:
            fully_traceable += 1
        elif has_ai or has_policy:
            partially_traceable += 1
        else:
            untraced += 1
            untraced_ids.append(iid)

    total_action_incidents = len(action_incidents)
    coverage = fully_traceable / total_action_incidents if total_action_incidents > 0 else 1.0

    return {
        "total_incidents_with_actions": total_action_incidents,
        "fully_traceable": fully_traceable,
        "partially_traceable": partially_traceable,
        "untraced": untraced,
        "auditability_coverage_pct": round(coverage * 100, 1),
        "untraced_incident_ids": untraced_ids[:10],
    }


def run() -> dict:
    print("\n" + "═" * 60)
    print("  METRIC 5 — Ledger Auditability & Hash Chain Integrity")
    print("═" * 60)

    entries = _read_ledger()
    if not entries:
        print(f"  ⚠️  Ledger is empty or missing at: {LEDGER_PATH}")
        print("       Run the full pipeline (python run_phase1.py or start the dashboard and trigger an incident)")
        return {"status": "NO_LEDGER_DATA"}

    print(f"  Loaded {len(entries)} ledger entries from {LEDGER_PATH.name}")

    # ── Hash Chain ─────────────────────────────────────────────────────────────
    chain_result = verify_hash_chain(entries)
    print(f"\n  Hash Chain Integrity")
    print(f"  {'─' * 50}")
    print(f"    Status              : {chain_result['status']}")
    print(f"    Entries checked     : {chain_result['entries_checked']}")
    print(f"    Hash errors         : {chain_result['hash_errors']}")
    if chain_result.get("error_details"):
        for err in chain_result["error_details"]:
            print(f"    ⚠️  {err}")

    # ── Traceability ──────────────────────────────────────────────────────────
    trace_result = verify_traceability(entries)
    print(f"\n  Action Traceability Audit")
    print(f"  {'─' * 50}")
    print(f"    Incidents with actions     : {trace_result['total_incidents_with_actions']}")
    print(f"    Fully traceable (D→AI→P→A) : {trace_result['fully_traceable']}")
    print(f"    Partially traceable        : {trace_result['partially_traceable']}")
    print(f"    Untraced (no AI context)   : {trace_result['untraced']}")
    print(f"    Auditability coverage      : {trace_result['auditability_coverage_pct']}%")
    if trace_result["untraced_incident_ids"]:
        print(f"    Untraced IDs               : {trace_result['untraced_incident_ids']}")

    # Unique event types summary
    event_types = {}
    for e in entries:
        et = str(e.get("event_type", "unknown"))
        event_types[et] = event_types.get(et, 0) + 1
    print(f"\n  Event Type Distribution")
    print(f"  {'─' * 50}")
    for et, count in sorted(event_types.items(), key=lambda x: -x[1]):
        print(f"    {et:<40}: {count}")

    return {**chain_result, **trace_result}


if __name__ == "__main__":
    run()
