"""Append-only, tamper-evident audit ledger for pipeline decisions."""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_LEDGER_PATH = Path(__file__).resolve().parents[5] / "data" / "audit_ledger.jsonl"


class AuditLedger:
    """Stores canonical JSON entries linked by SHA-256 hashes."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path is not None else DEFAULT_LEDGER_PATH
        self.lock = threading.RLock()

    def append_entry(
        self,
        event_type: str,
        data: dict[str, Any],
        *,
        incident_id: str | None = None,
    ) -> dict[str, Any]:
        with self.lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            previous_hash = self._last_hash()
            entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": event_type,
                "incident_id": incident_id,
                "data": data,
                "prev_hash": previous_hash,
            }
            entry["hash"] = self._hash(entry)
            with self.path.open("a", encoding="utf-8") as ledger_file:
                ledger_file.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")
            return entry

    def verify_chain(self) -> bool:
        with self.lock:
            previous_hash = ""
            if not self.path.exists():
                return True
            with self.path.open(encoding="utf-8") as ledger_file:
                for line in ledger_file:
                    if not line.strip():
                        continue
                    entry = json.loads(line)
                    entry_hash = entry.pop("hash", None)
                    if entry.get("prev_hash") != previous_hash or entry_hash != self._hash(entry):
                        return False
                    previous_hash = entry_hash
            return True

    def _last_hash(self) -> str:
        with self.lock:
            if not self.path.exists():
                return ""
            with self.path.open(encoding="utf-8") as ledger_file:
                entries = [line for line in ledger_file if line.strip()]
            if not entries:
                return ""
            return json.loads(entries[-1])["hash"]

    @staticmethod
    def _hash(entry: dict[str, Any]) -> str:
        payload = json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
