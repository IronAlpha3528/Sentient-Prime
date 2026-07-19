"""Active honeypot / honeytoken decoy deployer for Sentinel-Prime.

Creates hidden bait files on the local filesystem and tracks them in a
append-only JSONL registry.  When the Action Agent proposes a
``deploy_decoy`` containment action, the SOAR dispatcher calls this module.

The decoy is a hidden text file containing a realistic-looking credential
or document stub:
  - Linux: dot-prefix path  (e.g.  .sentinel_smb_creds.txt)
  - Windows: normal file + ``attrib +H`` to set the hidden attribute

A separate ``webhook_receiver.py`` listens for Canarytoken hits and calls
``mark_touched`` when a decoy is accessed.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import subprocess
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

logger = logging.getLogger(__name__)

# Registry lives alongside the audit ledger in data/
_PROJECT_ROOT = Path(__file__).resolve().parents[5]
_DECOY_DIR = _PROJECT_ROOT / "data" / "decoys"
_REGISTRY_PATH = _DECOY_DIR / "registry.jsonl"

_DECOY_TEMPLATES: dict[str, str] = {
    "smb_share": (
        "[SMB Credentials — INTERNAL USE ONLY]\n"
        "Server: \\\\CORP-FILE-01\\Sensitive\n"
        "Username: svc_backup\n"
        "Password: P@ssw0rd!2024\n"
        "Domain: CORP\n"
    ),
    "credential": (
        "# Service Account Credentials\n"
        "host: db-prod-01.corp.local\n"
        "user: db_admin\n"
        "password: Adm1n!Secr3t\n"
        "port: 5432\n"
    ),
    "api_key": (
        "CORP_API_KEY=sk-prod-a7f3c9d2e1b4f8a6c3d5e7f9a2b4c6d8\n"
        "CORP_API_SECRET=secret-prod-1f2e3d4c5b6a7f8e9d0c1b2a3f4e5d6c\n"
        "ENDPOINT=https://api.corp.internal/v2\n"
    ),
    "document": (
        "CONFIDENTIAL — Q3 Acquisition Target List\n\n"
        "Company A: $120M valuation — do not disclose\n"
        "Company B: $85M valuation — due diligence pending\n"
    ),
    "ot_config": (
        "[PLC Config — RESTRICTED]\n"
        "SCADA_HOST=192.168.200.10\n"
        "MODBUS_PORT=502\n"
        "ADMIN_PASSWORD=plcadmin2024!\n"
    ),
}


@dataclass
class DeployedDecoy:
    decoy_id: str
    decoy_type: str            # e.g. "smb_share", "credential"
    target_path: str           # absolute path to the hidden file
    placement_node: str        # logical node name (e.g. "db_server")
    incident_id: str
    deployed_at: str
    observation_window_minutes: int
    status: str = "active"     # "active" | "touched" | "expired"
    touched_at: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class DecoyDeployer:
    """Create, track, and expire active honeypot decoys."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        _DECOY_DIR.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def deploy(
        self,
        decoy_type: str = "smb_share",
        placement_node: str = "db_server",
        incident_id: str = "UNKNOWN",
        observation_window_minutes: int = 30,
    ) -> dict[str, Any]:
        """Deploy a honeytoken file and register it.

        Returns the DeployedDecoy as a dict.
        """
        with self._lock:
            decoy_id = f"DECOY-{uuid4().hex[:8].upper()}"
            template_key = decoy_type.lower().replace(" ", "_").split("_")[0]
            content = _DECOY_TEMPLATES.get(template_key) or _DECOY_TEMPLATES["smb_share"]

            filename = self._choose_filename(decoy_type, placement_node)
            target_path = _DECOY_DIR / filename
            target_path.write_text(content, encoding="utf-8")
            self._hide_file(target_path)

            now = datetime.now(timezone.utc).isoformat()
            decoy = DeployedDecoy(
                decoy_id=decoy_id,
                decoy_type=decoy_type,
                target_path=str(target_path),
                placement_node=placement_node,
                incident_id=incident_id,
                deployed_at=now,
                observation_window_minutes=observation_window_minutes,
            )

            self._append_registry(decoy.as_dict())
            self._ledger_entry("decoy_deployed", decoy.as_dict(), incident_id)
            logger.info("Deployed decoy %s → %s", decoy_id, target_path)
            return decoy.as_dict()

    def list_active(self) -> list[dict[str, Any]]:
        """Return all decoys with status == 'active'."""
        return [d for d in self._read_registry() if d.get("status") == "active"]

    def mark_touched(self, decoy_id: str) -> dict[str, Any] | None:
        """Mark a decoy as touched (triggered by honeypot webhook)."""
        with self._lock:
            records = self._read_registry()
            updated = None
            for rec in records:
                if rec["decoy_id"] == decoy_id:
                    rec["status"] = "touched"
                    rec["touched_at"] = datetime.now(timezone.utc).isoformat()
                    updated = rec
                    break
            if updated:
                self._write_registry(records)
                self._ledger_entry("decoy_touched", updated, updated.get("incident_id", "UNKNOWN"))
                logger.info("Decoy %s marked as TOUCHED", decoy_id)
            return updated

    def expire(self, decoy_id: str) -> dict[str, Any] | None:
        """Expire and delete a decoy file after the observation window ends."""
        with self._lock:
            records = self._read_registry()
            updated = None
            for rec in records:
                if rec["decoy_id"] == decoy_id and rec["status"] == "active":
                    rec["status"] = "expired"
                    updated = rec
                    path = Path(rec.get("target_path", ""))
                    if path.exists():
                        try:
                            path.unlink()
                        except OSError:
                            logger.warning("Could not delete decoy file %s", path)
                    break
            if updated:
                self._write_registry(records)
                self._ledger_entry("decoy_expired", updated, updated.get("incident_id", "UNKNOWN"))
                logger.info("Decoy %s expired and cleaned up", decoy_id)
            return updated

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _choose_filename(self, decoy_type: str, placement_node: str) -> str:
        """Return a platform-appropriate filename for the decoy."""
        slug = placement_node.lower().replace(" ", "_")
        suffix_map = {
            "smb_share": f".smb_creds_{slug}.txt",
            "credential": f".db_credentials_{slug}.env",
            "api_key": f".api_keys_{slug}.env",
            "document": f".acquisition_targets_{slug}.txt",
            "ot_config": f".plc_config_{slug}.ini",
        }
        key = decoy_type.lower().replace(" ", "_").split("_")[0]
        name = suffix_map.get(key, f".decoy_{slug}.txt")
        # On Windows the dot-prefix alone is not hidden; we use attrib separately
        return name

    def _hide_file(self, path: Path) -> None:
        """Set the hidden attribute on Windows; dot-prefix suffices on POSIX."""
        if platform.system() == "Windows":
            try:
                subprocess.run(["attrib", "+H", str(path)], check=True, capture_output=True)
            except (subprocess.SubprocessError, FileNotFoundError):
                logger.warning("Could not set hidden attribute on %s (attrib not available)", path)

    def _append_registry(self, record: dict[str, Any]) -> None:
        with _REGISTRY_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=str) + "\n")

    def _read_registry(self) -> list[dict[str, Any]]:
        if not _REGISTRY_PATH.exists():
            return []
        records: list[dict[str, Any]] = []
        with _REGISTRY_PATH.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return records

    def _write_registry(self, records: list[dict[str, Any]]) -> None:
        """Rewrite the entire registry (used for status updates)."""
        with _REGISTRY_PATH.open("w", encoding="utf-8") as f:
            for rec in records:
                f.write(json.dumps(rec, default=str) + "\n")

    def _ledger_entry(self, event_type: str, data: dict[str, Any], incident_id: str) -> None:
        try:
            from sentinel_prime.core.telemetry.ledger import AuditLedger
            AuditLedger().append_entry(event_type, data, incident_id=incident_id)
        except Exception:
            pass  # Never crash the deployer due to ledger errors
