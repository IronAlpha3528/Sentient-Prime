"""SOAR action wrapper for the active decoy deployer."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class DeployDecoyAction:
    """SOAR Action to deploy graph-guided honeytokens via DecoyDeployer."""

    def execute(self, strategy: dict[str, Any], target_host: str = "unknown-host") -> dict[str, Any]:
        """Deploy a honeytoken based on the AI Deception Agent strategy.

        Delegates to DecoyDeployer which creates a hidden file, registers it
        in the JSONL registry, and logs to the tamper-evident audit ledger.
        """
        from sentinel_prime.simulation.honeypots.decoy_deployer import DecoyDeployer

        decoy_type = strategy.get("decoy_type", "smb_share")
        placement_node = strategy.get("placement_node", target_host)
        incident_id = strategy.get("incident_id", "UNKNOWN")
        observation_window = int(strategy.get("observation_window_minutes", 30))

        try:
            result = DecoyDeployer().deploy(
                decoy_type=decoy_type,
                placement_node=placement_node,
                incident_id=incident_id,
                observation_window_minutes=observation_window,
            )
            logger.info("Deployed decoy %s on node %s", result["decoy_id"], placement_node)
            return {
                "action": "deploy_decoy",
                "status": "SUCCESS",
                "decoy_id": result["decoy_id"],
                "decoy_type": result["decoy_type"],
                "placement_node": result["placement_node"],
                "target_path": result["target_path"],
                "observation_window_minutes": result["observation_window_minutes"],
            }
        except Exception as exc:
            logger.error("Failed to deploy decoy: %s", exc)
            return {"action": "deploy_decoy", "status": "ERROR", "reason": str(exc)}
