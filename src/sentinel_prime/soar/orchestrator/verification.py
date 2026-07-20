import datetime
import logging
import os
import pathlib
import threading
import time
from enum import Enum
from typing import Any, Dict, List, Optional

import yaml

from sentinel_prime.core.evidence import EvidenceBus, BaseEvidence, EvidenceEvent, Subscriber
from sentinel_prime.core.telemetry.ledger import AuditLedger
from sentinel_prime.soar.orchestrator.actions import execute_action

logger = logging.getLogger(__name__)

class IncidentState(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONTAINMENT_IN_PROGRESS = "CONTAINMENT_IN_PROGRESS"
    VERIFICATION_PENDING = "VERIFICATION_PENDING"
    PARTIALLY_CONTAINED = "PARTIALLY_CONTAINED"
    CONTAINED = "CONTAINED"
    ESCALATED = "ESCALATED"
    RESOLVED = "RESOLVED"
    FAILED = "FAILED"

BACKUP_PLAYBOOKS = {
    "block_ip": "isolate_host",
    "isolate_host": "notify_analyst",
    "revoke_access": "notify_analyst",
    "deploy_decoy": "notify_analyst"
}

class VerificationEngine:
    """Asynchronously verifies SOAR containment actions using Cyber Graph telemetry."""

    def __init__(self, ledger: Optional[AuditLedger] = None, config_path: str = "config/sentinel_config.yaml") -> None:
        self.ledger = ledger or AuditLedger()
        self.config_path = pathlib.Path(config_path)
        self.config: Dict[str, Any] = {}
        self.load_config()

        # Load parameters with defaults
        verification_cfg = self.config.get("verification", {})
        self.delay_seconds = float(verification_cfg.get("delay_seconds", 2.0))
        self.retry_count = int(verification_cfg.get("retry_count", 3))
        self.retry_interval_seconds = float(verification_cfg.get("retry_interval_seconds", 1.0))
        self.max_duration_seconds = float(verification_cfg.get("max_duration_seconds", 10.0))
        self.escalation_threshold = float(verification_cfg.get("escalation_threshold", 0.8))

        # In-memory tracking state machine
        self.states: Dict[str, IncidentState] = {}
        self.history: Dict[str, List[Dict[str, Any]]] = {}
        self.lock = threading.Lock()

    def load_config(self) -> None:
        """Loads configuration from YAML or uses defaults."""
        if self.config_path.exists():
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    self.config = yaml.safe_load(f) or {}
            except Exception as e:
                logger.error("Failed to load sentinel config: %s", e)
                self.config = {}
        else:
            self.config = {}

    def get_incident_state(self, incident_id: str) -> IncidentState:
        """Retrieves the current state of an incident."""
        with self.lock:
            return self.states.get(incident_id, IncidentState.OPEN)

    def transition_state(self, incident_id: str, new_state: IncidentState, reason: str = "") -> None:
        """Transitions the incident to a new state and logs it to the Audit Ledger."""
        with self.lock:
            prev_state = self.states.get(incident_id, IncidentState.OPEN)
            self.states[incident_id] = new_state
            if incident_id not in self.history:
                self.history[incident_id] = []
            
            entry = {
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "previous_state": prev_state.value,
                "new_state": new_state.value,
                "reason": reason
            }
            self.history[incident_id].append(entry)
            
            logger.info("Incident %s transitioned from %s to %s | %s", incident_id, prev_state.value, new_state.value, reason)

            # Record to audit ledger
            self.ledger.append_entry(
                event_type="incident_state_transition",
                data=entry,
                incident_id=incident_id
            )

    def verify_incident(self, incident: Dict[str, Any], action_results: List[Dict[str, Any]]) -> None:
        """Schedules asynchronous verification in a background thread."""
        incident_id = incident.get("incident_id", f"INC-{incident.get('asset', 'UNKNOWN')}")
        
        # Spawn daemon thread to verify
        thread = threading.Thread(
            target=self._verify_loop,
            args=(incident_id, incident, action_results),
            name=f"Verify-{incident_id}",
            daemon=True
        )
        thread.start()

    def _verify_loop(self, incident_id: str, incident: Dict[str, Any], action_results: List[Dict[str, Any]]) -> None:
        """Main async verification sequence."""
        asset = incident.get("asset", "UNKNOWN")
        entity_type = incident.get("entity_type", "HOST")
        start_time = datetime.datetime.now(datetime.timezone.utc)

        self.transition_state(incident_id, IncidentState.CONTAINMENT_IN_PROGRESS, "Executing containment playbooks")
        self.transition_state(incident_id, IncidentState.VERIFICATION_PENDING, f"Containment executed. Beginning verification loop. Delay={self.delay_seconds}s")

        # 1. Check if any containment action initially failed execution
        failed_actions = [a for a in action_results if a.get("status") != "SUCCESS"]
        if failed_actions:
            self.transition_state(incident_id, IncidentState.FAILED, f"Containment execution failed for actions: {failed_actions}")
            self._escalate(incident_id, incident, action_results, "Containment action failed to execute")
            return

        # 2. Start monitoring query checks
        time.sleep(self.delay_seconds)
        
        successful_containment = False
        state = IncidentState.VERIFICATION_PENDING
        reason = ""
        evidence_collected = []

        for attempt in range(1, self.retry_count + 1):
            if attempt > 1:
                time.sleep(self.retry_interval_seconds)

            # Check if duration exceeded
            elapsed = (datetime.datetime.now(datetime.timezone.utc) - start_time).total_seconds()
            if elapsed > self.max_duration_seconds:
                reason = f"Verification timed out after {elapsed:.2f}s"
                state = IncidentState.FAILED
                break

            # Query fresh telemetry from CKG
            bus = EvidenceBus.get_instance()
            graph_manager = None
            for sub in bus.stream_manager.subscribers:
                if hasattr(sub, "graph_manager"):
                    graph_manager = sub.graph_manager
                    break

            if graph_manager is None:
                # Monitoring is unavailable
                reason = "Monitoring system unavailable (GraphManager subscriber missing)"
                state = IncidentState.FAILED
                logger.error("Closed-loop verification failed: %s", reason)
                break

            # Search CKG for any new events/edges associated with target asset after start_time.
            # Build candidate node IDs using the known TYPE:name prefix convention,
            # then use edges(nbunch=...) which is O(degree) instead of O(E).
            new_events = []
            with graph_manager.store.lock:
                g = graph_manager.store._graph
                node_prefixes = ["HOST", "USER", "PROCESS", "IP", "PLC"]
                candidates = [f"{p}:{asset}" for p in node_prefixes] + [asset]
                # Only keep nodes that actually exist in the graph
                existing = [n for n in candidates if g.has_node(n)]
                if not existing:
                    # Fallback: scan all nodes for suffix match (graph is small in this branch)
                    existing = [n for n in g.nodes() if n.split(":")[-1] == asset]
                incident_edges = list(g.in_edges(nbunch=existing, keys=True, data=True)) + list(g.out_edges(nbunch=existing, keys=True, data=True))
                for u, v, k, attrs in incident_edges:
                    ts_str = attrs.get("timestamp") or attrs.get("last_seen")
                    if ts_str:
                        try:
                            ts = datetime.datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                            if ts >= start_time:
                                new_events.append({
                                    "source": u,
                                    "target": v,
                                    "detector": attrs.get("source_detector"),
                                    "risk_score": float(attrs.get("risk", 0.0)),
                                    "timestamp": ts_str
                                })
                        except Exception:
                            pass

            evidence_collected = new_events
            if not new_events:
                # No new events! Attack successfully stopped!
                successful_containment = True
                state = IncidentState.CONTAINED
                reason = "Telemetry resolved. No new evidence events detected for asset."
                break
            else:
                # New events detected. Evaluate risk severity.
                max_new_risk = max(e["risk_score"] for e in new_events)
                logger.warning("Attempt %d/%d: Found %d fresh events for asset %s. Max risk: %.2f", 
                               attempt, self.retry_count, len(new_events), asset, max_new_risk)

                if max_new_risk >= self.escalation_threshold:
                    state = IncidentState.FAILED
                    reason = f"Malicious activity persists with high risk: {max_new_risk:.2f}"
                    # High risk persistent activity -> fail fast
                    break
                else:
                    state = IncidentState.PARTIALLY_CONTAINED
                    reason = f"Activity continuing with moderate/low risk: {max_new_risk:.2f}"

        # 3. Finalize states and notify
        if successful_containment:
            self.transition_state(incident_id, IncidentState.CONTAINED, reason)
            self.transition_state(incident_id, IncidentState.RESOLVED, "Closed-loop verification succeeded. Threat resolved.")
        elif state == IncidentState.PARTIALLY_CONTAINED:
            self.transition_state(incident_id, IncidentState.PARTIALLY_CONTAINED, reason)
            # Partially contained: lower risk in system and keep monitoring
            self._lower_risk(incident_id, incident, evidence_collected)
        else:
            self.transition_state(incident_id, IncidentState.FAILED, reason)
            self.transition_state(incident_id, IncidentState.ESCALATED, f"Escalating incident due to: {reason}")
            self._escalate(incident_id, incident, action_results, reason)

        # 4. Feedback Loop: Push verification event to Evidence Bus
        try:
            # Map action to supported detector (NETWORK, IDENTITY, ENDPOINT, OT)
            det_mapped = "ENDPOINT"
            if action_results:
                act = str(action_results[0].get("action", "")).lower()
                if "ip" in act:
                    det_mapped = "NETWORK"
                elif "access" in act or "credential" in act:
                    det_mapped = "IDENTITY"
                elif "ot" in act or "plc" in act:
                    det_mapped = "OT"

            ver_ev = BaseEvidence(
                detector=det_mapped,
                entity=asset,
                entity_type=entity_type,
                timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                window_start=start_time.isoformat(),
                window_end=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                confidence=1.0,
                risk_score=0.0 if successful_containment else (0.4 if state == IncidentState.PARTIALLY_CONTAINED else 1.0),
                severity="INFO" if successful_containment else ("HIGH" if state == IncidentState.PARTIALLY_CONTAINED else "CRITICAL"),
                top_reasons=[f"Closed-loop verification: {state.value}. Reason: {reason}"],
                metadata={
                    "incident_id": incident_id,
                    "evidence_collected_count": len(evidence_collected),
                    "successful": successful_containment,
                    "verification_detector": "VERIFICATION"
                }
            )
            bus.push(ver_ev)
        except Exception as e:
            logger.exception("Failed to push verification feedback evidence: %s", e)

        # 5. Audit Log complete cycle
        self.ledger.append_entry(
            event_type="incident_verification_cycle",
            data={
                "verification_time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "evidence_collected": evidence_collected,
                "decision": "RESOLVE" if successful_containment else ("MONITOR" if state == IncidentState.PARTIALLY_CONTAINED else "ESCALATE"),
                "final_state": self.states[incident_id].value,
                "soar_actions": action_results,
                "reason": reason
            },
            incident_id=incident_id
        )

    def _lower_risk(self, incident_id: str, incident: Dict[str, Any], evidence_collected: List[Dict[str, Any]]) -> None:
        """Lowers risk parameters in response to partial containment."""
        logger.info("Lowering risk parameters for incident %s", incident_id)
        # Typically we adjust the entity baseline or notify risk metrics

    def _escalate(self, incident_id: str, incident: Dict[str, Any], action_results: List[Dict[str, Any]], reason: str) -> None:
        """Triggers escalation: executes next SOAR playbook or alerts analyst."""
        logger.warning("Escalating containment failure for incident %s", incident_id)
        
        # Execute the next playbook sequentially
        for action_res in action_results:
            action = action_res.get("action")
            next_action = BACKUP_PLAYBOOKS.get(action)
            if next_action:
                if next_action == "notify_analyst":
                    logger.warning("ALERTER: Containment failed. Notifying security analyst for incident %s.", incident_id)
                else:
                    logger.info("Triggering backup playbook action '%s' for incident %s", next_action, incident_id)
                    backup_res = execute_action(next_action, incident)
                    self.ledger.append_entry(
                        event_type="action_execution",
                        data={
                            "action": next_action,
                            "status": str(backup_res.get("status", "SUCCESS")).upper(),
                            "is_backup": True,
                            "reason": f"Escalation from failed {action}"
                        },
                        incident_id=incident_id
                    )
