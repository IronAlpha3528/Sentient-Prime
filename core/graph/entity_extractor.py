from typing import Any, Dict, List, Tuple
from core.evidence.event import EvidenceEvent
from core.graph.graph_schema import NodeType, EdgeType

class EntityExtractor:
    """Extracts graph nodes and relationships (edges) from incoming EvidenceEvents

    based on the specialist detector type.
    """

    @staticmethod
    def extract(event: EvidenceEvent) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Parses an EvidenceEvent and returns a list of node dictionaries

        and edge dictionaries to be inserted/merged into the graph.
        """
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []

        payload = event.payload
        detector = str(event.detector).upper()
        entity = str(event.entity)
        entity_type = str(payload.get("entity_type", "HOST")).upper()

        # Common attributes
        timestamp = payload.get("timestamp") or event.timestamp
        risk_score = float(payload.get("risk_score", 0.0))
        confidence = float(payload.get("confidence", 1.0))
        severity = str(payload.get("severity", "INFO")).upper()

        # 1. Base Node representation of the primary reporting entity
        primary_node_id = f"{entity_type}:{entity}"
        primary_node = {
            "node_id": primary_node_id,
            "entity_type": entity_type,
            "display_name": entity,
            "risk_score": risk_score,
            "confidence": confidence,
            "severity": severity,
            "timestamp": timestamp,
            "metadata": payload.get("metadata", {}).copy()
        }
        nodes.append(primary_node)

        # 2. Detector specific extractions
        if detector == "NETWORK":
            src_ip = str(payload.get("source_ip", "0.0.0.0"))
            dst_ip = str(payload.get("destination_ip", "0.0.0.0"))
            
            src_node_id = f"HOST:{src_ip}"
            dst_node_id = f"HOST:{dst_ip}"
            
            nodes.append({
                "node_id": src_node_id,
                "entity_type": "HOST",
                "display_name": src_ip,
                "risk_score": risk_score,
                "confidence": confidence,
                "severity": severity,
                "timestamp": timestamp,
                "metadata": {"role": "source"}
            })
            nodes.append({
                "node_id": dst_node_id,
                "entity_type": "HOST",
                "display_name": dst_ip,
                "risk_score": risk_score,
                "confidence": confidence,
                "severity": severity,
                "timestamp": timestamp,
                "metadata": {"role": "destination"}
            })

            # Edge between source and destination
            edges.append({
                "source": src_node_id,
                "target": dst_node_id,
                "type": EdgeType.CONNECTS_TO.value,
                "timestamp": timestamp,
                "confidence": confidence,
                "risk": risk_score,
                "metadata": {
                    "protocol": payload.get("protocol", "unknown"),
                    "attack_family": payload.get("attack_family", "unknown"),
                    "flow_duration": payload.get("flow_duration", 0.0),
                    "source_detector": "NETWORK"
                }
            })
            
            # Edge between source host and primary network flow entity
            edges.append({
                "source": src_node_id,
                "target": primary_node_id,
                "type": EdgeType.GENERATES.value,
                "timestamp": timestamp,
                "confidence": confidence,
                "risk": risk_score,
                "metadata": {"source_detector": "NETWORK"}
            })

        elif detector == "IDENTITY":
            user = str(payload.get("user", entity))
            user_node_id = f"USER:{user}"
            
            # Ensure USER node exists
            nodes.append({
                "node_id": user_node_id,
                "entity_type": "USER",
                "display_name": user,
                "risk_score": risk_score,
                "confidence": confidence,
                "severity": severity,
                "timestamp": timestamp,
                "metadata": {"auth_count": payload.get("auth_count", 0)}
            })

            # If the user authenticated to computers, connect them
            computer_fanout = payload.get("identity_features", {}).get("computer_fanout", [])
            # Also support general traversal computers if present in metadata
            targets = payload.get("metadata", {}).get("accessed_computers", [])
            if not isinstance(targets, list):
                targets = [targets] if targets else []
                
            for target in targets:
                target_node_id = f"HOST:{target}"
                nodes.append({
                    "node_id": target_node_id,
                    "entity_type": "HOST",
                    "display_name": target,
                    "risk_score": risk_score * 0.5, # Propagate lower risk
                    "confidence": confidence,
                    "severity": severity,
                    "timestamp": timestamp,
                    "metadata": {"role": "target_server"}
                })
                edges.append({
                    "source": user_node_id,
                    "target": target_node_id,
                    "type": EdgeType.AUTHENTICATES_TO.value,
                    "timestamp": timestamp,
                    "confidence": confidence,
                    "risk": risk_score,
                    "metadata": {"source_detector": "IDENTITY", "off_hours": payload.get("off_hours", False)}
                })
            
            # Connect primary user to the event identity node if different
            if user_node_id != primary_node_id:
                edges.append({
                    "source": user_node_id,
                    "target": primary_node_id,
                    "type": EdgeType.AUTHENTICATES_TO.value,
                    "timestamp": timestamp,
                    "confidence": confidence,
                    "risk": risk_score,
                    "metadata": {"source_detector": "IDENTITY"}
                })

        elif detector == "ENDPOINT":
            process = str(payload.get("process", "unknown"))
            process_node_id = f"PROCESS:{entity}:{process}"
            
            # Process node
            nodes.append({
                "node_id": process_node_id,
                "entity_type": "PROCESS",
                "display_name": process,
                "risk_score": risk_score,
                "confidence": confidence,
                "severity": severity,
                "timestamp": timestamp,
                "metadata": {"mitre_candidates": payload.get("mitre_candidates", [])}
            })

            # Relation: Host runs Process
            edges.append({
                "source": primary_node_id,
                "target": process_node_id,
                "type": EdgeType.RUNS_PROCESS.value,
                "timestamp": timestamp,
                "confidence": confidence,
                "risk": risk_score,
                "metadata": {"source_detector": "ENDPOINT", "sigma_hits": payload.get("sigma_hits", [])}
            })

        elif detector == "OT":
            # PLC entity node already created as primary node
            # Create nodes for top shifted variables (actuators/sensors)
            shifted_vars = payload.get("top_shifted_variables", [])
            for var in shifted_vars:
                # Deduce actuator vs sensor by name heuristic
                is_actuator = "V" in var or "VALVE" in var.upper() or "PUMP" in var.upper()
                var_type = NodeType.ACTUATOR.value if is_actuator else NodeType.SENSOR.value
                var_node_id = f"{var_type}:{var}"
                
                nodes.append({
                    "node_id": var_node_id,
                    "entity_type": var_type,
                    "display_name": var,
                    "risk_score": risk_score,
                    "confidence": confidence,
                    "severity": severity,
                    "timestamp": timestamp,
                    "metadata": {"anomaly_score": payload.get("anomaly_score", 0.0)}
                })

                edge_type = EdgeType.CONTROLS.value if is_actuator else EdgeType.MEASURES.value
                edges.append({
                    "source": primary_node_id,
                    "target": var_node_id,
                    "type": edge_type,
                    "timestamp": timestamp,
                    "confidence": confidence,
                    "risk": risk_score,
                    "metadata": {"source_detector": "OT", "attack_probability": payload.get("attack_probability", 0.0)}
                })

        return nodes, edges
