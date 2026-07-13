import json
import logging
import os
import pickle
import threading
from typing import Any, Dict, List, Optional, Tuple, Union

import networkx as nx

from core.graph.node_builder import NodeBuilder
from core.graph.edge_builder import EdgeBuilder

logger = logging.getLogger(__name__)

class GraphStore:
    """A thread-safe wrapper around a NetworkX MultiDiGraph.

    Never exposes NetworkX objects directly. Maintains custom lookup indexes.
    """

    def __init__(self):
        self._graph = nx.MultiDiGraph()
        self.lock = threading.RLock()

        # Custom lookup indexes
        self._detector_index: Dict[str, List[Tuple[str, str, int]]] = {}  # detector -> List of (src, dst, key)
        self._timestamp_index: List[Tuple[str, str, Any]] = []           # List of (timestamp, 'node'|'edge', id)
        self._risk_index: List[Tuple[float, str]] = []                   # List of (risk_score, node_id)

    def add_node(self, node_id: str, node_data: Dict[str, Any]) -> None:
        """Adds a new node or updates/merges attributes of an existing node."""
        with self.lock:
            if self._graph.has_node(node_id):
                existing_attrs = self._graph.nodes[node_id]
                updated_attrs = NodeBuilder.merge(existing_attrs, node_data)
                # Re-assign to trigger index update
                self._update_node_indices(node_id, updated_attrs)
            else:
                new_attrs = NodeBuilder.build(node_data)
                self._graph.add_node(node_id, **new_attrs)
                self._update_node_indices(node_id, new_attrs)

    def add_edge(self, source: str, target: str, edge_data: Dict[str, Any]) -> None:
        """Adds an edge between source and target, or updates/merges if exists."""
        with self.lock:
            # Ensure source and target nodes exist in the graph (prevent orphan edges)
            if not self._graph.has_node(source):
                self._graph.add_node(source, **NodeBuilder.build({
                    "node_id": source,
                    "entity_type": source.split(":")[0] if ":" in source else "HOST",
                    "display_name": source.split(":")[1] if ":" in source else source,
                    "timestamp": edge_data.get("timestamp")
                }))
            if not self._graph.has_node(target):
                self._graph.add_node(target, **NodeBuilder.build({
                    "node_id": target,
                    "entity_type": target.split(":")[0] if ":" in target else "HOST",
                    "display_name": target.split(":")[1] if ":" in target else target,
                    "timestamp": edge_data.get("timestamp")
                }))

            # Check if matching relationship type edge already exists
            rel_type = edge_data.get("type", "CONNECTS_TO")
            matching_key = None
            
            # Retrieve all multi-edges between source and target
            if self._graph.has_edge(source, target):
                edge_dict = self._graph.get_edge_data(source, target)
                for key, attrs in edge_dict.items():
                    if attrs.get("type") == rel_type:
                        matching_key = key
                        break

            if matching_key is not None:
                existing_attrs = self._graph[source][target][matching_key]
                updated_attrs = EdgeBuilder.merge(existing_attrs, edge_data)
                self._update_edge_indices(source, target, matching_key, updated_attrs)
            else:
                new_attrs = EdgeBuilder.build(edge_data)
                key = self._graph.add_edge(source, target, **new_attrs)
                self._update_edge_indices(source, target, key, new_attrs)

    def _update_node_indices(self, node_id: str, attrs: Dict[str, Any]) -> None:
        """Helper to maintain node indexes."""
        # 1. Update risk index
        risk = attrs.get("risk_score", 0.0)
        self._risk_index = [item for item in self._risk_index if item[1] != node_id]
        self._risk_index.append((risk, node_id))
        self._risk_index.sort(key=lambda x: x[0], reverse=True)

        # 2. Update timestamp index
        ts = attrs.get("last_seen") or attrs.get("timestamp")
        if ts:
            self._timestamp_index.append((ts, "node", node_id))
            self._timestamp_index.sort(key=lambda x: x[0])

    def _update_edge_indices(self, source: str, target: str, key: int, attrs: Dict[str, Any]) -> None:
        """Helper to maintain edge indexes."""
        detector = str(attrs.get("source_detector", "unknown")).upper()
        edge_ref = (source, target, key)

        # 1. Update detector index
        if detector not in self._detector_index:
            self._detector_index[detector] = []
        if edge_ref not in self._detector_index[detector]:
            self._detector_index[detector].append(edge_ref)

        # 2. Update timestamp index
        ts = attrs.get("last_seen") or attrs.get("timestamp")
        if ts:
            self._timestamp_index.append((ts, "edge", edge_ref))
            self._timestamp_index.sort(key=lambda x: x[0])

    def get_node(self, node_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves attributes of a single node."""
        with self.lock:
            if self._graph.has_node(node_id):
                return dict(self._graph.nodes[node_id])
            return None

    def get_edge(self, source: str, target: str, relationship_type: str) -> Optional[Dict[str, Any]]:
        """Retrieves attributes of a matching edge."""
        with self.lock:
            if self._graph.has_edge(source, target):
                edges = self._graph.get_edge_data(source, target)
                for key, attrs in edges.items():
                    if attrs.get("type") == relationship_type:
                        return dict(attrs)
            return None

    def remove_node(self, node_id: str) -> bool:
        """Removes a node and its indexes from the graph."""
        with self.lock:
            if not self._graph.has_node(node_id):
                return False
            self._graph.remove_node(node_id)
            # Cleanup indexes
            self._risk_index = [item for item in self._risk_index if item[1] != node_id]
            self._timestamp_index = [item for item in self._timestamp_index if item[1] != "node" or item[2] != node_id]
            
            # Clean detector edge links referencing this node
            for det, edges in list(self._detector_index.items()):
                self._detector_index[det] = [e for e in edges if e[0] != node_id and e[1] != node_id]
            return True

    def remove_edge(self, source: str, target: str, relationship_type: str) -> bool:
        """Removes a matching edge from the graph."""
        with self.lock:
            if not self._graph.has_edge(source, target):
                return False
            edges = self._graph.get_edge_data(source, target)
            target_key = None
            for key, attrs in edges.items():
                if attrs.get("type") == relationship_type:
                    target_key = key
                    break
            if target_key is not None:
                self._graph.remove_edge(source, target, key=target_key)
                
                # Cleanup indexes
                edge_ref = (source, target, target_key)
                self._timestamp_index = [item for item in self._timestamp_index if item[1] != "edge" or item[2] != edge_ref]
                for det in list(self._detector_index.keys()):
                    self._detector_index[det] = [e for e in self._detector_index[det] if e != edge_ref]
                return True
            return False

    def clear(self) -> None:
        """Resets the store."""
        with self.lock:
            self._graph.clear()
            self._detector_index.clear()
            self._timestamp_index.clear()
            self._risk_index.clear()

    def save(self, path: str, format: str = "json") -> None:
        """Saves graph snapshot to a file."""
        from networkx.readwrite import json_graph
        with self.lock:
            if format.lower() == "json":
                data = json_graph.node_link_data(self._graph)
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, default=str)
            elif format.lower() == "pickle":
                with open(path, "wb") as f:
                    pickle.dump(self._graph, f)
            else:
                raise ValueError(f"Unsupported save format: {format}")

    def load(self, path: str, format: str = "json") -> None:
        """Loads graph snapshot from a file."""
        from networkx.readwrite import json_graph
        with self.lock:
            if not os.path.exists(path):
                logger.warning(f"Load path {path} not found. Skipping load.")
                return

            if format.lower() == "json":
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._graph = json_graph.node_link_graph(data)
            elif format.lower() == "pickle":
                with open(path, "rb") as f:
                    self._graph = pickle.load(f)
            else:
                raise ValueError(f"Unsupported load format: {format}")

            # Rebuild indexes
            self._rebuild_indexes()

    def _rebuild_indexes(self) -> None:
        """Re-scans nodes and edges to build lookup lists."""
        self._detector_index.clear()
        self._timestamp_index.clear()
        self._risk_index.clear()

        # Re-index nodes
        for node_id, attrs in self._graph.nodes(data=True):
            risk = attrs.get("risk_score", 0.0)
            self._risk_index.append((risk, node_id))
            ts = attrs.get("last_seen") or attrs.get("timestamp")
            if ts:
                self._timestamp_index.append((ts, "node", node_id))

        # Re-index edges
        for u, v, key, attrs in self._graph.edges(keys=True, data=True):
            detector = str(attrs.get("source_detector", "unknown")).upper()
            edge_ref = (u, v, key)
            if detector not in self._detector_index:
                self._detector_index[detector] = []
            self._detector_index[detector].append(edge_ref)
            ts = attrs.get("last_seen") or attrs.get("timestamp")
            if ts:
                self._timestamp_index.append((ts, "edge", edge_ref))

        # Sort sorted lists
        self._risk_index.sort(key=lambda x: x[0], reverse=True)
        self._timestamp_index.sort(key=lambda x: x[0])
