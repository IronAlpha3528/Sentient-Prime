import datetime
import json
import logging
import os
import pathlib
from typing import Any, Dict, List, Optional

from core.evidence.event import EvidenceEvent
from core.graph.entity_extractor import EntityExtractor
from core.graph.graph_store import GraphStore
from core.graph.graph_query import GraphQuery
from core.graph.graph_metrics import GraphMetrics
from core.graph.graph_export import GraphExport
from core.graph.graph_schema import NodeType, EdgeType

logger = logging.getLogger(__name__)

class GraphManager:
    """The central facade class for the Cyber Knowledge Graph system.

    Provides high-level APIs to update, query, export, and validate the graph.
    """

    def __init__(self, storage_dir: str = "processed/graph"):
        self.storage_dir = pathlib.Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        self.store = GraphStore()
        self.query_engine = GraphQuery(self.store)

        # Load existing graph if available
        self.build()

    def build(self) -> None:
        """Initializes the graph from saved JSON snapshot on startup."""
        json_path = self.storage_dir / "graph.json"
        if json_path.exists():
            try:
                self.store.load(str(json_path), format="json")
                logger.info(f"Loaded existing cyber graph from {json_path}")
            except Exception as e:
                logger.error(f"Failed to load graph from {json_path}: {e}")

    def update(self, event: EvidenceEvent) -> None:
        """Incrementally updates graph node and edge states based on an EvidenceEvent."""
        try:
            nodes, edges = EntityExtractor.extract(event)
            
            # Insert nodes
            for node in nodes:
                self.store.add_node(node["node_id"], node)

            # Insert edges
            for edge in edges:
                self.store.add_edge(edge["source"], edge["target"], edge)

            logger.info(f"Incrementally updated graph with event {event.event_id}. Added/Merged {len(nodes)} nodes, {len(edges)} edges.")
        except Exception as e:
            logger.error(f"Failed to incrementally update graph with event {event.event_id}: {e}")

    def query(self) -> GraphQuery:
        """Exposes the graph query engine for traversal and paths search."""
        return self.query_engine

    def export(self, prefix: Optional[str] = None) -> None:
        """Writes current graph structure, metrics, statistics, and validation reports to disk."""
        try:
            # 1. Structure JSON
            g_json = GraphExport.export_json(self.store._graph)
            json_file = self.storage_dir / "graph.json"
            with open(json_file, "w", encoding="utf-8") as f:
                f.write(g_json)

            # 2. Metrics JSON
            metrics = self.metrics()
            metrics_file = self.storage_dir / "graph_metrics.json"
            with open(metrics_file, "w", encoding="utf-8") as f:
                json.dump(metrics, f, indent=2)

            # 3. Summary statistics JSON
            summary = {
                "nodes_count": metrics["nodes_count"],
                "edges_count": metrics["edges_count"],
                "risk_distribution": metrics["risk_distribution"],
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
            }
            summary_file = self.storage_dir / "graph_summary.json"
            with open(summary_file, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2)

            # 4. Run validation and write report
            validation = self.validate()
            val_file = self.storage_dir / "graph_validation.json"
            with open(val_file, "w", encoding="utf-8") as f:
                json.dump(validation, f, indent=2)

            logger.info(f"Exported all cyber graph assets to {self.storage_dir}")
        except Exception as e:
            logger.error(f"Failed to export graph assets: {e}")

    def metrics(self) -> Dict[str, Any]:
        """Computes topological and security metrics over the graph."""
        with self.store.lock:
            return GraphMetrics.compute(self.store._graph)

    def validate(self) -> Dict[str, Any]:
        """Runs integrity and schema checks over the current graph nodes and edges."""
        errors = []
        warnings = []
        node_ids_set = set()

        with self.store.lock:
            # Check nodes
            for node_id, attrs in self.store._graph.nodes(data=True):
                node_ids_set.add(node_id)
                entity_type = attrs.get("entity_type")
                if not entity_type or not NodeType.has_value(entity_type):
                    errors.append(f"Node {node_id} has invalid entity_type '{entity_type}'")
                
                # Check timestamp
                if not attrs.get("first_seen") or not attrs.get("last_seen"):
                    warnings.append(f"Node {node_id} is missing temporal tracking timestamps")

            # Check edges
            for u, v, k, attrs in self.store._graph.edges(keys=True, data=True):
                # Check source and target nodes exist in graph (orphan check)
                if u not in node_ids_set:
                    errors.append(f"Edge ({u} -> {v}) references non-existent source node '{u}' (Orphan edge)")
                if v not in node_ids_set:
                    errors.append(f"Edge ({u} -> {v}) references non-existent target node '{v}' (Orphan edge)")

                # Check edge type
                e_type = attrs.get("type")
                if not e_type or not EdgeType.has_value(e_type):
                    errors.append(f"Edge ({u} -> {v}) has invalid relationship type '{e_type}'")

                # Check timestamp
                if not attrs.get("timestamp"):
                    warnings.append(f"Edge ({u} -> {v}) is missing timestamp attribute")

        valid = len(errors) == 0
        return {
            "valid": valid,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "metrics": {
                "nodes_checked": len(node_ids_set),
                "errors_count": len(errors),
                "warnings_count": len(warnings)
            },
            "errors": errors,
            "warnings": warnings
        }

    def health(self) -> str:
        """Returns the health status of the graph manager."""
        with self.store.lock:
            if self.store._graph is None:
                return "Uninitialized"
            # Simple validation integrity check
            val = self.validate()
            if not val["valid"]:
                return f"Degraded: {len(val['errors'])} validation errors present."
            return "Healthy"

    def shutdown(self) -> None:
        """Shuts down the graph manager, exporting latest states to disk."""
        logger.info("Shutting down Graph Manager...")
        self.export()
        self.store.clear()
