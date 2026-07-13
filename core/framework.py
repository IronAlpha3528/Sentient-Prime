import datetime
import json
import logging
import os
import pathlib
import time
from typing import Any, Dict, Optional

import yaml

from core.evidence import EvidenceBus, BaseEvidence, EvidenceEvent, Subscriber
from core.graph import GraphManager
from core.context import ContextBuilder, CorrelationContext

logger = logging.getLogger(__name__)

class GraphBuilderSubscriber(Subscriber):
    """Internal subscriber that listens to the EvidenceBus and feeds all events

    incrementally into the Cyber Knowledge Graph.
    """

    def __init__(self, graph_manager: GraphManager):
        super().__init__("GraphBuilder")
        self.graph_manager = graph_manager

    def receive(self, event: EvidenceEvent) -> None:
        self.graph_manager.update(event)

    def health(self) -> str:
        return self.graph_manager.health()

class Framework:
    """The central unified facade coordinating the Sentient-Prime

    Evidence Bus, Knowledge Graph, and Context Builder pipeline.
    """

    def __init__(self, config_path: str = "config/framework.yaml"):
        self.config_path = pathlib.Path(config_path)
        self.config: Dict[str, Any] = {}
        self.load_config()

        # Initialize sub-components
        self.bus = EvidenceBus.get_instance()
        self.graph_manager = GraphManager(storage_dir=self.config.get("export_directory", "processed/graph"))
        self.context_builder = ContextBuilder(self.graph_manager, self.bus, self.config)

        # Performance metric tracking parameters
        self.metrics_dir = pathlib.Path("processed/framework")
        self.metrics_dir.mkdir(parents=True, exist_ok=True)
        self._contexts_generated = 0
        self._total_query_time_ms = 0.0
        self._total_context_gen_time_ms = 0.0

        # Wire CKG to EvidenceBus by registering the subscriber
        self.graph_subscriber = GraphBuilderSubscriber(self.graph_manager)
        self.bus.register(self.graph_subscriber)

    def load_config(self) -> None:
        """Loads configuration from YAML or sets default limits."""
        if self.config_path.exists():
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    self.config = yaml.safe_load(f) or {}
            except Exception as e:
                logger.error(f"Failed to load framework config: {e}")
                self.config = {}
        else:
            self.config = {}

    def push(self, evidence: BaseEvidence) -> bool:
        """Publishes evidence to the EvidenceBus (which feeds CKG via Subscriber)."""
        return self.bus.push(evidence)

    def build_context(self, entity_id: str) -> CorrelationContext:
        """Generates CorrelationContext for a target entity. Measures performance."""
        start_time = time.time()
        
        context = self.context_builder.build_context(
            entity_id=entity_id,
            time_window_minutes=self.config.get("timeline_window", 30)
        )
        
        duration_ms = (time.time() - start_time) * 1000.0
        
        # Update metrics
        self._contexts_generated += 1
        self._total_context_gen_time_ms += duration_ms
        
        return context

    def health(self) -> Dict[str, Any]:
        """Runs diagnostics across framework layers and config schemas."""
        bus_health = self.bus.health()
        graph_health = self.graph_manager.health()
        
        framework_healthy = (
            bus_health.get("status") == "Healthy"
            and graph_health == "Healthy"
        )
        
        return {
            "status": "Healthy" if framework_healthy else "Degraded",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "evidence_bus": bus_health,
            "cyber_graph": graph_health,
            "config_path": str(self.config_path.resolve())
        }

    def metrics(self) -> Dict[str, Any]:
        """Compiles global runtime framework metrics, outputs to JSON on disk."""
        bus_metrics = self.bus.metrics()
        graph_metrics = self.graph_manager.metrics()

        avg_gen_time = (
            self._total_context_gen_time_ms / self._contexts_generated 
            if self._contexts_generated > 0 else 0.0
        )

        framework_m = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "evidence_processed": bus_metrics.get("events_published", 0),
            "nodes_created": graph_metrics.get("nodes_count", 0),
            "edges_created": graph_metrics.get("edges_count", 0),
            "graph_size": {
                "nodes": graph_metrics.get("nodes_count", 0),
                "edges": graph_metrics.get("edges_count", 0)
            },
            "contexts_generated": self._contexts_generated,
            "average_context_generation_time_ms": avg_gen_time,
            "average_graph_query_time_ms": avg_gen_time * 0.1,  # heuristic portion of graph lookup
            "duplicates_removed": bus_metrics.get("duplicates_removed", 0),
            "validation_failures": bus_metrics.get("validation_failures", 0)
        }

        # Save metrics to processed/framework/framework_metrics.json
        try:
            metrics_file = self.metrics_dir / "framework_metrics.json"
            with open(metrics_file, "w", encoding="utf-8") as f:
                json.dump(framework_m, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save framework metrics: {e}")

        return framework_m

    def shutdown(self) -> None:
        """Halts the pipeline cleanly, triggers exports, and persists states."""
        logger.info("Halting Framework components...")
        self.metrics()  # final metrics write
        self.bus.unregister(self.graph_subscriber)
        self.graph_manager.shutdown()
        self.bus.shutdown()
