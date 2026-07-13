import uuid
import datetime
import logging
from typing import Any, Dict, List, Optional
import networkx as nx

from sentinel_prime.core.context.context_schema import CorrelationContext
from sentinel_prime.core.context.timeline_builder import TimelineBuilder
from sentinel_prime.core.context.summary_builder import SummaryBuilder
from sentinel_prime.core.graph.graph_manager import GraphManager
from sentinel_prime.core.evidence.evidence_bus import EvidenceBus

logger = logging.getLogger(__name__)

class ContextBuilder:
    """Aggregates information from the Cyber Knowledge Graph and the Evidence Bus

    to assemble local subgraphs, timelines, and summaries into a CorrelationContext.
    """

    def __init__(self, graph_manager: GraphManager, bus: Optional[EvidenceBus] = None, config: Optional[Dict[str, Any]] = None):
        self.graph_manager = graph_manager
        self.bus = bus or EvidenceBus.get_instance()
        self.config = config or {}
        
        self.radius = self.config.get("graph_radius", 2)
        self.max_nodes = self.config.get("max_nodes", 50)
        self.max_edges = self.config.get("max_edges", 100)

    def build_context(self, entity_id: str, time_window_minutes: int = 30) -> CorrelationContext:
        """Constructs a compact CorrelationContext for a target entity ID."""
        store = self.graph_manager.store
        graph = store._graph

        related_nodes = []
        related_edges = []
        graph_paths = []
        supporting_evidence = []

        with store.lock:
            # Match node identifier or fall back to display name matching
            matched_node = None
            if graph.has_node(entity_id):
                matched_node = entity_id
            else:
                for n, attrs in graph.nodes(data=True):
                    if attrs.get("display_name") == entity_id:
                        matched_node = n
                        break
                        
            if not matched_node:
                # Return empty context if entity has no graph presence
                now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
                return CorrelationContext(
                    context_id=str(uuid.uuid4()),
                    entity=entity_id,
                    time_window=(now_str, now_str),
                    risk_summary="Entity not found in Cyber Knowledge Graph."
                )

            # Retrieve local subgraph (within configured hops radius)
            undirected_copy = graph.to_undirected()
            lengths = nx.single_source_shortest_path_length(undirected_copy, matched_node, cutoff=self.radius)
            
            # Slice to max allowed nodes
            subgraph_nodes = list(lengths.keys())[:self.max_nodes]
            subg = graph.subgraph(subgraph_nodes)

            for n in subgraph_nodes:
                if n != matched_node:
                    related_nodes.append(n)
                    try:
                        # Extract shortest path from target node to adjacent node
                        path = nx.shortest_path(undirected_copy, matched_node, n)
                        graph_paths.append(path)
                    except Exception:
                        pass

            # Extract edges from local subgraph
            for u, v, k, attrs in subg.edges(keys=True, data=True):
                if len(related_edges) >= self.max_edges:
                    break
                edge_dict = dict(attrs)
                edge_dict["source"] = u
                edge_dict["target"] = v
                related_edges.append(edge_dict)

            # Reconstruct supporting evidence findings from the node parameters
            for n_id in subgraph_nodes:
                n_attrs = graph.nodes[n_id]
                supporting_evidence.append({
                    "entity": n_attrs.get("display_name", n_id),
                    "entity_type": n_attrs.get("entity_type", "HOST"),
                    "detector": "GRAPH",
                    "risk_score": float(n_attrs.get("risk_score", 0.0)),
                    "severity": str(n_attrs.get("severity", "INFO")),
                    "timestamp": n_attrs.get("last_seen")
                })

        # Compile chronological timeline events
        timeline_events = []
        for edge in related_edges:
            timeline_events.append({
                "timestamp": edge.get("timestamp"),
                "detector": str(edge.get("source_detector", "unknown")).upper(),
                "entity": edge.get("source"),
                "risk_score": float(edge.get("risk", 0.0)),
                "confidence": float(edge.get("confidence", 1.0)),
                "top_reasons": edge.get("metadata", {}).get("top_reasons", [])
            })

        timeline = TimelineBuilder.build(timeline_events)
        risk_summary = SummaryBuilder.summarize(timeline_events)

        # Set time window bounds
        now = datetime.datetime.now(datetime.timezone.utc)
        start = (now - datetime.timedelta(minutes=time_window_minutes)).isoformat()
        end = now.isoformat()

        return CorrelationContext(
            context_id=str(uuid.uuid4()),
            entity=matched_node,
            time_window=(start, end),
            related_entities=related_nodes,
            related_events=related_edges,
            graph_paths=graph_paths,
            risk_summary=risk_summary,
            supporting_evidence=supporting_evidence,
            timeline=timeline
        )
