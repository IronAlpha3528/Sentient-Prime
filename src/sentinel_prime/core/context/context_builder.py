import uuid
import datetime
import logging
import time
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
        
        # In-memory cache to avoid repeated graph queries for the same entity within a short time
        self._cache: Dict[str, Any] = {}
        # Cache TTL in seconds (e.g. 10 seconds to avoid repeated rebuilds during a single incident analysis)
        self.cache_ttl = self.config.get("context_cache_ttl", 10)

    def build_context(self, entity_id: str, time_window_minutes: int = 30, incident_id: Optional[str] = None) -> CorrelationContext:
        """Constructs a compact CorrelationContext for a target entity ID."""
        now_time = time.time()
        
        # 1. Check cache
        if entity_id in self._cache:
            cached_context, timestamp = self._cache[entity_id]
            if now_time - timestamp < self.cache_ttl:
                logger.info(f"Reusing cached CorrelationContext for entity: {entity_id}")
                if incident_id:
                    cached_context.incident_id = incident_id
                return cached_context

        start_gen_time = time.time()
        
        try:
            store = self.graph_manager.store
            graph = store._graph

            related_nodes = []
            related_edges = []
            graph_paths = []
            supporting_evidence = []

            start_graph_time = time.time()
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
                    err_ctx = CorrelationContext(
                        context_id=str(uuid.uuid4()),
                        entity=entity_id,
                        time_window=(now_str, now_str),
                        risk_summary="Entity not found in Cyber Knowledge Graph.",
                        incident_id=incident_id or ""
                    )
                    duration_ms = (time.time() - start_gen_time) * 1000.0
                    logger.warning(f"Context building failed: Entity {entity_id} not found in graph. Took {duration_ms:.2f}ms.")
                    return err_ctx

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
            
            graph_query_time_ms = (time.time() - start_graph_time) * 1000.0

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

            # Build entities structured dictionary
            entities = {"users": [], "hosts": [], "ips": [], "processes": []}
            for n_id in subgraph_nodes:
                if ":" in n_id:
                    parts = n_id.split(":")
                    prefix = parts[0].upper()
                    name = parts[1]
                    if prefix == "USER":
                        entities["users"].append(name)
                    elif prefix == "HOST":
                        entities["hosts"].append(name)
                    elif prefix == "IP":
                        entities["ips"].append(name)
                    elif prefix == "PROCESS":
                        proc_name = ":".join(parts[2:]) if len(parts) > 2 else parts[1]
                        entities["processes"].append(proc_name)
                else:
                    entities["hosts"].append(n_id)

            # Threat Intelligence enrichment
            start_intel_time = time.time()
            threat_intel_results = []
            try:
                # Query the FAISS ATT&CK index based on timeline descriptions or matched techniques
                query_parts = []
                for ev in timeline_events[:3]:
                    reasons = ev.get("top_reasons", [])
                    if reasons:
                        query_parts.extend(reasons)
                if not query_parts:
                    query_parts.append(entity_id)
                query_str = " ".join(query_parts)
                
                from sentinel_prime.ai.agents.rag.query import search as rag_search
                rag_results = rag_search(query_str, top_k=3)
                for r in rag_results:
                    threat_intel_results.append({
                        "technique_id": r.get("technique_id"),
                        "name": r.get("name"),
                        "description": r.get("description"),
                        "score": r.get("distance")
                    })
            except Exception as e:
                logger.warning(f"Failed to query Threat Intelligence: {e}")
            threat_enrich_time_ms = (time.time() - start_intel_time) * 1000.0

            # Monitoring Snapshot enrichment
            monitoring_snapshot = {}
            if self.bus:
                try:
                    bus_metrics = self.bus.metrics()
                    bus_health = self.bus.health()
                    monitoring_snapshot = {
                        "pipeline_status": bus_health.get("status", "Healthy"),
                        "detector_health": {sub.name: sub.health() for sub in self.bus.stream_manager.subscribers} if hasattr(self.bus, "stream_manager") else {},
                        "evidence_counts": bus_metrics.get("events_received", 0),
                        "current_queue_size": bus_metrics.get("current_queue_size", 0),
                        "subscriber_count": bus_metrics.get("subscriber_count", 0),
                        "average_latency_ms": bus_metrics.get("average_latency", 0.0),
                    }
                except Exception as e:
                    logger.warning(f"Could not retrieve monitoring snapshot: {e}")

            # Compute confidence summary
            conf_sum = "High"
            if timeline_events:
                avg_conf = sum(e.get("confidence", 1.0) for e in timeline_events) / len(timeline_events)
                if avg_conf < 0.5:
                    conf_sum = "Low"
                elif avg_conf < 0.8:
                    conf_sum = "Medium"
            else:
                conf_sum = "N/A (No events)"

            context = CorrelationContext(
                context_id=str(uuid.uuid4()),
                entity=matched_node,
                time_window=(start, end),
                related_entities=related_nodes,
                related_events=related_edges,
                graph_paths=graph_paths,
                risk_summary=risk_summary,
                supporting_evidence=supporting_evidence,
                timeline=timeline,
                incident_id=incident_id or "",
                entities=entities,
                relationships=related_edges,
                evidence=supporting_evidence,
                threat_intel=threat_intel_results,
                graph_subgraph={"nodes": subgraph_nodes, "edges": related_edges},
                historical_incidents=[],
                confidence_summary=conf_sum,
                monitoring_snapshot=monitoring_snapshot
            )

            context_gen_time_ms = (time.time() - start_gen_time) * 1000.0

            # Performance Logging
            logger.info(
                f"Context build stats for entity {entity_id} | "
                f"Gen time: {context_gen_time_ms:.2f}ms | "
                f"Graph query time: {graph_query_time_ms:.2f}ms | "
                f"Threat enrichment time: {threat_enrich_time_ms:.2f}ms | "
                f"Num evidence: {len(supporting_evidence)} | "
                f"Num entities: {len(subgraph_nodes)}"
            )

            # Cache the generated context
            self._cache[entity_id] = (context, time.time())

            return context

        except Exception as e:
            logger.error(f"Critical error in ContextBuilder: {e}", exc_info=True)
            now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
            return CorrelationContext(
                context_id=str(uuid.uuid4()),
                entity=entity_id,
                time_window=(now_str, now_str),
                risk_summary=f"Exception raised during context generation: {e}",
                incident_id=incident_id or ""
            )
