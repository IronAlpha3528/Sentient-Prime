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
from sentinel_prime.detection.correlation.meta_classifier import MetaClassifier

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
        
        # Initialize Meta-Classifier with configured path if any
        model_path = self.config.get("correlation", {}).get("model_path", "data/models/meta_lightgbm.pkl")
        self.meta_classifier = MetaClassifier(model_path=model_path)
        
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
            
            # --- Node lookup (fast, under lock) ---
            matched_node = None
            with store.lock:
                if graph.has_node(entity_id):
                    matched_node = entity_id
                else:
                    for n, attrs in graph.nodes(data=True):
                        if attrs.get("display_name") == entity_id:
                            matched_node = n
                            break
            # Lock released before any slow I/O
                            
            if not matched_node:
                # Enrich fallback context with RAG lookup (outside lock — no contention)
                threat_intel_results = []
                try:
                    from sentinel_prime.ai.agents.rag.query import search as rag_search
                    rag_results = rag_search(entity_id, top_k=3)
                    for r in rag_results:
                        threat_intel_results.append({
                            "technique_id": r.get("technique_id"),
                            "name": r.get("name"),
                            "description": r.get("description"),
                            "score": r.get("distance")
                        })
                except Exception as e:
                    logger.warning(f"Failed to query Threat Intelligence for missing entity: {e}")

                monitoring_snapshot = {}
                if self.bus:
                    try:
                        monitoring_snapshot = self.bus.metrics()
                    except Exception:
                        pass

                now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
                err_ctx = CorrelationContext(
                    context_id=str(uuid.uuid4()),
                    entity=entity_id,
                    time_window=(now_str, now_str),
                    risk_summary=f"Entity {entity_id} not found in Cyber Knowledge Graph. Diagnostic fallback applied.",
                    incident_id=incident_id or "",
                    threat_intel=threat_intel_results,
                    monitoring_snapshot=monitoring_snapshot,
                    unified_threat_score=0.0,
                    confidence_score=0.1,
                    risk_level="LOW"
                )
                duration_ms = (time.time() - start_gen_time) * 1000.0
                logger.warning(f"Context building failed: Entity {entity_id} not found in graph. Generated baseline fallback. Took {duration_ms:.2f}ms.")
                return err_ctx

            # --- Subgraph extraction (under lock) ---
            with store.lock:
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

            # Historical Incidents memory enrichment
            historical_incidents_results = []
            try:
                # Search historical incident memories
                hist_results = rag_search(query_str, enabled_providers=["historical_incident"], top_k=2)
                for r in hist_results:
                    historical_incidents_results.append({
                        "incident_id": r.get("incident_id"),
                        "similarity_score": r.get("similarity_score"),
                        "summary": r.get("summary"),
                        "resolved_threat": r.get("resolved_threat"),
                        "timestamp": r.get("timestamp"),
                        "lessons_learned": r.get("lessons_learned", "")
                    })
            except Exception as e:
                logger.warning(f"Failed to query Historical Incident Memory: {e}")

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
                historical_incidents=historical_incidents_results,
                confidence_summary=conf_sum,
                monitoring_snapshot=monitoring_snapshot
            )

            # --- Feature Extraction for Meta-Classifier ---
            # 1. Initialize detector values
            net_score = 0.0
            net_conf = 1.0
            net_sev = "INFO"
            
            id_score = 0.0
            id_conf = 1.0
            id_sev = "INFO"
            
            ep_score = 0.0
            ep_conf = 1.0
            ep_sev = "INFO"
            
            ot_score = 0.0
            ot_conf = 1.0
            ot_sev = "INFO"
            
            honeypot_touched = 0.0
            sigma_match_count = 0
            
            # Detect unique active detectors
            active_detectors = set()
            
            # Extract from timeline_events and related_edges
            for ev in timeline_events:
                det = str(ev.get("detector", "")).upper()
                score_val = float(ev.get("risk_score", 0.0))
                conf_val = float(ev.get("confidence", 1.0))
                
                if score_val > 0.0:
                    active_detectors.add(det)
                    
                if det == "NETWORK":
                    if score_val > 0.0:
                        net_conf = conf_val if net_score == 0.0 else max(net_conf, conf_val)
                    net_score = max(net_score, score_val)
                elif det == "IDENTITY":
                    if score_val > 0.0:
                        id_conf = conf_val if id_score == 0.0 else max(id_conf, conf_val)
                    id_score = max(id_score, score_val)
                elif det == "ENDPOINT":
                    if score_val > 0.0:
                        ep_conf = conf_val if ep_score == 0.0 else max(ep_conf, conf_val)
                    ep_score = max(ep_score, score_val)
                elif det in ["OT", "ICS"]:
                    if score_val > 0.0:
                        ot_conf = conf_val if ot_score == 0.0 else max(ot_conf, conf_val)
                    ot_score = max(ot_score, score_val)
                elif det in ["DECEPTION", "HONEYPOT", "CANARYTOKEN", "CONPOT"]:
                    honeypot_touched = 1.0

            # Scan related_edges for sigma match count, honeypot, and severities
            for edge in related_edges:
                det = str(edge.get("source_detector", "")).upper()
                meta = edge.get("metadata", {})
                
                # Check for sigma matches
                sigma_matches = meta.get("sigma_matches") or meta.get("sigma_hits") or []
                if isinstance(sigma_matches, list):
                    sigma_match_count += len(sigma_matches)
                elif isinstance(sigma_matches, str):
                    sigma_match_count += 1
                    
                if det in ["DECEPTION", "HONEYPOT", "CANARYTOKEN", "CONPOT"]:
                    honeypot_touched = 1.0

            # Extract severities from supporting_evidence (nodes)
            for ev in supporting_evidence:
                ent_type = ev.get("entity_type", "")
                sev_val = ev.get("severity", "INFO")
                # Map to corresponding detector based on heuristics
                if ent_type == "USER":
                    if id_sev == "INFO" or (id_sev == "LOW" and sev_val in ["MEDIUM", "HIGH", "CRITICAL"]):
                        id_sev = sev_val
                elif ent_type == "PROCESS":
                    if ep_sev == "INFO" or (ep_sev == "LOW" and sev_val in ["MEDIUM", "HIGH", "CRITICAL"]):
                        ep_sev = sev_val
                elif ent_type in ["PLC", "ACTUATOR", "SENSOR"]:
                    if ot_sev == "INFO" or (ot_sev == "LOW" and sev_val in ["MEDIUM", "HIGH", "CRITICAL"]):
                        ot_sev = sev_val
                else: # HOST/IP
                    if net_sev == "INFO" or (net_sev == "LOW" and sev_val in ["MEDIUM", "HIGH", "CRITICAL"]):
                        net_sev = sev_val

            # Compute graph-level metrics
            try:
                g_metrics = self.graph_manager.metrics()
            except Exception:
                g_metrics = {}

            # Centralities for the current matched_node
            deg_centrality = g_metrics.get("degree_centrality", {}).get(matched_node, 0.0)
            betweenness_centrality = g_metrics.get("betweenness_centrality", {}).get(matched_node, 0.0)
            closeness_centrality = g_metrics.get("closeness_centrality", {}).get(matched_node, 0.0)
            pagerank = g_metrics.get("pagerank", {}).get(matched_node, 0.0)
            
            wcc_count = g_metrics.get("weakly_connected_components_count", 0)
            communities = g_metrics.get("communities", [])
            communities_count = len(communities)
            
            # Find community size
            community_size = 0
            for comm in communities:
                if matched_node in comm:
                    community_size = len(comm)
                    break
                    
            node_degree = 0
            try:
                if self.graph_manager.store._graph.has_node(matched_node):
                    node_degree = self.graph_manager.store._graph.degree(matched_node)
            except Exception:
                pass

            # Threat Intel features
            threat_intel_match_count = len(threat_intel_results)
            max_threat_intel_score = max([float(ti.get("score", 0.0)) for ti in threat_intel_results]) if threat_intel_results else 0.0

            # Evidence features
            evidence_diversity = len(active_detectors)
            evidence_count = len(supporting_evidence)
            historical_incident_frequency = len(context.historical_incidents) if hasattr(context, "historical_incidents") else 0

            # Temporal Activity calculation
            temporal_activity = 0.0
            timestamps = []
            for ev in timeline_events:
                ts_str = ev.get("timestamp")
                if ts_str:
                    try:
                        timestamps.append(datetime.datetime.fromisoformat(ts_str.replace('Z', '+00:00')))
                    except Exception:
                        pass
            if len(timestamps) >= 2:
                temporal_activity = (max(timestamps) - min(timestamps)).total_seconds() / 60.0

            # Monitoring features
            monitoring_queue_size = float(monitoring_snapshot.get("current_queue_size", 0.0))
            monitoring_latency = float(monitoring_snapshot.get("average_latency_ms", 0.0))

            # Bundle features
            meta_features = {
                "network_score": net_score,
                "network_confidence": net_conf,
                "network_severity": net_sev,
                "identity_score": id_score,
                "identity_confidence": id_conf,
                "identity_severity": id_sev,
                "endpoint_score": ep_score,
                "endpoint_confidence": ep_conf,
                "endpoint_severity": ep_sev,
                "ot_score": ot_score,
                "ot_confidence": ot_conf,
                "ot_severity": ot_sev,
                "honeypot_touched": honeypot_touched,
                "degree_centrality": deg_centrality,
                "betweenness_centrality": betweenness_centrality,
                "closeness_centrality": closeness_centrality,
                "pagerank": pagerank,
                "weakly_connected_components_count": wcc_count,
                "communities_count": communities_count,
                "community_size": community_size,
                "node_degree": node_degree,
                "threat_intel_match_count": threat_intel_match_count,
                "max_threat_intel_score": max_threat_intel_score,
                "evidence_diversity": evidence_diversity,
                "evidence_count": evidence_count,
                "sigma_match_count": sigma_match_count,
                "historical_incident_frequency": historical_incident_frequency,
                "temporal_activity": temporal_activity,
                "monitoring_queue_size": monitoring_queue_size,
                "monitoring_latency": monitoring_latency
            }

            # Predict and enrich context
            assessment = self.meta_classifier.predict(meta_features)
            
            context.unified_threat_score = assessment["unified_threat_score"]
            context.confidence_score = assessment["confidence_score"]
            context.risk_level = assessment["risk_level"]
            context.top_features = assessment["top_features"]
            context.detector_contributions = assessment["detector_contributions"]

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
