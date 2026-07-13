import datetime
from typing import Any, Dict, List, Optional
from core.graph.graph_store import GraphStore

class GraphQuery:
    """Implements optimized querying and traversal APIs over the GraphStore.

    Hides raw NetworkX operations from external callers.
    """

    def __init__(self, store: GraphStore):
        self.store = store

    def find_node(self, node_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves details of a single node in the graph."""
        return self.store.get_node(node_id)

    def find_neighbors(self, node_id: str, direction: str = "both") -> List[str]:
        """Returns adjacent node IDs based on incoming/outgoing edge directions."""
        with self.store.lock:
            if not self.store._graph.has_node(node_id):
                return []
            if direction == "in":
                return list(self.store._graph.predecessors(node_id))
            elif direction == "out":
                return list(self.store._graph.successors(node_id))
            else:
                # both incoming and outgoing connections
                return list(set(list(self.store._graph.predecessors(node_id)) + list(self.store._graph.successors(node_id))))

    def find_shortest_path(self, source: str, target: str) -> List[str]:
        """Computes the shortest path from source node to target node."""
        import networkx as nx
        with self.store.lock:
            try:
                # Computes shortest path. Uses undirected copy for maximum traversal range
                undirected_copy = self.store._graph.to_undirected()
                return nx.shortest_path(undirected_copy, source, target)
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                return []

    def find_nodes_by_type(self, node_type: str) -> List[Dict[str, Any]]:
        """Queries all nodes matching a specific entity type."""
        nodes = []
        with self.store.lock:
            for node_id, attrs in self.store._graph.nodes(data=True):
                if str(attrs.get("entity_type", "")).upper() == str(node_type).upper():
                    nodes.append(dict(attrs))
        return nodes

    def find_hosts(self) -> List[Dict[str, Any]]:
        """Returns all HOST nodes in the graph."""
        return self.find_nodes_by_type("HOST")

    def find_users(self) -> List[Dict[str, Any]]:
        """Returns all USER nodes in the graph."""
        return self.find_nodes_by_type("USER")

    def find_processes(self) -> List[Dict[str, Any]]:
        """Returns all PROCESS nodes in the graph."""
        return self.find_nodes_by_type("PROCESS")

    def find_high_risk_nodes(self, threshold: float = 0.5) -> List[Dict[str, Any]]:
        """Finds all nodes exceeding the specified risk threshold, sorted descending."""
        high_risk = []
        with self.store.lock:
            for risk, node_id in self.store._risk_index:
                if risk >= threshold:
                    node = self.store._graph.nodes[node_id]
                    high_risk.append(dict(node))
                else:
                    break
        return high_risk

    def find_recent_events(self, time_window_minutes: int = 10) -> List[Dict[str, Any]]:
        """Retrieves nodes and edges updated within the last N minutes."""
        recent = []
        now = datetime.datetime.now(datetime.timezone.utc)
        with self.store.lock:
            for ts, type_str, ref in reversed(self.store._timestamp_index):
                try:
                    ts_dt = datetime.datetime.fromisoformat(ts.replace('Z', '+00:00'))
                    delta = (now - ts_dt).total_seconds() / 60.0
                    if delta <= time_window_minutes:
                        if type_str == "node":
                            recent.append({
                                "type": "node", 
                                "id": ref, 
                                "data": dict(self.store._graph.nodes[ref])
                            })
                        else:
                            u, v, k = ref
                            recent.append({
                                "type": "edge", 
                                "source": u, 
                                "target": v, 
                                "data": dict(self.store._graph[u][v][k])
                            })
                    else:
                        break
                except Exception:
                    pass
        return recent

    def find_attack_chain(self, start_node_id: str, depth: int = 3) -> Dict[str, Any]:
        """Constructs an attack graph traversal starting from a node.

        Returns a dictionary containing sub-nodes, edges, and a chronological timeline.
        """
        import networkx as nx
        with self.store.lock:
            if not self.store._graph.has_node(start_node_id):
                return {"nodes": [], "edges": [], "timeline": []}

            # Gather neighborhood within depth limit (ignoring edge direction to rebuild chain)
            undirected_copy = self.store._graph.to_undirected()
            subgraph_nodes = nx.single_source_shortest_path_length(
                undirected_copy, start_node_id, cutoff=depth
            ).keys()
            
            subg = self.store._graph.subgraph(subgraph_nodes)

            nodes_list = []
            for n, attrs in subg.nodes(data=True):
                nodes_list.append(dict(attrs))

            edges_list = []
            timeline = []
            for u, v, k, attrs in subg.edges(keys=True, data=True):
                edge_dict = dict(attrs)
                edge_dict["source"] = u
                edge_dict["target"] = v
                edges_list.append(edge_dict)

                ts = attrs.get("timestamp")
                if ts:
                    timeline.append({
                        "timestamp": ts,
                        "description": f"{u} --[{attrs.get('type')}]--> {v}",
                        "risk": attrs.get("risk", 0.0),
                        "confidence": attrs.get("confidence", 1.0)
                    })

            timeline.sort(key=lambda x: x["timestamp"])
            return {
                "nodes": nodes_list,
                "edges": edges_list,
                "timeline": timeline
            }

    def find_entities_by_detector(self, detector: str) -> List[Dict[str, Any]]:
        """Queries all graph relationships established by a specific specialist detector."""
        det_upper = str(detector).upper()
        results = []
        with self.store.lock:
            edge_refs = self.store._detector_index.get(det_upper, [])
            for u, v, k in edge_refs:
                if self.store._graph.has_edge(u, v, k):
                    results.append({
                        "source": u,
                        "target": v,
                        "relationship": dict(self.store._graph[u][v][k])
                    })
        return results
