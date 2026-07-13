from typing import Any, Dict
import networkx as nx

class GraphMetrics:
    """Computes various NetworkX topological and risk-based metrics

    over the knowledge graph to enrich downstream correlation context.
    """

    @staticmethod
    def compute(graph: nx.MultiDiGraph) -> Dict[str, Any]:
        """Calculates centrality, clusters, PageRank, communities,

        and risk distribution. Safely handles empty or disconnected states.
        """
        node_count = graph.number_of_nodes()
        edge_count = graph.number_of_edges()

        if node_count == 0:
            return {
                "nodes_count": 0,
                "edges_count": 0,
                "degree_centrality": {},
                "betweenness_centrality": {},
                "closeness_centrality": {},
                "pagerank": {},
                "weakly_connected_components_count": 0,
                "communities": [],
                "risk_distribution": {"benign": 0, "moderate": 0, "high": 0, "critical": 0}
            }

        # 1. Centralities
        deg_centrality = nx.degree_centrality(graph)

        # Wrap betweenness and closeness calculation to swallow potential division errors
        try:
            bet_centrality = nx.betweenness_centrality(graph)
        except Exception:
            bet_centrality = {}

        try:
            close_centrality = nx.closeness_centrality(graph)
        except Exception:
            close_centrality = {}

        # 2. PageRank (Compute on simple DiGraph representation for stability)
        try:
            simple_digraph = nx.DiGraph(graph)
            pagerank = nx.pagerank(simple_digraph)
        except Exception:
            pagerank = {}

        # 3. Weakly Connected Components (identifies isolated sub-attack groups)
        try:
            wcc = list(nx.weakly_connected_components(graph))
            wcc_count = len(wcc)
        except Exception:
            wcc_count = 0

        # 4. Modularity Communities (Clustering of entities)
        try:
            from networkx.algorithms import community
            undirected_simple = nx.Graph(graph)
            comm_list = list(community.greedy_modularity_communities(undirected_simple))
            communities = [list(c) for c in comm_list]
        except Exception:
            communities = []

        # 5. Risk Score Distribution
        risk_dist = {"benign": 0, "moderate": 0, "high": 0, "critical": 0}
        for _, attrs in graph.nodes(data=True):
            r = float(attrs.get("risk_score", 0.0))
            if r < 0.2:
                risk_dist["benign"] += 1
            elif r < 0.5:
                risk_dist["moderate"] += 1
            elif r < 0.8:
                risk_dist["high"] += 1
            else:
                risk_dist["critical"] += 1

        return {
            "nodes_count": node_count,
            "edges_count": edge_count,
            "degree_centrality": deg_centrality,
            "betweenness_centrality": bet_centrality,
            "closeness_centrality": close_centrality,
            "pagerank": pagerank,
            "weakly_connected_components_count": wcc_count,
            "communities": communities,
            "risk_distribution": risk_dist
        }
