import json
import pickle
from typing import Any, Dict
import networkx as nx

class GraphExport:
    """Handles exporting of NetworkX MultiDiGraph snapshots into standard formats

    (JSON, GraphML, Pickle) for external tools or downstream SIEM components.
    """

    @staticmethod
    def export_json(graph: nx.MultiDiGraph) -> str:
        """Converts the graph into a standard node-link JSON string."""
        from networkx.readwrite import json_graph
        data = json_graph.node_link_data(graph)
        return json.dumps(data, indent=2, default=str)

    @staticmethod
    def export_graphml(graph: nx.MultiDiGraph, path: str) -> None:
        """Saves the graph as standard GraphML.

        Automatically stringifies nested dictionaries/lists to avoid XML serialization exceptions.
        """
        temp_graph = graph.copy()
        
        # Flatten dictionary or list attributes to JSON strings for compatibility
        for _, attrs in temp_graph.nodes(data=True):
            for k, v in list(attrs.items()):
                if isinstance(v, (dict, list)):
                    attrs[k] = json.dumps(v, default=str)
                    
        for _, _, _, attrs in temp_graph.edges(keys=True, data=True):
            for k, v in list(attrs.items()):
                if isinstance(v, (dict, list)):
                    attrs[k] = json.dumps(v, default=str)
                    
        nx.write_graphml(temp_graph, path)

    @staticmethod
    def export_pickle(graph: nx.MultiDiGraph, path: str) -> None:
        """Saves the graph state using Python's pickle serialization."""
        with open(path, "wb") as f:
            pickle.dump(graph, f)
