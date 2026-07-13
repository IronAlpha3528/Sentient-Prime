def simulate_action(action_name: str, target_entity: str, graph_topology: dict) -> dict:
    """
    Simulates removing an entity from the graph to see how many dependent nodes are orphaned.
    Returns the calculated blast radius.
    """
    if target_entity not in graph_topology:
        return {"blast_radius_nodes": 0, "simulated_impact_level": "Low", "affected_nodes": []}
        
    # Get connections
    connections = graph_topology.get(target_entity, [])
    blast_radius = len(connections)
    
    if blast_radius == 0:
        impact = "Low"
    elif blast_radius < 3:
        impact = "Medium"
    elif blast_radius < 10:
        impact = "High"
    else:
        impact = "Critical"
        
    return {
        "blast_radius_nodes": blast_radius,
        "simulated_impact_level": impact,
        "affected_nodes": connections
    }
