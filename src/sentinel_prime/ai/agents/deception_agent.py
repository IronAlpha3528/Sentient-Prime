from typing import Optional, Any
import json
from .base_agent import BaseAgent
from .prompts import DECEPTION_PROMPT, DeceptionStrategy

class DeceptionAgent:
    def __init__(self):
        self.agent = BaseAgent(
            system_instruction=DECEPTION_PROMPT,
            response_schema=DeceptionStrategy
        )
        
    def run(self, hypotheses: dict, prediction: dict, graph_topology: Optional[Any] = None, context: Optional[Any] = None) -> dict:
        if context:
            context_dict = context.to_dict() if hasattr(context, "to_dict") else context
            topology = {}
            for edge in context_dict.get("related_events", []):
                src = edge.get("source")
                tgt = edge.get("target")
                if src and tgt:
                    if src not in topology:
                        topology[src] = []
                    if tgt not in topology[src]:
                        topology[src].append(tgt)
            graph_topology = topology

        prompt = f"""
        Based on the current hypotheses and prediction, design an active deception strategy 
        if there is a testable uncertainty.
        
        HYPOTHESES:
        {json.dumps(hypotheses, indent=2)}
        
        PREDICTION:
        {json.dumps(prediction, indent=2)}
        
        GRAPH TOPOLOGY:
        {json.dumps(graph_topology, indent=2)}
        """
        
        return self.agent.run(prompt)
