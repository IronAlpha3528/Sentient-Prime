import json
from .base_agent import BaseAgent
from .prompts import DECEPTION_PROMPT, DeceptionStrategy

class DeceptionAgent:
    def __init__(self):
        self.agent = BaseAgent(
            system_instruction=DECEPTION_PROMPT,
            response_schema=DeceptionStrategy
        )
        
    def run(self, hypotheses: dict, prediction: dict, graph_topology: dict) -> dict:
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
