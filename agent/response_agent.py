import json
from .base_agent import BaseAgent
from .prompts import RESPONSE_PROMPT, ResponsePlan

class ResponseAgent:
    def __init__(self):
        self.agent = BaseAgent(
            system_instruction=RESPONSE_PROMPT,
            response_schema=ResponsePlan
        )
        
    def run(self, hypotheses: dict, prediction: dict, asset_criticality: dict) -> dict:
        prompt = f"""
        Based on the hypotheses, prediction, and asset criticality, propose 2-3 containment candidates.
        
        HYPOTHESES:
        {json.dumps(hypotheses, indent=2)}
        
        PREDICTION:
        {json.dumps(prediction, indent=2)}
        
        ASSET CRITICALITY:
        {json.dumps(asset_criticality, indent=2)}
        """
        
        return self.agent.run(prompt)
