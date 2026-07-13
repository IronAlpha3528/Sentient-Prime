import json
from .base_agent import BaseAgent
from .prompts import PREDICTION_PROMPT, AttackPrediction
from .tools import fetch_prediction_context

class PredictionAgent:
    def __init__(self):
        self.agent = BaseAgent(
            system_instruction=PREDICTION_PROMPT,
            response_schema=AttackPrediction
        )
        
    def run(self, hypotheses: dict) -> dict:
        context = fetch_prediction_context()
        
        prompt = f"""
        Based on the provided hypotheses and graph context, predict the attacker's next move.
        
        HYPOTHESES:
        {json.dumps(hypotheses, indent=2)}
        
        GRAPH CONTEXT:
        {json.dumps(context, indent=2)}
        """
        
        return self.agent.run(prompt)
