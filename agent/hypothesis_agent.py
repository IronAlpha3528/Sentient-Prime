import json
from .base_agent import BaseAgent
from .prompts import HYPOTHESIS_PROMPT, HypothesisList

class HypothesisAgent:
    def __init__(self):
        self.agent = BaseAgent(
            system_instruction=HYPOTHESIS_PROMPT,
            response_schema=HypothesisList
        )
        
    def run(self, incident_story: dict) -> dict:
        prompt = f"""
        Please analyze this incident story and generate 2-4 competing hypotheses.
        Remember to include at least one benign explanation.
        
        INCIDENT STORY:
        {json.dumps(incident_story, indent=2)}
        """
        
        return self.agent.run(prompt)
