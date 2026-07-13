import json
from .base_agent import BaseAgent
from .prompts import CORRELATION_PROMPT, IncidentStory
from .tools import fetch_correlation_context

class CorrelationAgent:
    def __init__(self):
        self.agent = BaseAgent(
            system_instruction=CORRELATION_PROMPT,
            response_schema=IncidentStory
        )
        
    def run(self, incident_id: str) -> dict:
        # Route B: Fetch context upfront
        context = fetch_correlation_context(incident_id)
        
        prompt = f"""
        Please analyze the following context and produce a cross-domain incident story.
        
        CONTEXT:
        {json.dumps(context, indent=2)}
        """
        
        return self.agent.run(prompt)
