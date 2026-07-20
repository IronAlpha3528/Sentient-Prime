import json
from typing import Optional, Any
from .base_agent import BaseAgent
from .prompts import ACTION_PROMPT, ActionPlan

from sentinel_prime.core.config_manager import config

class ActionAgent:
    def __init__(self):
        self.agent = BaseAgent(
            system_instruction=ACTION_PROMPT,
            response_schema=ActionPlan,
            api_key=config.GEMINI_API_KEY_ACTION
        )
        
    def run(self, analysis: dict, critique: dict, context: Optional[Any] = None) -> dict:
        prompt = f"""
        Based on the validated analysis, propose 2-3 containment or deception actions.
        Use exact function names and parameters.
        
        ANALYSIS:
        {json.dumps(analysis, indent=2)}
        
        CRITIQUE (Self-Correction):
        {json.dumps(critique, indent=2)}
        """
        return self.agent.run(prompt)
