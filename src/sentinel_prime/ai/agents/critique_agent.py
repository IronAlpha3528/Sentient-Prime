import json
from typing import Optional, Any
from .base_agent import BaseAgent
from .prompts import CRITIQUE_PROMPT, CritiqueResult

from sentinel_prime.core.config_manager import config

class CritiqueAgent:
    def __init__(self):
        self.agent = BaseAgent(
            system_instruction=CRITIQUE_PROMPT,
            response_schema=CritiqueResult,
            api_key=config.GEMINI_API_KEY_CRITIQUE
        )
        
    def run(self, analysis_result: dict, context: Optional[Any] = None) -> dict:
        prompt = f"""
        Review this Analysis Result. Check for logical leaps, unlikely MITRE techniques, or hallucinations.
        
        ANALYSIS RESULT:
        {json.dumps(analysis_result, indent=2)}
        
        CONTEXT (for reference):
        {json.dumps(context.to_dict() if hasattr(context, "to_dict") else context, indent=2)}
        """
        return self.agent.run(prompt)
