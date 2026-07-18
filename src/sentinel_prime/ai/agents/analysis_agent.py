import json
from typing import Optional, Any
from .base_agent import BaseAgent
from .prompts import ANALYSIS_PROMPT, AnalysisResult

class AnalysisAgent:
    def __init__(self):
        self.agent = BaseAgent(
            system_instruction=ANALYSIS_PROMPT,
            response_schema=AnalysisResult
        )
        
    def run(self, context: Optional[Any] = None) -> dict:
        prompt = f"""
        Analyze the following incident context, build the cross-domain story, generate hypotheses, and predict the attack path.
        
        CONTEXT:
        {json.dumps(context.to_dict() if hasattr(context, "to_dict") else context, indent=2)}
        """
        return self.agent.run(prompt)
