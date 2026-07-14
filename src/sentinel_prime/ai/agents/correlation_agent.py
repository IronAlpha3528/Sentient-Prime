import json
from typing import Union, Any
from .base_agent import BaseAgent
from .prompts import CORRELATION_PROMPT, IncidentStory
from .tools import fetch_correlation_context
from sentinel_prime.core.context.context_schema import CorrelationContext

class CorrelationAgent:
    def __init__(self):
        self.agent = BaseAgent(
            system_instruction=CORRELATION_PROMPT,
            response_schema=IncidentStory
        )
        
    def run(self, context: Union[CorrelationContext, str]) -> dict:
        if isinstance(context, str):
            # Fallback for testing / backward compatibility
            try:
                from sentinel_prime.core.framework import Framework
                framework = Framework()
                context_obj = framework.build_context(context)
                context_dict = context_obj.to_dict()
            except Exception:
                context_dict = fetch_correlation_context(context)
        else:
            context_dict = context.to_dict() if hasattr(context, "to_dict") else context
            
        prompt = f"""
        Please analyze the following context and produce a cross-domain incident story.
        
        CONTEXT:
        {json.dumps(context_dict, indent=2)}
        """
        
        return self.agent.run(prompt)
