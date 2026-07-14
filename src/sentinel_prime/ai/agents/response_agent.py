from typing import Optional, Any
import json
from .base_agent import BaseAgent
from .prompts import RESPONSE_PROMPT, ResponsePlan

class ResponseAgent:
    def __init__(self):
        self.agent = BaseAgent(
            system_instruction=RESPONSE_PROMPT,
            response_schema=ResponsePlan
        )
        
    def run(self, hypotheses: dict, prediction: dict, asset_criticality: Optional[Any] = None, context: Optional[Any] = None) -> dict:
        if context:
            context_dict = context.to_dict() if hasattr(context, "to_dict") else context
            criticality = {}
            for node in context_dict.get("related_entities", []):
                node_crit = "Low"
                for se in context_dict.get("supporting_evidence", []):
                    if se.get("entity") == node:
                        risk = se.get("risk_score", 0.0)
                        if risk >= 0.8:
                            node_crit = "Critical"
                        elif risk >= 0.5:
                            node_crit = "High"
                        elif risk >= 0.3:
                            node_crit = "Medium"
                criticality[node] = node_crit
            asset_criticality = criticality

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
