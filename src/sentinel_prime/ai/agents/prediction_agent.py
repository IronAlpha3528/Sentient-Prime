from typing import Optional, Any
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
        
    def run(self, hypotheses: dict, context: Optional[Any] = None) -> dict:
        if context:
            context_dict = context.to_dict() if hasattr(context, "to_dict") else context
            topology = {}
            for edge in context_dict.get("related_events", []):
                src = edge.get("source")
                tgt = edge.get("target")
                if src and tgt:
                    if src not in topology:
                        topology[src] = []
                    if tgt not in topology[src]:
                        topology[src].append(tgt)
            
            critical_assets = []
            for node in context_dict.get("related_entities", []):
                is_crit = False
                for se in context_dict.get("supporting_evidence", []):
                    if se.get("entity") == node and se.get("risk_score", 0.0) >= 0.8:
                        is_crit = True
                if is_crit and node not in critical_assets:
                    critical_assets.append(node)
                    
            prediction_context = {
                "graph_topology": topology,
                "critical_assets": critical_assets
            }
        else:
            prediction_context = fetch_prediction_context()
            
        prompt = f"""
        Based on the provided hypotheses and graph context, predict the attacker's next move.
        
        HYPOTHESES:
        {json.dumps(hypotheses, indent=2)}
        
        GRAPH CONTEXT:
        {json.dumps(prediction_context, indent=2)}
        """
        
        return self.agent.run(prompt)
