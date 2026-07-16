import json
import logging
from typing import Dict, Any, Optional

from sentinel_prime.core.framework import Framework
from .correlation_agent import CorrelationAgent
from .hypothesis_agent import HypothesisAgent
from .prediction_agent import PredictionAgent
from .deception_agent import DeceptionAgent
from .response_agent import ResponseAgent
from .apt_attribution import attribute_and_predict
from sentinel_prime.soar.risk_scoring.scorer import score_and_rank_actions

logger = logging.getLogger(__name__)

def run_pipeline(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """
    Entry point for the AI Reasoning Core.
    Takes a Common Evidence Object, builds Context using ContextBuilder, and runs
    the 5-agent pipeline.
    """
    incident_id = evidence.get("incident_id", "UNKNOWN")
    print(f"--- Starting AI Reasoning Pipeline for Incident {incident_id} ---")
    
    # 1. Build context via Framework / ContextBuilder
    try:
        framework = Framework()
        entity_id = evidence.get("entity_id") or evidence.get("target_asset")
        if not entity_id:
            entities = evidence.get("entities", {})
            for key in ["hosts", "users", "ips"]:
                if entities.get(key):
                    entity_id = entities[key][0]
                    break
        if not entity_id:
            entity_id = "internet" # Safe default fallback
            
        print(f"Building context for entity: {entity_id}")
        context = framework.build_context(entity_id)
        # Ensure incident_id is set
        context.incident_id = incident_id
    except Exception as e:
        logger.error(f"Failed to build context: {e}")
        # Build an empty/fallback context
        import uuid, datetime
        from sentinel_prime.core.context import CorrelationContext
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
        context = CorrelationContext(
            context_id=str(uuid.uuid4()),
            entity="unknown",
            time_window=(now_str, now_str),
            risk_summary=f"ContextBuilder failed to run: {e}",
            incident_id=incident_id
        )
        
    # Block 1: Correlation Agent (Cross-domain incident story)
    print("[Agent 1] Running Correlation Agent...")
    story_result = CorrelationAgent().run(context)
    
    # Block 2: Hypothesis Agent
    print("[Agent 2] Running Hypothesis Agent...")
    hypothesis_result = HypothesisAgent().run(story_result, context)
    hypotheses = hypothesis_result.get("hypotheses", [])
    
    # Map hypotheses for legacy schemas compatibility
    mapped_hypotheses = []
    for h in hypotheses:
        mapped_h = {
            "hypothesis": h.get("title"),
            "technique_id": h.get("mitre_techniques", [None])[0] if h.get("mitre_techniques") else None,
            "technique_name": h.get("title"),
            "tactic": None,
            "confidence": h.get("confidence", 0.0),
            "reasoning": h.get("description"),
            "is_benign": not h.get("is_malicious", True),
            "title": h.get("title"),
            "description": h.get("description"),
            "is_malicious": h.get("is_malicious", True),
            "supporting_evidence": h.get("supporting_evidence", []),
            "mitre_techniques": h.get("mitre_techniques", [])
        }
        mapped_hypotheses.append(mapped_h)
        
    # Filter for the most likely malicious hypothesis
    top_hypothesis = None
    for h in sorted(mapped_hypotheses, key=lambda x: x.get("confidence", 0), reverse=True):
        if not h.get("is_benign"):
            top_hypothesis = h
            break
            
    if not top_hypothesis and mapped_hypotheses:
        top_hypothesis = max(mapped_hypotheses, key=lambda x: x.get("confidence", 0))
        
    if not top_hypothesis:
        top_hypothesis = {
            "hypothesis": "Unknown threat",
            "technique_id": None,
            "technique_name": None,
            "tactic": None,
            "confidence": 0.1,
            "reasoning": "No hypotheses generated",
            "is_benign": True
        }

    # Block 3: Prediction Agent
    print("[Agent 3] Running Prediction Agent...")
    prediction_result = PredictionAgent().run(hypothesis_result, context)
    
    # Block 4: Deception Agent
    print("[Agent 4] Running Deception Agent...")
    deception_result = DeceptionAgent().run(hypothesis_result, prediction_result, context=context)
    
    # Block 5: Response Agent
    print("[Agent 5] Running Response Agent...")
    response_result = ResponseAgent().run(hypothesis_result, prediction_result, context=context)
    
    # Run legacy Block 2 & Block 3 with real context data to maintain compatibility
    print("[Legacy compatibility] Running attribution and scoring with real context...")
    attribution_data = attribute_and_predict(top_hypothesis, context.to_dict())
    scoring_data = score_and_rank_actions(top_hypothesis, attribution_data)
    
    # Combine final output (with all fields for new and old callers)
    final_output = {
        "incident_id": incident_id,
        "original_evidence": evidence,
        "correlation_context": context.to_dict(),
        "story": story_result,
        "hypotheses": mapped_hypotheses,
        "top_hypothesis_selected": top_hypothesis,
        "prediction": prediction_result,
        "deception_strategy": deception_result,
        "response_agent_plan": response_result,
        # legacy fields
        "attribution_and_prediction": attribution_data,
        "response_plan": scoring_data
    }
    
    print("--- Pipeline Complete ---")
    return final_output


