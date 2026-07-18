import json
import logging
from typing import Dict, Any, Optional

from sentinel_prime.core.framework import Framework
from .analysis_agent import AnalysisAgent
from .critique_agent import CritiqueAgent
from .action_agent import ActionAgent
from .apt_attribution import attribute_and_predict
from sentinel_prime.soar.risk_scoring.scorer import score_and_rank_actions

logger = logging.getLogger(__name__)

def run_pipeline(evidence: Dict[str, Any]) -> Dict[str, Any]:
    incident_id = evidence.get("incident_id", "UNKNOWN")
    print(f"--- Starting Refactored 3-Stage AI Pipeline for Incident {incident_id} ---")
    
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
        context.incident_id = incident_id
    except Exception as e:
        logger.error(f"Failed to build context: {e}")
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
        
    # Stage 1: Analysis Agent (Correlation, Hypothesis, Prediction)
    print("[Stage 1] Running Analysis Agent...")
    analysis_result = AnalysisAgent().run(context)
    
    # Stage 2: Critique Agent (Self-Correction)
    print("[Stage 2] Running Critique Agent (Devil's Advocate)...")
    critique_result = CritiqueAgent().run(analysis_result, context)
    
    # Extract the validated hypotheses to use for legacy compatibility
    hypotheses = critique_result.get("corrected_hypotheses", analysis_result.get("hypotheses", []))
    
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
        
    # Stage 3: Action Agent (Structured Function Calling)
    print("[Stage 3] Running Action Agent...")
    action_result = ActionAgent().run(analysis_result, critique_result, context=context)
    
    print("[Legacy compatibility] Running attribution and scoring with real context...")
    attribution_data = attribute_and_predict(top_hypothesis, context.to_dict())
    scoring_data = score_and_rank_actions(top_hypothesis, attribution_data)

    response_agent_plan = {
        "recommended_actions": action_result.get("recommended_actions", [])
    }

    final_output = {
        "incident_id": incident_id,
        "original_evidence": evidence,
        "correlation_context": context.to_dict(),
        "story": analysis_result.get("story", {}),
        "hypotheses": mapped_hypotheses,
        "top_hypothesis_selected": top_hypothesis,
        "prediction": analysis_result.get("prediction", {}),
        "critique": critique_result,
        "response_agent_plan": response_agent_plan,
        "attribution_and_prediction": attribution_data,
        "response_plan": scoring_data
    }

    # Persist each AI agent stage into the tamper-evident audit ledger
    try:
        from sentinel_prime.core.telemetry.ledger import AuditLedger
        ledger = AuditLedger()
        ledger.append_entry("ai_analysis", analysis_result, incident_id=incident_id)
        ledger.append_entry("ai_critique", critique_result, incident_id=incident_id)
        ledger.append_entry("ai_action_plan", action_result, incident_id=incident_id)
        ledger.append_entry("risk_scoring", scoring_data, incident_id=incident_id)
    except OSError:
        logger.exception("Unable to persist AI reasoning stages to the audit ledger")

    print("--- 3-Stage Pipeline Complete ---")
    return final_output
