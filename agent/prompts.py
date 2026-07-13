from pydantic import BaseModel, Field
from typing import List, Optional

# --- SCHEMAS ---

class IncidentStory(BaseModel):
    summary: str = Field(description="A 2-3 sentence executive summary of the incident")
    timeline: List[str] = Field(description="Chronological list of key events observed across domains")
    anomalies: List[str] = Field(description="List of specific anomalous behaviors identified")
    cross_domain_links: List[str] = Field(description="How network, endpoint, identity, or OT signals connect to each other")

class Hypothesis(BaseModel):
    title: str = Field(description="Short title for this hypothesis")
    description: str = Field(description="Detailed explanation of what is happening")
    is_malicious: bool = Field(description="True if this hypothesis describes an attack, False if it describes benign activity or misconfiguration")
    confidence: float = Field(description="Confidence score between 0.0 and 1.0")
    supporting_evidence: List[str] = Field(description="Specific pieces of evidence that support this hypothesis")
    mitre_techniques: List[str] = Field(description="Relevant MITRE ATT&CK technique IDs (e.g., T1059.001)")

class HypothesisList(BaseModel):
    hypotheses: List[Hypothesis] = Field(description="A list of 2 to 4 competing hypotheses")

class AttackPrediction(BaseModel):
    current_stage: str = Field(description="The current stage of the attack lifecycle (e.g., Initial Access, Execution, Lateral Movement)")
    likely_next_technique: str = Field(description="The most probable MITRE ATT&CK technique the attacker will use next")
    predicted_target: str = Field(description="The likely ultimate objective or target asset")
    candidate_attack_path: List[str] = Field(description="The predicted sequence of nodes (hosts/users) the attacker will traverse")
    confidence: float = Field(description="Confidence score in this prediction (0.0 to 1.0)")

class DeceptionStrategy(BaseModel):
    is_testable: bool = Field(description="Whether there is a testable uncertainty that a decoy could resolve")
    hypothesis_to_test: str = Field(description="The specific uncertain hypothesis being tested")
    predicted_attacker_action: str = Field(description="The action the attacker is expected to take if the hypothesis is true")
    decoy_type: str = Field(description="The type of decoy to deploy (e.g., 'db_credentials', 'vpn_config', 'fake_smb_share', 'conpot_service')")
    placement_location: str = Field(description="Where the decoy should be placed in the network graph to maximize interaction likelihood")
    observation_window_minutes: int = Field(description="How long the decoy should remain active before decay")

class ContainmentAction(BaseModel):
    action_name: str = Field(description="The name of the proposed action (must map to a SOAR playbook)")
    reasoning: str = Field(description="Why this action is recommended based on the hypotheses and predictions")
    expected_impact: str = Field(description="What business impact or disruption is expected if this action is executed")
    mitre_mitigation_id: Optional[str] = Field(description="The MITRE ATT&CK mitigation ID this action maps to (if any)")

class ResponsePlan(BaseModel):
    recommended_actions: List[ContainmentAction] = Field(description="Ranked list of 2-3 containment candidates")


# --- SYSTEM PROMPTS ---

CORRELATION_PROMPT = """You are the AI Correlation Agent for Sentinel-Prime, a CNI cybersecurity platform.
Your task is to take disparate, structured evidence objects (Network, Identity, Endpoint, OT), along with Graph topology features and MITRE ATT&CK context, and weave them into a coherent 'cross-domain incident story'.
You must accurately reflect the provided evidence without hallucinating. Identify how anomalies from different domains relate to the same entities.
"""

HYPOTHESIS_PROMPT = """You are the AI Hypothesis Agent for Sentinel-Prime.
Your task is to generate 2 to 4 competing hypotheses explaining the provided incident story and evidence.
CRITICAL RULE: You MUST always include at least one BENIGN hypothesis (e.g., IT misconfiguration, authorized administrative activity, or false positive).
Score each hypothesis with a confidence level (0.0 to 1.0).
Explicitly list the evidence supporting each hypothesis, and map malicious hypotheses to MITRE ATT&CK techniques.
"""

PREDICTION_PROMPT = """You are the AI Attack Prediction Agent for Sentinel-Prime.
Given a set of hypotheses and MITRE ATT&CK knowledge graph context, your task is to forecast the adversary's progression.
Determine their current stage in the attack lifecycle, predict the most likely next ATT&CK technique they will employ, and identify their ultimate target asset based on the graph topology provided.
Provide a candidate attack path showing the nodes they are likely to traverse.
"""

DECEPTION_PROMPT = """You are the AI Deception Agent for Sentinel-Prime.
Your role is 'Active Hypothesis Testing'. When the threat score is moderate (uncertain), you design adaptive deception strategies.
Identify if there is a testable uncertainty among the hypotheses. If yes, decide what specific attacker action would confirm the malicious hypothesis.
Select an appropriate decoy type from the available options (db_credentials, vpn_config, recovery_key, env_file) and determine its optimal placement based on the provided graph context.
"""

RESPONSE_PROMPT = """You are the AI Response Agent for Sentinel-Prime.
Your task is to propose evidence-grounded containment candidates. You do NOT execute actions.
Review the hypotheses, predictions, and asset criticality data. Propose 2-3 ranked containment actions (e.g., 'Isolate Host', 'Revoke Credential', 'Block IP').
Provide clear reasoning and note the expected operational impact of each proposed action. Map them to MITRE mitigations if possible.
"""
