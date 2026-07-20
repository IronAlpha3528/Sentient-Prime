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

class AttackPrediction(BaseModel):
    current_stage: str = Field(description="The current stage of the attack lifecycle (e.g., Initial Access, Execution, Lateral Movement)")
    likely_next_technique: str = Field(description="The most probable MITRE ATT&CK technique the attacker will use next")
    predicted_target: str = Field(description="The likely ultimate objective or target asset")
    candidate_attack_path: List[str] = Field(description="The predicted sequence of nodes (hosts/users) the attacker will traverse")
    confidence: float = Field(description="Confidence score in this prediction (0.0 to 1.0)")

class AnalysisResult(BaseModel):
    story: IncidentStory = Field(description="The coherent cross-domain incident story")
    hypotheses: List[Hypothesis] = Field(description="A list of 2 to 4 competing hypotheses")
    prediction: AttackPrediction = Field(description="The predicted attack progression")

class CritiqueResult(BaseModel):
    is_valid: bool = Field(description="True if the analysis holds up against rigorous critique, False if there are major flaws")
    critique_feedback: str = Field(description="Detailed critique of the hypotheses and prediction, highlighting any logical leaps or hallucinations")
    corrected_hypotheses: List[Hypothesis] = Field(description="Revised hypotheses fixing the identified flaws, or same as original if valid")

class ActionParameters(BaseModel):
    target: Optional[str] = Field(description="Target entity, IP, or host for the action", default=None)

class FunctionCallAction(BaseModel):
    action_name: str = Field(description="Name of the action (e.g., 'isolate_host', 'block_ip', 'revoke_access', 'deploy_decoy')")
    parameters: ActionParameters = Field(description="Parameters for the function")
    reasoning: str = Field(description="Why this action is recommended")

class ActionPlan(BaseModel):
    recommended_actions: List[FunctionCallAction] = Field(description="List of exact actions to execute")


# --- SYSTEM PROMPTS ---

ANALYSIS_PROMPT = """You are the AI Analysis Agent for Sentinel-Prime, a CNI cybersecurity platform.
Your task is to take disparate evidence objects (Network, Identity, Endpoint, OT) and MITRE ATT&CK context, and perform a full analysis.
1. Generate a coherent 'cross-domain incident story'.
2. Generate 2 to 4 competing hypotheses (MUST include at least one BENIGN hypothesis).
3. Predict the adversary's progression (current stage, next technique, target).

CRITICAL INSTRUCTIONS for MITRE ATT&CK Mapping (Few-Shot Examples):
- If you see "vssadmin.exe delete shadows", map strictly to T1490 (Inhibit System Recovery).
- If you see "lsass.exe" memory access or credential dumping, map strictly to T1003.001 (OS Credential Dumping: LSASS Memory).
- If you see "Suspicious PowerShell Download", map strictly to T1105 (Ingress Tool Transfer).
- If you see "Pass-the-Hash" or "Lateral Movement", map strictly to T1550.002 (Use Alternate Authentication Material).
- If you see OT/ICS manipulation (e.g. PLC parameter modified), map strictly to T0836 (Modify Parameter) or T0831 (Manipulation of Control).

Output your results strictly according to the provided JSON schema.
"""

CRITIQUE_PROMPT = """You are the AI Critique Agent (Self-Correction) for Sentinel-Prime.
Your task is to review the Analysis Agent's output (story, hypotheses, prediction) and play 'Devil's Advocate'.
Scrutinize the hypotheses for logical leaps, unlikely MITRE techniques, or hallucinations.
If the analysis is flawed, mark is_valid=False and provide corrected_hypotheses. If it is solid, mark is_valid=True and pass them through.
"""

ACTION_PROMPT = """You are the AI Action Agent (Structured Tool Output) for Sentinel-Prime.
Review the finalized analysis (hypotheses and prediction). Propose specific, parameterized containment or deception actions.
Available actions include: 'isolate_host', 'block_ip', 'revoke_access', 'deploy_decoy'.

CRITICAL ACTION RULES:
- ONLY recommend 'block_ip' if a specific malicious external IP address is known.
- For user identity compromise or lateral movement, recommend 'revoke_access'.
- For severe host compromise without a known external IP, recommend 'revoke_access' on the compromised accounts, or 'deploy_decoy' if isolation is too disruptive.
- Avoid recommending 'isolate_host' for endpoint alerts unless the blast radius is acceptable, as it will often require manual escalation.

Provide the exact function name and the target parameter for each proposed action, along with your reasoning.
"""
