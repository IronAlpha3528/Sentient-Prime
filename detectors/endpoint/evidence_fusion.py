import logging
from typing import Dict, Any, List, Tuple
from detectors.endpoint.endpoint_evidence import EndpointEvidence

logger = logging.getLogger(__name__)

def generate_top_reasons(features: Dict[str, Any], sigma_matches: List[Dict[str, Any]]) -> List[str]:
    reasons = []

    # Heuristic triggers from feature vectors
    if features.get("encoded_command_flag", 0.0) > 0:
        reasons.append("Encoded command execution observed")
    if features.get("powershell_flag", 0.0) > 0:
        reasons.append("PowerShell execution detected")
    if features.get("lsass_access_count", 0.0) > 0:
        reasons.append("LSASS memory access observed")
    if features.get("remote_thread_count", 0.0) > 0:
        reasons.append("CreateRemoteThread injection behaviour")
    if features.get("lolbin_flag", 0.0) > 0:
        reasons.append("Suspicious LOLBin executable usage")
    if features.get("child_process_count", 0.0) > 5.0:
        reasons.append("High process fan-out rate")
    if features.get("parent_child_rarity", 0.0) > 0.5:
        reasons.append("Rare parent-child execution relationship")
    if features.get("registry_modification_count", 0.0) > 10.0:
        reasons.append("High registry modification rate")
    if features.get("network_connection_count", 0.0) > 5.0:
        reasons.append("High volume of outgoing network connections")

    # Add Sigma rule descriptions
    for match in sigma_matches:
        reasons.append(f"Sigma rule trigger: {match['rule_name']} ({match['severity']} severity)")

    return list(set(reasons))

def fuse_predictions_and_rules(
    ml_risk_score: float,
    sigma_matches: List[Dict[str, Any]],
    features: Dict[str, Any],
    window: Dict[str, Any]
) -> EndpointEvidence:
    """
    Fuses LightGBM Risk Score and Sigma rule matches into a single EndpointEvidence object.
    Neither source dominates:
      - Case 1: High ML (>= 0.75) + High/Med Sigma -> Critical (Risk 0.95+)
      - Case 2: High ML (>= 0.75) + No Sigma -> High/Medium (Risk equal to ML)
      - Case 3: Low ML (< 0.75) + High/Med Sigma -> Known Technique (Risk 0.80)
      - Case 4: Low ML (< 0.75) + Low/No Sigma -> Benign / Low deviation (Risk equal to ML)
    """
    has_high_sigma = any(m["severity"] in ["high", "critical", "medium"] for m in sigma_matches)
    has_sigma = len(sigma_matches) > 0

    if ml_risk_score >= 0.75:
        if has_high_sigma:
            # Case 1: High ML + High Sigma (Critical threat)
            risk_score = max(ml_risk_score, 0.95)
            severity = "critical"
            confidence = 0.95
        else:
            # Case 2: High ML + Low/No Sigma (Suspicious Behaviour)
            risk_score = ml_risk_score
            severity = "high" if ml_risk_score >= 0.85 else "medium"
            confidence = 0.75
    else:
        if has_high_sigma:
            # Case 3: Low ML + High Sigma (Known Technique)
            risk_score = 0.80
            severity = "medium"
            confidence = 0.80
        elif has_sigma:
            # Case 4a: Low ML + Low Sigma
            risk_score = max(ml_risk_score, 0.50)
            severity = "low"
            confidence = 0.60
        else:
            # Case 4b: Low ML + No Sigma (Benign)
            risk_score = ml_risk_score
            severity = "low"
            confidence = 0.50

    # Extract ATT&CK details
    mitre_candidates = []
    for match in sigma_matches:
        for tech in match.get("mitre_techniques", []):
            mitre_candidates.append(tech)

    reasons = generate_top_reasons(features, sigma_matches)

    evidence = EndpointEvidence(
        detector="endpoint",
        entity="host",
        host=window.get("host"),
        process=window.get("process"),
        timestamp=window.get("window_end"),
        window_start=window.get("window_start"),
        window_end=window.get("window_end"),
        risk_score=risk_score,
        confidence=confidence,
        severity=severity,
        sigma_hits=sigma_matches,
        mitre_candidates=list(set(mitre_candidates)),
        behavioural_features=features,
        top_reasons=reasons,
        raw_prediction=ml_risk_score
    )

    return evidence
