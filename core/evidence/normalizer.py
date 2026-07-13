import datetime
from typing import Any, Dict, Union
from core.evidence.base_evidence import BaseEvidence
from core.evidence.network_evidence import NetworkEvidence
from core.evidence.identity_evidence import IdentityEvidence
from core.evidence.endpoint_evidence import EndpointEvidence
from core.evidence.ot_evidence import OTEvidence
from core.evidence.schemas import DetectorType
from core.evidence.risk import normalize_score

def normalize_timestamp(timestamp: str) -> str:
    """Converts input timestamp string to standardized ISO 8601 format."""
    if not timestamp:
        return datetime.datetime.now(datetime.timezone.utc).isoformat()
    try:
        iso_str = str(timestamp).replace('Z', '+00:00')
        return datetime.datetime.fromisoformat(iso_str).isoformat()
    except Exception:
        return datetime.datetime.now(datetime.timezone.utc).isoformat()

def normalize_evidence_object(evidence: Union[BaseEvidence, Dict[str, Any]]) -> BaseEvidence:
    """Normalizes all fields in the evidence object, ensuring it satisfies UEF standards

    and returns a typed BaseEvidence (or subclass) instance.
    """
    if isinstance(evidence, dict):
        detector_str = str(evidence.get("detector", "")).upper()
        if detector_str == DetectorType.NETWORK.value:
            inst = NetworkEvidence.from_dict(evidence)
        elif detector_str == DetectorType.IDENTITY.value:
            inst = IdentityEvidence.from_dict(evidence)
        elif detector_str == DetectorType.ENDPOINT.value:
            inst = EndpointEvidence.from_dict(evidence)
        elif detector_str == DetectorType.OT.value:
            inst = OTEvidence.from_dict(evidence)
        else:
            inst = BaseEvidence.from_dict(evidence)
    else:
        inst = evidence

    # Normalize basic fields
    inst.detector = str(inst.detector).upper()
    inst.entity = str(inst.entity).strip()
    inst.entity_type = str(inst.entity_type).upper()
    inst.severity = str(inst.severity).upper()

    # Normalize risk & confidence floats
    inst.risk_score = normalize_score(inst.risk_score)
    inst.confidence = normalize_score(inst.confidence)

    # Normalize times
    inst.timestamp = normalize_timestamp(inst.timestamp)
    if inst.window_start:
        inst.window_start = normalize_timestamp(inst.window_start)
    if inst.window_end:
        inst.window_end = normalize_timestamp(inst.window_end)

    # Clean top_reasons and metadata
    if not isinstance(inst.top_reasons, list):
        inst.top_reasons = []
    inst.top_reasons = [str(r) for r in inst.top_reasons]

    if not isinstance(inst.metadata, dict):
        inst.metadata = {}

    # Perform class-specific normalizations
    if isinstance(inst, NetworkEvidence):
        inst.attack_family = str(inst.attack_family)
        inst.protocol = str(inst.protocol)
        inst.source_ip = str(inst.source_ip)
        inst.destination_ip = str(inst.destination_ip)
        inst.flow_duration = float(inst.flow_duration) if inst.flow_duration else 0.0
        if not isinstance(inst.top_network_features, dict):
            inst.top_network_features = {}
    elif isinstance(inst, IdentityEvidence):
        inst.user = str(inst.user)
        inst.auth_count = int(inst.auth_count) if inst.auth_count else 0
        inst.computer_fanout = int(inst.computer_fanout) if inst.computer_fanout else 0
        inst.new_computer_ratio = float(inst.new_computer_ratio) if inst.new_computer_ratio else 0.0
        inst.off_hours = bool(inst.off_hours)
        if not isinstance(inst.identity_features, dict):
            inst.identity_features = {}
    elif isinstance(inst, EndpointEvidence):
        inst.process = str(inst.process)
        if not isinstance(inst.sigma_hits, list):
            inst.sigma_hits = []
        if not isinstance(inst.mitre_candidates, list):
            inst.mitre_candidates = []
        if not isinstance(inst.endpoint_features, dict):
            inst.endpoint_features = {}
    elif isinstance(inst, OTEvidence):
        if not isinstance(inst.top_shifted_variables, list):
            inst.top_shifted_variables = []
        inst.anomaly_score = float(inst.anomaly_score) if inst.anomaly_score else 0.0
        inst.attack_probability = float(inst.attack_probability) if inst.attack_probability else 0.0
        if not isinstance(inst.sensor_summary, dict) and not isinstance(inst.sensor_summary, str):
            inst.sensor_summary = {}
        if not isinstance(inst.control_summary, dict) and not isinstance(inst.control_summary, str):
            inst.control_summary = {}

    return inst
