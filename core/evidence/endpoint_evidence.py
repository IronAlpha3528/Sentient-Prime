from dataclasses import dataclass, field
from typing import Dict, Any, List
from core.evidence.base_evidence import BaseEvidence

@dataclass
class EndpointEvidence(BaseEvidence):
    process: str = "unknown"
    sigma_hits: List[Dict[str, Any]] = field(default_factory=list)
    mitre_candidates: List[str] = field(default_factory=list)
    endpoint_features: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.detector:
            self.detector = "ENDPOINT"
        if not self.entity_type:
            self.entity_type = "HOST"
