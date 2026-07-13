from dataclasses import dataclass, field
from typing import Dict, Any
from core.evidence.base_evidence import BaseEvidence

@dataclass
class NetworkEvidence(BaseEvidence):
    attack_family: str = "unknown"
    protocol: str = "unknown"
    source_ip: str = "0.0.0.0"
    destination_ip: str = "0.0.0.0"
    flow_duration: float = 0.0
    top_network_features: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.detector:
            self.detector = "NETWORK"
        if not self.entity_type:
            self.entity_type = "NETWORK_FLOW"
