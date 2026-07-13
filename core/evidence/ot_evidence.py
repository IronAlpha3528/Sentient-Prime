from dataclasses import dataclass, field
from typing import Dict, Any, List, Union
from core.evidence.base_evidence import BaseEvidence

@dataclass
class OTEvidence(BaseEvidence):
    top_shifted_variables: List[str] = field(default_factory=list)
    anomaly_score: float = 0.0
    attack_probability: float = 0.0
    sensor_summary: Union[Dict[str, Any], str] = field(default_factory=dict)
    control_summary: Union[Dict[str, Any], str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.detector:
            self.detector = "OT"
        if not self.entity_type:
            self.entity_type = "DEVICE"
        if not self.entity:
            self.entity = "CNI-Process-PLC"
