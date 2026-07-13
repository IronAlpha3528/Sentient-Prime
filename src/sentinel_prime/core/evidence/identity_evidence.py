from dataclasses import dataclass, field
from typing import Dict, Any
from sentinel_prime.core.evidence.base_evidence import BaseEvidence

@dataclass
class IdentityEvidence(BaseEvidence):
    user: str = "unknown"
    auth_count: int = 0
    computer_fanout: int = 0
    new_computer_ratio: float = 0.0
    off_hours: bool = False
    identity_features: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.detector:
            self.detector = "IDENTITY"
        if not self.entity_type:
            self.entity_type = "USER"
        if not self.entity:
            self.entity = self.user
