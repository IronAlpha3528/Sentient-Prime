from dataclasses import dataclass, field, asdict
from typing import Any, Optional, List, Dict

@dataclass
class EndpointEvidence:
    detector: str = "endpoint"
    entity: str = "host"
    host: Optional[str] = None
    process: Optional[str] = None
    timestamp: Optional[str] = None
    window_start: Optional[str] = None
    window_end: Optional[str] = None
    risk_score: float = 0.0
    confidence: float = 0.0
    severity: str = "low"
    sigma_hits: List[Dict[str, Any]] = field(default_factory=list)
    mitre_candidates: List[str] = field(default_factory=list)
    behavioural_features: Dict[str, Any] = field(default_factory=dict)
    top_reasons: List[str] = field(default_factory=list)
    raw_prediction: float = 0.0
    schema_version: str = "1.0.0"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
