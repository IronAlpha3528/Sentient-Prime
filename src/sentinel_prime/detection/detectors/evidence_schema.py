from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class DetectorEvidence:
    """Unified Phase-1 detector output consumed by later correlation/AI stages."""

    detector: str
    entity_type: str
    entity_id: str
    score: float
    classification: str
    features: dict[str, Any]
    evidence: list[dict[str, Any]] = field(default_factory=list)
    model_version: str = "unknown"
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
