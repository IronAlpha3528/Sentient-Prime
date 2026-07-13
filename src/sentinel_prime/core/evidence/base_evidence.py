from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional

@dataclass
class BaseEvidence:
    detector: str
    entity: str
    entity_type: str
    timestamp: str
    window_start: str
    window_end: str
    confidence: float
    risk_score: float
    severity: str
    schema_version: str = "v1"
    top_reasons: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def validate(self) -> Any:
        """Validates the evidence object, returning a ValidationResult."""
        from core.evidence.validator import validate_evidence
        return validate_evidence(self)

    def to_dict(self) -> Dict[str, Any]:
        """Converts the evidence object to a dictionary."""
        return asdict(self)

    def to_json(self, indent: Optional[int] = None) -> str:
        """Converts the evidence object to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BaseEvidence':
        """Instantiates the class from a dictionary, mapping only valid fields."""
        import inspect
        sig = inspect.signature(cls)
        valid_fields = {}
        for k, v in data.items():
            if k in sig.parameters:
                # If field has default factory, keep as is
                valid_fields[k] = v
        # Ensure default fields are present if not in data
        return cls(**valid_fields)

    @classmethod
    def from_json(cls, json_str: str) -> 'BaseEvidence':
        """Instantiates the class from a JSON string."""
        data = json.loads(json_str)
        return cls.from_dict(data)

    def summary(self) -> str:
        """Returns a single-line summary of the evidence."""
        reasons_part = f" Reasons: {', '.join(self.top_reasons)}" if self.top_reasons else ""
        return (
            f"[{self.detector}] Entity {self.entity} ({self.entity_type}) - "
            f"Risk: {self.risk_score:.2f}, Confidence: {self.confidence:.2f}, "
            f"Severity: {self.severity}.{reasons_part}"
        )

    def pretty_print(self) -> None:
        """Prints a human-readable JSON representation of the evidence."""
        print(self.to_json(indent=2))
