import json
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional

@dataclass
class OTEvidence:
    detector: str = "ot"
    entity: str = "CNI-Process-PLC"
    timestamp: str = ""
    window_start: str = ""
    window_end: str = ""
    risk_score: float = 0.0
    confidence: float = 0.0
    severity: str = "LOW"
    anomaly_score: float = 0.0
    attack_probability: float = 0.0
    top_shifted_variables: List[str] = field(default_factory=list)
    behaviour_summary: str = ""
    top_reasons: List[str] = field(default_factory=list)
    raw_prediction: float = 0.0
    schema_version: str = "v2.1"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detector": self.detector,
            "entity": self.entity,
            "timestamp": self.timestamp,
            "window_start": self.window_start,
            "window_end": self.window_end,
            "risk_score": float(self.risk_score),
            "confidence": float(self.confidence),
            "severity": self.severity.upper(),
            "anomaly_score": float(self.anomaly_score),
            "attack_probability": float(self.attack_probability),
            "top_shifted_variables": self.top_shifted_variables,
            "behaviour_summary": self.behaviour_summary,
            "top_reasons": self.top_reasons,
            "raw_prediction": float(self.raw_prediction),
            "schema_version": self.schema_version
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)
