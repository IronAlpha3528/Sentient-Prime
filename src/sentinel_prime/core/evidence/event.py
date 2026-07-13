import datetime
from enum import Enum
import uuid
from dataclasses import dataclass
from typing import Any, Dict

class EventPriority(str, Enum):
    LOW = "LOW"
    NORMAL = "NORMAL"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class EventStatus(str, Enum):
    CREATED = "CREATED"
    VALIDATED = "VALIDATED"
    QUEUED = "QUEUED"
    PROCESSING = "PROCESSING"
    PROCESSED = "PROCESSED"
    FAILED = "FAILED"
    ARCHIVED = "ARCHIVED"

PRIORITY_VALUES = {
    EventPriority.LOW: 1,
    EventPriority.NORMAL: 2,
    EventPriority.HIGH: 3,
    EventPriority.CRITICAL: 4
}

@dataclass
class EvidenceEvent:
    event_id: str
    timestamp: str
    detector: str
    entity: str
    payload: Dict[str, Any]
    priority: EventPriority
    status: EventStatus
    retry_count: int = 0
    version: str = "v1"

    @classmethod
    def wrap(cls, evidence_dict: Dict[str, Any], priority: EventPriority = EventPriority.NORMAL) -> 'EvidenceEvent':
        """Wraps a standardized evidence dictionary into a new EvidenceEvent."""
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
        return cls(
            event_id=str(uuid.uuid4()),
            timestamp=now_str,
            detector=str(evidence_dict.get("detector", "UNKNOWN")),
            entity=str(evidence_dict.get("entity", "unknown")),
            payload=evidence_dict,
            priority=priority,
            status=EventStatus.CREATED
        )

    def to_dict(self) -> Dict[str, Any]:
        """Converts the event into a standard dictionary structure."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "detector": self.detector,
            "entity": self.entity,
            "payload": self.payload,
            "priority": self.priority.value,
            "status": self.status.value,
            "retry_count": self.retry_count,
            "version": self.version
        }
