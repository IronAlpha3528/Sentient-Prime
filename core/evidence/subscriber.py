from abc import ABC, abstractmethod
import datetime
import logging
from typing import List, Optional, Tuple
from core.evidence.event import EvidenceEvent

logger = logging.getLogger(__name__)

class SubscriberFilter:
    """Filter class to route only matching EvidenceEvents to a subscriber."""

    def __init__(
        self,
        detectors: Optional[List[str]] = None,
        severities: Optional[List[str]] = None,
        priorities: Optional[List[str]] = None,
        entities: Optional[List[str]] = None,
        entity_types: Optional[List[str]] = None,
        min_risk_score: Optional[float] = None,
        time_window: Optional[Tuple[str, str]] = None  # (start_iso, end_iso)
    ):
        self.detectors = [d.upper() for d in detectors] if detectors else None
        self.severities = [s.upper() for s in severities] if severities else None
        self.priorities = [p.upper() for p in priorities] if priorities else None
        self.entities = entities if entities else None
        self.entity_types = [et.upper() for et in entity_types] if entity_types else None
        self.min_risk_score = min_risk_score
        self.time_window = time_window

    def matches(self, event: EvidenceEvent) -> bool:
        """Evaluates whether an EvidenceEvent meets all filter criteria."""
        if self.detectors and event.detector.upper() not in self.detectors:
            return False

        severity = str(event.payload.get("severity", "")).upper()
        if self.severities and severity not in self.severities:
            return False

        if self.priorities and event.priority.upper() not in self.priorities:
            return False

        if self.entities and event.entity not in self.entities:
            return False

        entity_type = str(event.payload.get("entity_type", "")).upper()
        if self.entity_types and entity_type not in self.entity_types:
            return False

        risk_score = float(event.payload.get("risk_score", 0.0))
        if self.min_risk_score is not None and risk_score < self.min_risk_score:
            return False

        if self.time_window:
            start_str, end_str = self.time_window
            try:
                ev_time = datetime.datetime.fromisoformat(event.timestamp.replace('Z', '+00:00'))
                start_dt = datetime.datetime.fromisoformat(start_str.replace('Z', '+00:00'))
                end_dt = datetime.datetime.fromisoformat(end_str.replace('Z', '+00:00'))
                if not (start_dt <= ev_time <= end_dt):
                    return False
            except Exception as e:
                logger.debug(f"Time filter parsing exception: {e}")
                # Pass check if timezone/datetime format cannot be evaluated
                pass

        return True

class Subscriber(ABC):
    """Abstract Base Class for all Evidence Bus subscribers."""

    def __init__(self, name: str, filter_criteria: Optional[SubscriberFilter] = None):
        self.name = name
        self.filter_criteria = filter_criteria or SubscriberFilter()
        self.is_subscribed = False

    @abstractmethod
    def receive(self, event: EvidenceEvent) -> None:
        """Called by the EvidenceBus when a matching event is published."""
        pass

    @abstractmethod
    def health(self) -> str:
        """Returns subscriber health diagnostics (e.g. 'Healthy', 'Degraded')."""
        pass

    def matches(self, event: EvidenceEvent) -> bool:
        """Checks if the event matches the subscriber's filter settings."""
        return self.filter_criteria.matches(event)

# Interface definitions for future modules (Task S8)
class CorrelationAgent(Subscriber):
    def receive(self, event: EvidenceEvent) -> None:
        raise NotImplementedError("CorrelationAgent subscriber logic not implemented.")
    def health(self) -> str:
        return "Interface Interface Placeholder"

class MITRERAG(Subscriber):
    def receive(self, event: EvidenceEvent) -> None:
        raise NotImplementedError("MITRERAG subscriber logic not implemented.")
    def health(self) -> str:
        return "Interface Interface Placeholder"

class GraphBuilder(Subscriber):
    def receive(self, event: EvidenceEvent) -> None:
        raise NotImplementedError("GraphBuilder subscriber logic not implemented.")
    def health(self) -> str:
        return "Interface Interface Placeholder"

class Dashboard(Subscriber):
    def receive(self, event: EvidenceEvent) -> None:
        raise NotImplementedError("Dashboard subscriber logic not implemented.")
    def health(self) -> str:
        return "Interface Interface Placeholder"

class Logger(Subscriber):
    def receive(self, event: EvidenceEvent) -> None:
        raise NotImplementedError("Logger subscriber logic not implemented.")
    def health(self) -> str:
        return "Interface Interface Placeholder"

class PredictionAgent(Subscriber):
    def receive(self, event: EvidenceEvent) -> None:
        raise NotImplementedError("PredictionAgent subscriber logic not implemented.")
    def health(self) -> str:
        return "Interface Interface Placeholder"

class DecisionAgent(Subscriber):
    def receive(self, event: EvidenceEvent) -> None:
        raise NotImplementedError("DecisionAgent subscriber logic not implemented.")
    def health(self) -> str:
        return "Interface Interface Placeholder"

class HoneyPotManager(Subscriber):
    def receive(self, event: EvidenceEvent) -> None:
        raise NotImplementedError("HoneyPotManager subscriber logic not implemented.")
    def health(self) -> str:
        return "Interface Interface Placeholder"
