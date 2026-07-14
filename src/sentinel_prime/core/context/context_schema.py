import json
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Tuple

@dataclass
class CorrelationContext:
    """The final AI-ready context payload containing local subgraph states,

    chronological evidence timelines, and deterministic text summaries.
    """
    context_id: str
    entity: str
    time_window: Tuple[str, str]
    related_entities: List[str] = field(default_factory=list)
    related_events: List[Dict[str, Any]] = field(default_factory=list)
    graph_paths: List[List[str]] = field(default_factory=list)
    risk_summary: str = ""
    supporting_evidence: List[Dict[str, Any]] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    incident_id: str = ""
    entities: Dict[str, List[str]] = field(default_factory=dict)
    relationships: List[Dict[str, Any]] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    threat_intel: List[Dict[str, Any]] = field(default_factory=list)
    graph_subgraph: Dict[str, Any] = field(default_factory=dict)
    historical_incidents: List[Dict[str, Any]] = field(default_factory=list)
    confidence_summary: str = ""
    monitoring_snapshot: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Converts the correlation context to a dictionary."""
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        """Converts the correlation context to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def to_markdown(self) -> str:
        """Serializes the context into a clean markdown format for direct prompt injection."""
        timeline_md = ""
        for idx, entry in enumerate(self.timeline, start=1):
            timeline_md += f"{idx}. **[{entry.get('timestamp')}]** {entry.get('description')} (Risk: {entry.get('risk', 0.0):.2f}, Conf: {entry.get('confidence', 1.0):.2f})\n"

        related_md = ", ".join(self.related_entities) if self.related_entities else "None"
        
        md = f"""# Correlation Security Context: {self.entity}
**Context ID**: `{self.context_id}`
**Incident ID**: `{self.incident_id}`
**Temporal Scope**: {self.time_window[0]} to {self.time_window[1]}

## Risk Assessment
{self.risk_summary}

## Attack Timeline Chain
{timeline_md if timeline_md else "No timeline entries recorded."}

## Graph Connections
- **Connected Entities**: {related_md}
- **Observed Paths**: {self.graph_paths if self.graph_paths else "None"}

## Supporting Telemetry Features
"""
        for idx, ev in enumerate(self.supporting_evidence, start=1):
            md += f"- **[{ev.get('detector')}]** Entity: {ev.get('entity')} | Severity: {ev.get('severity')} | Risk Score: {ev.get('risk_score', 0.0):.2f}\n"

        if self.threat_intel:
            md += "\n## Threat Intelligence Enrichment\n"
            for ti in self.threat_intel:
                md += f"- **[{ti.get('technique_id')}] {ti.get('name')}**: {ti.get('description')} (Match Score: {ti.get('score', 0.0):.4f})\n"

        if self.monitoring_snapshot:
            md += "\n## Monitoring & Pipeline Status\n"
            md += f"- **Pipeline Status**: {self.monitoring_snapshot.get('pipeline_status')}\n"
            md += f"- **Total Events Processed**: {self.monitoring_snapshot.get('evidence_counts')}\n"
            md += f"- **Queue Depth**: {self.monitoring_snapshot.get('current_queue_size')}\n"

        return md

    def save(self, path: str) -> None:
        """Saves context JSON to path."""
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_json())

    @classmethod
    def load(cls, path: str) -> 'CorrelationContext':
        """Loads context JSON from path."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        # Rebuild tuple for time_window
        tw = data.get("time_window")
        if tw:
            data["time_window"] = (tw[0], tw[1])
            
        return cls(**data)
