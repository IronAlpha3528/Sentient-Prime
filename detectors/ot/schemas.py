from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional

@dataclass
class DatasetManifest:
    file_path: str
    relative_path: str
    row_estimate: int
    column_count: int
    file_size_bytes: int
    timestamp_column: Optional[str] = None
    label_column: Optional[str] = None
    sampling_interval_seconds: Optional[float] = None

@dataclass
class NormalizedOTRow:
    timestamp: str
    window_index: int
    attack_label: int
    sensor_values: Dict[str, float] = field(default_factory=dict)
    actuator_states: Dict[str, float] = field(default_factory=dict)
    controller_states: Dict[str, float] = field(default_factory=dict)
    setpoints: Dict[str, float] = field(default_factory=dict)
    status_flags: Dict[str, float] = field(default_factory=dict)
    raw_row: Dict[str, Any] = field(default_factory=dict)

@dataclass
class WindowMetadata:
    window_id: str
    start_time: str
    end_time: str
    host: str
    label: int
    duration_seconds: float
    row_count: int
    attack_ratio: float
