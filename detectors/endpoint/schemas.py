from dataclasses import dataclass, field, asdict
from typing import Any, Optional, List, Dict

@dataclass
class ArchiveManifest:
    archive_path: str
    relative_path: str
    archive_size: int
    compressed_size: int
    member_list: List[str] = field(default_factory=list)
    telemetry_files: List[str] = field(default_factory=list)
    metadata_files: List[str] = field(default_factory=list)

@dataclass
class EndpointEvent:
    timestamp: Optional[str] = None
    host: Optional[str] = None
    user: Optional[str] = None
    provider: Optional[str] = None
    channel: Optional[str] = None
    event_id: Optional[str] = None
    process_name: Optional[str] = None
    parent_process_name: Optional[str] = None
    process_id: Optional[int] = None
    parent_process_id: Optional[int] = None
    command_line: Optional[str] = None
    parent_command_line: Optional[str] = None
    image_path: Optional[str] = None
    integrity_level: Optional[str] = None
    hashes: Optional[str] = None
    target_process: Optional[str] = None
    granted_access: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    dns_query: Optional[str] = None
    registry_path: Optional[str] = None
    file_path: Optional[str] = None
    image_loaded: Optional[str] = None
    raw_event: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
