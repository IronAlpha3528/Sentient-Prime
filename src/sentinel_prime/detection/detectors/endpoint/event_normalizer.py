import os
import logging
from typing import Dict, Any, Optional, Tuple
from pathlib import Path
from collections import defaultdict

from sentinel_prime.detection.detectors.endpoint.schemas import EndpointEvent
from sentinel_prime.detection.detectors.endpoint.field_mapper import find_alias_value

logger = logging.getLogger(__name__)

# Statistics trackers
discard_counts = defaultdict(int)
provider_counts = defaultdict(int)
event_id_counts = defaultdict(int)

def clear_stats() -> None:
    discard_counts.clear()
    provider_counts.clear()
    event_id_counts.clear()

def get_stats() -> Dict[str, Dict[str, int]]:
    return {
        "discards": dict(discard_counts),
        "providers": dict(provider_counts),
        "event_ids": dict(event_id_counts)
    }

def get_basename(path_str: Optional[str]) -> Optional[str]:
    if not path_str:
        return None
    # Handle Windows backslashes and Unix forward slashes
    normalized = path_str.replace("\\", "/")
    parts = normalized.split("/")
    return parts[-1] if parts else None

def cast_to_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        if isinstance(value, (int, float)):
            return int(value)
        # Handle hex strings (e.g. 0x4)
        val_str = str(value).strip()
        if val_str.lower().startswith("0x"):
            return int(val_str, 16)
        return int(val_str)
    except Exception:
        return None

def normalize_event(raw_event: Dict[str, Any]) -> Tuple[Optional[EndpointEvent], Optional[str]]:
    """
    Normalizes a raw dictionary event to EndpointEvent.
    Returns (EndpointEvent, None) on success, or (None, discard_reason) on failure.
    """
    if not raw_event or not isinstance(raw_event, dict):
        discard_counts["empty_or_not_dict"] += 1
        return None, "empty_or_not_dict"

    # Extract required timestamp
    ts = find_alias_value(raw_event, "timestamp")
    if not ts:
        discard_counts["missing_timestamp"] += 1
        return None, "missing_timestamp"
    
    # Extract remaining fields
    host = find_alias_value(raw_event, "host")
    user = find_alias_value(raw_event, "user")
    provider = find_alias_value(raw_event, "provider")
    channel = find_alias_value(raw_event, "channel")
    event_id_raw = find_alias_value(raw_event, "event_id")
    event_id = str(event_id_raw) if event_id_raw is not None else None

    # Process and Parent Process Name / Image Path resolution
    raw_img = find_alias_value(raw_event, "image_path")
    process_name = get_basename(raw_img) if raw_img else find_alias_value(raw_event, "process_name")
    if process_name and ("\\" in str(process_name) or "/" in str(process_name)):
        process_name = get_basename(str(process_name))

    raw_parent_img = find_alias_value(raw_event, "parent_process_name")
    parent_process_name = raw_parent_img
    if parent_process_name and ("\\" in str(parent_process_name) or "/" in str(parent_process_name)):
        parent_process_name = get_basename(str(parent_process_name))

    process_id = cast_to_int(find_alias_value(raw_event, "process_id"))
    parent_process_id = cast_to_int(find_alias_value(raw_event, "parent_process_id"))

    command_line = find_alias_value(raw_event, "command_line")
    parent_command_line = find_alias_value(raw_event, "parent_command_line")

    # Additional fields
    integrity_level = find_alias_value(raw_event, "integrity_level")
    hashes = find_alias_value(raw_event, "hashes")
    target_process = find_alias_value(raw_event, "target_process")
    granted_access = find_alias_value(raw_event, "granted_access")
    destination_ip = find_alias_value(raw_event, "destination_ip")
    destination_port = cast_to_int(find_alias_value(raw_event, "destination_port"))
    dns_query = find_alias_value(raw_event, "dns_query")
    registry_path = find_alias_value(raw_event, "registry_path")
    file_path = find_alias_value(raw_event, "file_path")
    image_loaded = find_alias_value(raw_event, "image_loaded")

    # We must filter out unrelated metadata or control/non-endpoint logs.
    # If no provider/channel/event_id is present, it might be unrelated metadata.
    if not provider and not channel and not event_id and not process_name:
        discard_counts["unrelated_metadata"] += 1
        return None, "unrelated_metadata"

    # Track metrics
    prov_str = str(provider) if provider else "Unknown"
    provider_counts[prov_str] += 1
    if event_id:
        event_id_counts[event_id] += 1

    event = EndpointEvent(
        timestamp=str(ts),
        host=str(host) if host else None,
        user=str(user) if user else None,
        provider=prov_str,
        channel=str(channel) if channel else None,
        event_id=event_id,
        process_name=str(process_name) if process_name else None,
        parent_process_name=str(parent_process_name) if parent_process_name else None,
        process_id=process_id,
        parent_process_id=parent_process_id,
        command_line=str(command_line) if command_line else None,
        parent_command_line=str(parent_command_line) if parent_command_line else None,
        image_path=str(raw_img) if raw_img else None,
        integrity_level=str(integrity_level) if integrity_level else None,
        hashes=str(hashes) if hashes else None,
        target_process=str(target_process) if target_process else None,
        granted_access=str(granted_access) if granted_access else None,
        destination_ip=str(destination_ip) if destination_ip else None,
        destination_port=destination_port,
        dns_query=str(dns_query) if dns_query else None,
        registry_path=str(registry_path) if registry_path else None,
        file_path=str(file_path) if file_path else None,
        image_loaded=str(image_loaded) if image_loaded else None,
        raw_event=raw_event
    )

    return event, None
