import os
from typing import Dict, Any, List, Optional

FIELD_ALIASES = {
    "timestamp": ["UtcTime", "@timestamp", "timestamp", "TimeCreated", "SystemTime", "time", "creation_time"],
    "host": ["Computer", "host.name", "computer_name", "ComputerName", "host_name", "host"],
    "user": ["User", "user.name", "user_name", "username", "SubjectUserName", "user"],
    "provider": ["ProviderName", "provider", "event.provider", "Provider_Name", "provider_name"],
    "channel": ["Channel", "winlog.channel", "channel", "ChannelName"],
    "event_id": ["EventID", "event_id", "event.code", "EventId", "event_code"],
    "process_name": ["Image", "process.executable", "process.name", "process_name", "process_path", "SourceImage"],
    "parent_process_name": ["ParentImage", "process.parent.executable", "process.parent.name", "parent_process_name", "parent_process_path"],
    "process_id": ["ProcessId", "process.pid", "process_id", "ProcessID", "SourceProcessId", "SourceProcessID"],
    "parent_process_id": ["ParentProcessId", "process.parent.pid", "parent_process_id", "ParentProcessID"],
    "command_line": ["CommandLine", "process.command_line", "command_line", "process_command_line"],
    "parent_command_line": ["ParentCommandLine", "process.parent.command_line", "parent_command_line", "process_parent_command_line"],
    "image_path": ["Image", "process.executable", "process_path", "SourceImage"],
    "integrity_level": ["IntegrityLevel", "integrity_level", "process.integrity_level"],
    "hashes": ["Hashes", "process.hash", "hashes", "process_hash"],
    "target_process": ["TargetImage", "process.target.executable", "target_image", "process_target_image", "TargetProcessAddress"],
    "granted_access": ["GrantedAccess", "granted_access", "AccessMask", "granted_access_mask"],
    "destination_ip": ["DestinationIp", "destination.ip", "destination_ip", "DestinationIP"],
    "destination_port": ["DestinationPort", "destination.port", "destination_port", "DestinationPortValue"],
    "dns_query": ["QueryName", "dns.question.name", "dns_query", "dns_name", "QueryNameValue"],
    "registry_path": ["TargetObject", "registry.path", "registry_path", "registry_key", "TargetObjectValue"],
    "file_path": ["TargetFilename", "file.path", "file_path", "TargetFile", "TargetFilenameValue"],
    "image_loaded": ["ImageLoaded", "process.thread.image_loaded", "image_loaded"]
}

def extract_nested_value(record: Dict[str, Any], path: str) -> Optional[Any]:
    parts = path.split(".")
    val = record
    for part in parts:
        if isinstance(val, dict):
            val = val.get(part)
        else:
            return None
    return val

def find_alias_value(record: Dict[str, Any], canonical_field: str) -> Optional[Any]:
    aliases = FIELD_ALIASES.get(canonical_field)
    if not aliases:
        return None

    for alias in aliases:
        # Check flat key first (e.g. event.code can be a flat key in CSV/some JSON formats)
        if alias in record:
            return record[alias]
            
        if "." in alias:
            val = extract_nested_value(record, alias)
            if val is not None:
                return val

    # Special handling for standard nested structures (e.g. Sysmon XML to JSON conversions)
    if canonical_field == "timestamp" and "TimeCreated" in record:
        tc = record["TimeCreated"]
        if isinstance(tc, dict):
            for k in ["SystemTime", "@SystemTime", "timestamp"]:
                if k in tc:
                    return tc[k]

    return None
