import os
import json
import math
import logging
from collections import Counter
from typing import List, Dict, Any
import pandas as pd

logger = logging.getLogger(__name__)

# List of common script interpreters
SCRIPT_INTERPRETERS = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "bash", "sh", "python.exe", "python", "perl.exe", "regini.exe"
}

# List of common LOLBins
LOLBINS = {
    "certutil.exe", "rundll32.exe", "mshta.exe", "regsvr32.exe", "bitsadmin.exe",
    "wmic.exe", "installutil.exe", "wuauclt.exe", "mavinject.exe", "schtasks.exe",
    "scrcons.exe", "hh.exe", "control.exe", "explorer.exe", "verclsid.exe"
}

# Common benign parent-child relationships
COMMON_SPAWNS = {
    ("explorer.exe", "chrome.exe"),
    ("explorer.exe", "iexplore.exe"),
    ("explorer.exe", "explorer.exe"),
    ("services.exe", "svchost.exe"),
    ("services.exe", "spoolsv.exe"),
    ("smss.exe", "csrss.exe"),
    ("smss.exe", "wininit.exe"),
    ("wininit.exe", "services.exe"),
    ("wininit.exe", "lsass.exe"),
}

def calculate_entropy(s: str) -> float:
    if not s:
        return 0.0
    cnt = Counter(s)
    total = len(s)
    return -sum((count / total) * math.log2(count / total) for count in cnt.values())

def build_features_for_window(window: Dict[str, Any]) -> Dict[str, Any]:
    events = window["events"]
    host = window["host"]
    process = window["process"]
    parent_process = window["parent_process"]
    
    # Heuristics
    # Support pandas NaN checks safely
    process_str = str(process) if (process and not pd.isna(process)) else ""
    parent_str = str(parent_process) if (parent_process and not pd.isna(parent_process)) else ""
    
    process_lower = process_str.lower()
    parent_lower = parent_str.lower()
    
    # 1. Process Depth
    process_depth = 2.0 if parent_str else 1.0

    # Find the main command line from the events
    cmd_str = ""
    for ev in events:
        if ev.command_line:
            cmd_str = ev.command_line
            break
            
    cmd_lower = cmd_str.lower()
    
    # 2. Command details
    command_length = float(len(cmd_str))
    command_token_count = float(len(cmd_str.split())) if cmd_str else 0.0
    
    # 3. Encoded command flag
    encoded_flag = 0.0
    for marker in ["-enc", "-encodedcommand", "base64", "-e "]:
        if marker in cmd_lower:
            encoded_flag = 1.0
            break
            
    # 4. PowerShell flag
    powershell_flag = 0.0
    if "powershell" in process_lower or "pwsh" in process_lower or "powershell" in cmd_lower or "pwsh" in cmd_lower:
        powershell_flag = 1.0
        
    # 5. Script Interpreter Flag
    script_interpreter_flag = 1.0 if process_lower in SCRIPT_INTERPRETERS else 0.0
    
    # 6. LOLBin flag
    lolbin_flag = 1.0 if process_lower in LOLBINS else 0.0
    
    # 7. Parent-Child relationship
    parent_child_frequency = 0.0
    for ev in events:
        if ev.parent_process_name and ev.process_name:
            if ev.parent_process_name.lower() == parent_lower and ev.process_name.lower() == process_lower:
                parent_child_frequency += 1.0
                
    parent_child_rarity = 1.0
    if (parent_lower, process_lower) in COMMON_SPAWNS:
        parent_child_rarity = 0.0

    # 8. Event subcategory counts
    child_process_count = 0.0
    unique_child_procs = set()
    network_connection_count = 0.0
    unique_destinations = set()
    destination_ports = set()
    dns_query_count = 0.0
    registry_modification_count = 0.0
    registry_create_count = 0.0
    file_create_count = 0.0
    image_load_count = 0.0
    process_access_count = 0.0
    lsass_access_count = 0.0
    remote_thread_count = 0.0
    granted_access_entropy = 0.0
    integrity_levels = set()
    users = set()
    rare_image_load_count = 0.0
    
    for ev in events:
        eid = ev.event_id
        if ev.integrity_level:
            integrity_levels.add(ev.integrity_level)
        if ev.user:
            users.add(ev.user)

        # Process creation events (Event ID 1)
        if eid == "1":
            child_process_count += 1.0
            if ev.process_name:
                unique_child_procs.add(ev.process_name)
                
        # Network connection events (Event ID 3)
        elif eid == "3":
            network_connection_count += 1.0
            if ev.destination_ip:
                unique_destinations.add(ev.destination_ip)
            if ev.destination_port is not None:
                destination_ports.add(ev.destination_port)
                
        # DLL image load events (Event ID 7)
        elif eid == "7":
            image_load_count += 1.0
            img_loaded = ev.image_loaded or ""
            img_lower = img_loaded.lower()
            # If loaded from temp/public/appdata directories
            if any(p in img_lower for p in ["\\temp\\", "\\public\\", "\\appdata\\", "\\users\\"]):
                rare_image_load_count += 1.0
                
        # Remote thread creation events (Event ID 8)
        elif eid == "8":
            remote_thread_count += 1.0
            
        # Process access events (Event ID 10)
        elif eid == "10":
            process_access_count += 1.0
            if ev.granted_access:
                granted_access_entropy = max(granted_access_entropy, calculate_entropy(ev.granted_access))
            target_p = ev.target_process or ""
            if "lsass" in target_p.lower():
                lsass_access_count += 1.0
                
        # File creation events (Event ID 11)
        elif eid == "11":
            file_create_count += 1.0
            
        # Registry key modification events (Event ID 12, 13, 14)
        elif eid in ["12", "13", "14"]:
            registry_modification_count += 1.0
            if eid in ["12", "13"]:
                registry_create_count += 1.0
                
        # DNS query events (Event ID 22)
        elif eid == "22":
            dns_query_count += 1.0

    unique_child_processes = float(len(unique_child_procs))
    unique_destination_count = float(len(unique_destinations))
    destination_port_count = float(len(destination_ports))
    integrity_level_change = 1.0 if len(integrity_levels) > 1 else 0.0
    cross_user_process_count = float(len(users))

    return {
        "window_id": window["window_id"],
        "host": host,
        "process": process,
        "parent_process": parent_process,
        "window_start": window["window_start"],
        "window_end": window["window_end"],
        "event_count": float(window["event_count"]),
        "process_depth": process_depth,
        "child_process_count": child_process_count,
        "unique_child_processes": unique_child_processes,
        "parent_child_frequency": parent_child_frequency,
        "parent_child_rarity": parent_child_rarity,
        "command_length": command_length,
        "command_token_count": command_token_count,
        "encoded_command_flag": encoded_flag,
        "powershell_flag": powershell_flag,
        "script_interpreter_flag": script_interpreter_flag,
        "lolbin_flag": lolbin_flag,
        "network_connection_count": network_connection_count,
        "unique_destination_count": unique_destination_count,
        "destination_port_count": destination_port_count,
        "dns_query_count": dns_query_count,
        "registry_modification_count": registry_modification_count,
        "registry_create_count": registry_create_count,
        "file_create_count": file_create_count,
        "image_load_count": image_load_count,
        "process_access_count": process_access_count,
        "lsass_access_count": lsass_access_count,
        "remote_thread_count": remote_thread_count,
        "granted_access_entropy": granted_access_entropy,
        "integrity_level_change": integrity_level_change,
        "cross_user_process_count": cross_user_process_count,
        "rare_image_load_count": rare_image_load_count
    }

FEATURE_CONTRACT = {
    "process_depth": {"dtype": "float64", "description": "Depth of process in execution hierarchy (2 if parent exists, else 1)", "normalization": "none", "allowed_null": False},
    "child_process_count": {"dtype": "float64", "description": "Number of process spawn events inside the window", "normalization": "none", "allowed_null": False},
    "unique_child_processes": {"dtype": "float64", "description": "Number of unique process names spawned as children in this window", "normalization": "none", "allowed_null": False},
    "parent_child_frequency": {"dtype": "float64", "description": "Frequency count of the parent-child pair in events", "normalization": "none", "allowed_null": False},
    "parent_child_rarity": {"dtype": "float64", "description": "Rarity score of the parent-child combination (1.0 if rare/unknown, 0.0 if common)", "normalization": "none", "allowed_null": False},
    "command_length": {"dtype": "float64", "description": "Length of process command line string", "normalization": "none", "allowed_null": False},
    "command_token_count": {"dtype": "float64", "description": "Number of whitespace-separated tokens in command line", "normalization": "none", "allowed_null": False},
    "encoded_command_flag": {"dtype": "float64", "description": "Flag representing potential base64 or encoded execution commands", "normalization": "none", "allowed_null": False},
    "powershell_flag": {"dtype": "float64", "description": "Flag representing execution involving PowerShell/pwsh", "normalization": "none", "allowed_null": False},
    "script_interpreter_flag": {"dtype": "float64", "description": "Flag indicating process name is a script interpreter", "normalization": "none", "allowed_null": False},
    "lolbin_flag": {"dtype": "float64", "description": "Flag representing process matches a recognized LOLBin", "normalization": "none", "allowed_null": False},
    "network_connection_count": {"dtype": "float64", "description": "Number of network connections observed", "normalization": "none", "allowed_null": False},
    "unique_destination_count": {"dtype": "float64", "description": "Number of unique destination IP addresses", "normalization": "none", "allowed_null": False},
    "destination_port_count": {"dtype": "float64", "description": "Number of unique destination ports", "normalization": "none", "allowed_null": False},
    "dns_query_count": {"dtype": "float64", "description": "Number of DNS queries issued", "normalization": "none", "allowed_null": False},
    "registry_modification_count": {"dtype": "float64", "description": "Number of registry modifications (creates, deletes, sets)", "normalization": "none", "allowed_null": False},
    "registry_create_count": {"dtype": "float64", "description": "Number of registry keys or values created", "normalization": "none", "allowed_null": False},
    "file_create_count": {"dtype": "float64", "description": "Number of file creation operations", "normalization": "none", "allowed_null": False},
    "image_load_count": {"dtype": "float64", "description": "Number of image/DLL load events", "normalization": "none", "allowed_null": False},
    "process_access_count": {"dtype": "float64", "description": "Number of times this process accessed another process", "normalization": "none", "allowed_null": False},
    "lsass_access_count": {"dtype": "float64", "description": "Number of process accesses specifically targeting LSASS memory", "normalization": "none", "allowed_null": False},
    "remote_thread_count": {"dtype": "float64", "description": "Number of remote threads created", "normalization": "none", "allowed_null": False},
    "granted_access_entropy": {"dtype": "float64", "description": "Character entropy of the process granted access mask", "normalization": "none", "allowed_null": False},
    "integrity_level_change": {"dtype": "float64", "description": "Flag indicating multiple integrity levels occurred within the window", "normalization": "none", "allowed_null": False},
    "cross_user_process_count": {"dtype": "float64", "description": "Number of unique users associated with events in the window", "normalization": "none", "allowed_null": False},
    "rare_image_load_count": {"dtype": "float64", "description": "Number of images loaded from temp/appdata/public directories", "normalization": "none", "allowed_null": False}
}

def save_features(feature_rows: List[Dict[str, Any]], output_parquet_path: str, contract_json_path: str) -> None:
    df = pd.DataFrame(feature_rows)
    os.makedirs(os.path.dirname(output_parquet_path), exist_ok=True)
    os.makedirs(os.path.dirname(contract_json_path), exist_ok=True)
    
    # Save Parquet
    df.to_parquet(output_parquet_path, index=False)
    logger.info(f"Saved {len(df)} feature rows to Parquet: {output_parquet_path}")

    # Save feature contract
    with open(contract_json_path, "w", encoding="utf-8") as f:
        json.dump(FEATURE_CONTRACT, f, indent=2)
    logger.info(f"Saved feature contract to: {contract_json_path}")
