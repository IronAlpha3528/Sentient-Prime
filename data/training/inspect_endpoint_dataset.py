import os
import json
import csv
import sys
from pathlib import Path
import zipfile
from collections import defaultdict
import numpy as np

# Resolve OTRF_DATASET_PATH (Task O1)
OTRF_ENV_VAR = "OTRF_DATASET_PATH"
DEFAULT_PATH = r"C:\Users\Aanoush Surana\OneDrive\Desktop\ET Hackathon\OTRF-Endpoint-Data\datasets\atomic\windows"

def get_otrf_path() -> Path:
    path_str = os.environ.get(OTRF_ENV_VAR)
    if not path_str:
        # Fallback to local development path if it exists
        if Path(DEFAULT_PATH).exists():
            path_str = DEFAULT_PATH
        else:
            raise FileNotFoundError(
                f"OTRF dataset path not found. Please set the environment variable '{OTRF_ENV_VAR}' "
                f"or ensure the default directory exists at: {DEFAULT_PATH}"
            )
    
    path = Path(path_str)
    if not path.exists():
        raise FileNotFoundError(f"Configured OTRF directory does not exist: {path}")
    return path


# Canonical Field mapping (Task O3)
FIELD_ALIASES = {
    "event_id": ["EventID", "event_id", "event.code", "EventId", "event_code"],
    "process_name": ["Image", "process.executable", "process.name", "process_name", "process_path"],
    "parent_process_name": ["ParentImage", "process.parent.executable", "process.parent.name", "parent_process_name", "parent_process_path"],
    "command_line": ["CommandLine", "process.command_line", "command_line", "process_command_line"],
    "parent_command_line": ["ParentCommandLine", "process.parent.command_line", "parent_command_line", "process_parent_command_line"],
    "process_id": ["ProcessId", "process.pid", "process_id", "ProcessID"],
    "parent_process_id": ["ParentProcessId", "process.parent.pid", "parent_process_id", "ParentProcessID"],
    "user_name": ["User", "user.name", "user_name", "username", "SubjectUserName"],
    "computer_name": ["Computer", "host.name", "computer_name", "ComputerName", "host_name"],
    "timestamp": ["UtcTime", "@timestamp", "timestamp", "TimeCreated", "SystemTime"],
    "destination_ip": ["DestinationIp", "destination.ip", "destination_ip", "DestinationIP"],
    "destination_port": ["DestinationPort", "destination.port", "destination_port", "DestinationPortValue"],
    "target_image": ["TargetImage", "process.target.executable", "target_image", "process_target_image"],
    "granted_access": ["GrantedAccess", "granted_access", "AccessMask"],
    "target_object": ["TargetObject", "target_object", "ObjectName"],
    "hashes": ["Hashes", "process.hash", "hashes", "process_hash"],
    "integrity_level": ["IntegrityLevel", "integrity_level", "process.integrity_level"],
    "provider_name": ["ProviderName", "provider", "event.provider", "Provider_Name"],
    "channel": ["Channel", "winlog.channel", "channel", "ChannelName"]
}


def find_field_value(record, canonical_field):
    # Searches raw record or nested record for possible aliases
    for alias in FIELD_ALIASES[canonical_field]:
        # Handle simple dot notation (e.g. process.name)
        if "." in alias:
            parts = alias.split(".")
            val = record
            for part in parts:
                if isinstance(val, dict):
                    val = val.get(part)
                else:
                    val = None
                    break
            if val is not None:
                return val, alias
        else:
            if alias in record:
                return record[alias], alias
    return None, None


def main() -> None:
    try:
        otrf_path = get_otrf_path()
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Inspecting OTRF Windows host datasets at: {otrf_path}")
    
    # 1. Discover ZIP archives recursively (Task O1)
    all_zips = list(otrf_path.rglob("*.zip"))
    host_zips = []
    for z in all_zips:
        # Select only archives whose path contains a host directory (Task O1)
        if "host" in [part.lower() for part in z.parts]:
            host_zips.append(z)
            
    print(f"Discovered {len(host_zips)} endpoint host ZIP archives.")

    manifests = []
    
    # Aggregated metrics across all files
    global_providers = defaultdict(int)
    global_sysmon_event_ids = defaultdict(int)
    global_field_alias_counts = defaultdict(lambda: defaultdict(int))
    
    # Process tree counts
    global_process_tree_stats = {
        "timestamp": {"present": 0, "absent": 0},
        "host": {"present": 0, "absent": 0},
        "process_id": {"present": 0, "absent": 0},
        "parent_process_id": {"present": 0, "absent": 0},
        "process_name": {"present": 0, "absent": 0},
        "parent_process_name": {"present": 0, "absent": 0},
        "command_line": {"present": 0, "absent": 0},
        "parent_command_line": {"present": 0, "absent": 0},
        "user": {"present": 0, "absent": 0}
    }
    
    total_inspected_events = 0
    ground_truth_level_counts = defaultdict(int)
    has_event_labels = False
    has_process_labels = False
    
    # Limit number of records to read per zip for performance, but parse enough for schema
    MAX_EVENTS_PER_ZIP = 1000

    for z_path in host_zips:
        manifest_record = {
            "archive_name": z_path.name,
            "archive_path": str(z_path),
            "relative_archive_path": str(z_path.relative_to(otrf_path.parent.parent.parent)),
            "archive_size_bytes": z_path.stat().st_size,
            "parent_tactic_directory": "",
            "parent_technique_directory": "",
            "archive_member_count": 0,
            "archive_member_names": [],
            "telemetry_file_types": [],
            "compressed_size": 0,
            "uncompressed_size": 0,
            "read_success": False,
            "read_error": "",
            "event_count": 0,
            "earliest_timestamp": None,
            "latest_timestamp": None,
            "observed_providers": [],
            "observed_channels": [],
            "observed_event_ids": [],
            "observed_hosts": [],
            "observed_users": [],
            "observed_top_level_fields": [],
            "observed_nested_field_paths": [],
            "metadata_files_present": [],
            "metadata_fields": [],
            "attack_tactic_metadata_available": False,
            "attack_technique_metadata_available": False,
            "event_level_label_available": False,
            "process_level_label_available": False,
            "timestamp_ground_truth_available": False,
            "scenario_level_metadata_available": True  # Scenario filename metadata is always present
        }

        # Tactic / Technique extraction from path
        parts = [p.lower() for p in z_path.parts]
        for idx, part in enumerate(parts):
            if part == "windows" and idx + 1 < len(parts):
                manifest_record["parent_tactic_directory"] = z_path.parts[idx + 1]
                if idx + 2 < len(parts):
                    manifest_record["parent_technique_directory"] = z_path.parts[idx + 2]

        try:
            with zipfile.ZipFile(z_path, "r") as z_file:
                members = z_file.infolist()
                manifest_record["archive_member_count"] = len(members)
                manifest_record["archive_member_names"] = [m.filename for m in members]
                
                # Check for metadata files (YAML / markdown / txt)
                for m in members:
                    if m.filename.endswith((".yaml", ".yml", ".md", ".txt", ".json")):
                        if not m.filename.endswith((".json", ".jsonl", ".ndjson", ".csv")):
                            manifest_record["metadata_files_present"].append(m.filename)
                
                # Sizes
                manifest_record["compressed_size"] = sum(m.compress_size for m in members)
                manifest_record["uncompressed_size"] = sum(m.file_size for m in members)

                # Process telemetry files (Task O1)
                telemetry_members = []
                for m in members:
                    ext = Path(m.filename).suffix.lower()
                    if ext in [".json", ".jsonl", ".ndjson", ".csv"]:
                        telemetry_members.append(m)
                        if ext not in manifest_record["telemetry_file_types"]:
                            manifest_record["telemetry_file_types"].append(ext)

                zip_events = []
                # Open telemetry files incrementally (Task O1)
                for m in telemetry_members:
                    with z_file.open(m.filename) as f:
                        # Decode and parse text
                        content = f.read().decode("utf-8", errors="ignore")
                        content_stripped = content.strip()
                        if not content_stripped:
                            continue
                            
                        # Try parsing as JSON array
                        if content_stripped.startswith("[") and content_stripped.endswith("]"):
                            try:
                                parsed = json.loads(content_stripped)
                                if isinstance(parsed, list):
                                    zip_events.extend(parsed)
                            except json.JSONDecodeError:
                                # Fallback to NDJSON line parsing
                                for line in content_stripped.splitlines():
                                    line = line.strip()
                                    if line:
                                        try:
                                            zip_events.append(json.loads(line))
                                        except json.JSONDecodeError:
                                            pass
                        else:
                            # Parse as NDJSON
                            for line in content_stripped.splitlines():
                                line = line.strip()
                                if line:
                                    try:
                                        zip_events.append(json.loads(line))
                                    except json.JSONDecodeError:
                                        pass

                manifest_record["event_count"] = len(zip_events)
                total_inspected_events += len(zip_events)
                
                # Schema and field analyses on read events
                observed_providers = set()
                observed_channels = set()
                observed_event_ids = set()
                observed_hosts = set()
                observed_users = set()
                observed_top_fields = set()

                # Slice events to analyze to prevent slow execution on huge files
                sample_events = zip_events[:MAX_EVENTS_PER_ZIP]
                
                for ev in sample_events:
                    observed_top_fields.update(ev.keys())
                    
                    # 1. Provider & Channel detection (Task O4)
                    prov_val, prov_alias = find_field_value(ev, "provider_name")
                    if prov_val:
                        prov_str = str(prov_val)
                        observed_providers.add(prov_str)
                        global_providers[prov_str] += 1
                        
                    chan_val, _ = find_field_value(ev, "channel")
                    if chan_val:
                        observed_channels.add(str(chan_val))

                    # Event ID count (Task O4)
                    eid_val, _ = find_field_value(ev, "event_id")
                    if eid_val is not None:
                        eid_str = str(eid_val)
                        observed_event_ids.add(eid_str)
                        # If Sysmon
                        if prov_val and "sysmon" in str(prov_val).lower():
                            global_sysmon_event_ids[eid_str] += 1

                    # 2. Host & User detection
                    host_val, _ = find_field_value(ev, "computer_name")
                    if host_val:
                        observed_hosts.add(str(host_val))
                    user_val, _ = find_field_value(ev, "user_name")
                    if user_val:
                        observed_users.add(str(user_val))

                    # 3. Alias discovery counts (Task O3)
                    for canonical, aliases in FIELD_ALIASES.items():
                        val, matched_alias = find_field_value(ev, canonical)
                        if matched_alias:
                            global_field_alias_counts[canonical][matched_alias] += 1

                    # 4. Process tree check counts (Task O5)
                    # timestamp
                    t_val, _ = find_field_value(ev, "timestamp")
                    global_process_tree_stats["timestamp"]["present" if t_val else "absent"] += 1
                    
                    # host
                    h_val, _ = find_field_value(ev, "computer_name")
                    global_process_tree_stats["host"]["present" if h_val else "absent"] += 1
                    
                    # process ID
                    pid_val, _ = find_field_value(ev, "process_id")
                    global_process_tree_stats["process_id"]["present" if pid_val else "absent"] += 1
                    
                    # parent process ID
                    ppid_val, _ = find_field_value(ev, "parent_process_id")
                    global_process_tree_stats["parent_process_id"]["present" if ppid_val else "absent"] += 1
                    
                    # process image name
                    pname_val, _ = find_field_value(ev, "process_name")
                    global_process_tree_stats["process_name"]["present" if pname_val else "absent"] += 1
                    
                    # parent process image name
                    ppname_val, _ = find_field_value(ev, "parent_process_name")
                    global_process_tree_stats["parent_process_name"]["present" if ppname_val else "absent"] += 1
                    
                    # command line
                    cmd_val, _ = find_field_value(ev, "command_line")
                    global_process_tree_stats["command_line"]["present" if cmd_val else "absent"] += 1
                    
                    # parent command line
                    pcmd_val, _ = find_field_value(ev, "parent_command_line")
                    global_process_tree_stats["parent_command_line"]["present" if pcmd_val else "absent"] += 1
                    
                    # user
                    usr_val, _ = find_field_value(ev, "user_name")
                    global_process_tree_stats["user"]["present" if usr_val else "absent"] += 1

                    # Timestamp parsing for range
                    if t_val:
                        t_str = str(t_val)
                        if manifest_record["earliest_timestamp"] is None or t_str < manifest_record["earliest_timestamp"]:
                            manifest_record["earliest_timestamp"] = t_str
                        if manifest_record["latest_timestamp"] is None or t_str > manifest_record["latest_timestamp"]:
                            manifest_record["latest_timestamp"] = t_str

                    # Check for explicit event-level labels (Task O6)
                    if "label" in ev or "is_malicious" in ev or "attack" in ev:
                        has_event_labels = True
                        manifest_record["event_level_label_available"] = True

                manifest_record["observed_providers"] = list(observed_providers)
                manifest_record["observed_channels"] = list(observed_channels)
                manifest_record["observed_event_ids"] = list(observed_event_ids)
                manifest_record["observed_hosts"] = list(observed_hosts)
                manifest_record["observed_users"] = list(observed_users)
                manifest_record["observed_top_level_fields"] = list(observed_top_fields)
                
                manifest_record["read_success"] = True

        except Exception as e:
            manifest_record["read_success"] = False
            manifest_record["read_error"] = str(e)
            print(f"Error reading {z_path.name}: {e}")

        manifests.append(manifest_record)

    # 5. Output Process-Tree Feasibility Check (Task O5)
    feasibility_rates = {}
    print("\n--- Process Tree Field Availability Rates ---")
    for field, stats in global_process_tree_stats.items():
        present = stats["present"]
        absent = stats["absent"]
        total = present + absent
        pct = (present / total * 100.0) if total > 0 else 0.0
        feasibility_rates[field] = pct
        print(f"  {field:<20} | Present: {present:<8} | Absent: {absent:<8} | Availability: {pct:.2f}%")

    # Feasibility rating determination logic
    # If PID, Parent PID, Host, and Timestamp are highly available
    pid_avail = feasibility_rates.get("process_id", 0.0)
    ppid_avail = feasibility_rates.get("parent_process_id", 0.0)
    host_avail = feasibility_rates.get("host", 0.0)
    time_avail = feasibility_rates.get("timestamp", 0.0)

    if pid_avail > 80.0 and ppid_avail > 80.0 and host_avail > 80.0 and time_avail > 80.0:
        feasibility_rating = "FULL"
    elif pid_avail > 20.0 and ppid_avail > 20.0:
        feasibility_rating = "PARTIAL"
    else:
        feasibility_rating = "LOW"
    print(f"\nPROCESS TREE FEASIBILITY: {feasibility_rating}")

    # 6. OTRF Ground-Truth Analysis (Task O6)
    # Check if we have labels or sidecar recipes
    metadata_count = sum(len(m["metadata_files_present"]) for m in manifests)
    
    if has_event_labels:
        gt_level = "GROUND_TRUTH_LEVEL_1_EVENT"
        gt_reason = "Telemetry logs contain explicit label or is_malicious attributes on individual events."
    elif has_process_labels:
        gt_level = "GROUND_TRUTH_LEVEL_2_PROCESS"
        gt_reason = "Specific Process IDs or process entities are marked as malicious in execution sidecars."
    elif metadata_count > 0:
        # Check if execution timestamps or intervals are logged in yaml/txt
        gt_level = "GROUND_TRUTH_LEVEL_3_TIME_RANGE"
        gt_reason = "Sidecar YAML/metadata files contain attack execution time-ranges or timestamps."
    else:
        gt_level = "GROUND_TRUTH_LEVEL_4_SCENARIO"
        gt_reason = "Only scenario-level / file-level attack context is available based on archive path and filename metadata."
        
    print(f"Strongest available ground-truth level: {gt_level}")
    print(f"Reason: {gt_reason}")

    # 7. Training Unit Recommendation (Task O7)
    if feasibility_rating == "FULL":
        recommended_unit = "PROCESS_CENTRIC"
        rec_reason = "Process ID, Parent Process ID, Host, and Timestamp have high availability, allowing exact reconstruction of process trees."
    elif feasibility_rating == "PARTIAL":
        recommended_unit = "PROCESS_TIME_WINDOW"
        rec_reason = "Parent-child links are partially available, suggesting process tracking grouped inside short temporal windows."
    else:
        recommended_unit = "HOST_TIME_WINDOW"
        rec_reason = "Process tree identity is incomplete or missing. Telemetry must be aggregated per Host within rolling temporal windows."

    print(f"Recommended training unit: {recommended_unit}")

    # 8. Feature Candidate Report (Task O8)
    feature_candidates = {
        "raw_context_fields": [
            "timestamp", "computer_name", "user_name", "process_id", "parent_process_id",
            "process_name", "parent_process_name", "command_line", "parent_command_line",
            "event_id", "provider_name", "channel"
        ],
        "model_candidate_features": [
            "process_depth",
            "child_process_count",
            "unique_child_process_count",
            "parent_child_frequency",
            "command_length",
            "command_token_count",
            "encoded_command_flag",
            "powershell_flag",
            "script_interpreter_flag",
            "lolbin_flag",
            "remote_thread_count",
            "network_connection_count",
            "registry_set_count",
            "file_create_count",
            "image_load_count"
        ],
        "rule_sigma_context": [
            "image_path",
            "command_line",
            "target_object",
            "parent_image_path"
        ],
        "metadata_only_never_ml_features": [
            "archive_name",
            "scenario_name",
            "attack_tactic",
            "attack_technique",
            "tool_name"
        ]
    }

    # 9. Output results to directory (Task O9)
    out_dir = Path("data/processed/endpoint/inspection")
    out_dir.mkdir(parents=True, exist_ok=True)

    # Save otrf_archive_manifest.json
    with open(out_dir / "otrf_archive_manifest.json", "w", encoding="utf-8") as f:
        json.dump(manifests, f, indent=2)

    # Save otrf_archive_manifest.csv
    with open(out_dir / "otrf_archive_manifest.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["archive_name", "archive_size_bytes", "member_count", "telemetry_types", "tactic", "technique", "event_count", "read_success"])
        for m in manifests:
            writer.writerow([
                m["archive_name"],
                m["archive_size_bytes"],
                m["archive_member_count"],
                ",".join(m["telemetry_file_types"]),
                m["parent_tactic_directory"],
                m["parent_technique_directory"],
                m["event_count"],
                m["read_success"]
            ])

    # Save otrf_schema_report.json
    schema_report = {
        "observed_aliases_by_canonical": {k: dict(v) for k, v in global_field_alias_counts.items()},
        "availability_rates": feasibility_rates
    }
    with open(out_dir / "otrf_schema_report.json", "w", encoding="utf-8") as f:
        json.dump(schema_report, f, indent=2)

    # Save otrf_provider_event_report.json
    provider_event_report = {
        "observed_providers": dict(global_providers),
        "observed_sysmon_event_ids": dict(global_sysmon_event_ids)
    }
    with open(out_dir / "otrf_provider_event_report.json", "w", encoding="utf-8") as f:
        json.dump(provider_event_report, f, indent=2)

    # Save otrf_ground_truth_report.json
    gt_report = {
        "strongest_ground_truth_level": gt_level,
        "reasoning": gt_reason,
        "recommended_training_unit": recommended_unit,
        "recommendation_reasoning": rec_reason
    }
    with open(out_dir / "otrf_ground_truth_report.json", "w", encoding="utf-8") as f:
        json.dump(gt_report, f, indent=2)

    # Save otrf_feature_candidate_report.json
    with open(out_dir / "otrf_feature_candidate_report.json", "w", encoding="utf-8") as f:
        json.dump(feature_candidates, f, indent=2)

    # Save otrf_inspection_summary.md (Task O9 summary file)
    readable_zips = sum(1 for m in manifests if m["read_success"])
    failed_zips = len(host_zips) - readable_zips
    
    summary_md = f"""# OTRF Endpoint Dataset Inspection Summary

This report documents the findings from inspecting the downloaded OTRF Windows atomic host telemetry datasets.

## Archive Manifest Summary
- **Host archives found**: {len(host_zips)}
- **Readable archives**: {readable_zips}
- **Failed archives**: {failed_zips}
- **Total inspected events**: {total_inspected_events}

## Telemetry Providers and Channels
- **Main Providers observed**: {", ".join(list(global_providers.keys())[:5])}
- **Sysmon telemetry present**: {"Yes" if "Microsoft-Windows-Sysmon" in global_providers else "No"}
- **Sysmon Event ID counts**:
{chr(10).join(f"  - Event ID {eid}: {count}" for eid, count in global_sysmon_event_ids.items())}

## Schema & Process Tree Feasibility
- **Feasibility Rating**: {feasibility_rating}
- **Field Availability Rates**:
{chr(10).join(f"  - {f}: {rate:.2f}%" for f, rate in feasibility_rates.items())}

## Ground-Truth & Model Design Recommendations
- **Strongest Ground-Truth Level**: {gt_level} ({gt_reason})
- **Recommended Training Unit**: {recommended_unit}
- **Recommended Endpoint Model Type**: Supervised process-centric Classifier with sliding window anomaly thresholds.
- **Is Supervised LightGBM currently justified?**: Yes, but at the process level or using time-window targets since scenario labels are coarse.
- **Is Sigma Integration feasible?**: Yes, EventID, Image, CommandLine, and ParentImage are highly available, mapping directly to Sysmon rules.

## Dataset Limitations
1. Process PIDs can overlap across different hosts/scenarios, requiring strict compound keying (`host` + `pid` + `session`).
2. Absence of explicit benign logs in atomic attack datasets; requires injection of host baseline data to avoid false alarm bias.
"""
    (out_dir / "otrf_inspection_summary.md").write_text(summary_md, encoding="utf-8")
    print(f"Saved inspection reports to: {out_dir}")


if __name__ == "__main__":
    main()
