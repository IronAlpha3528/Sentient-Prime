import os
import json
import csv
import zipfile
import pytest
from pathlib import Path
import pandas as pd
import numpy as np

from detectors.endpoint.schemas import ArchiveManifest, EndpointEvent
from detectors.endpoint.dataset_discovery import get_otrf_path, discover_archives, DatasetNotFoundError
from detectors.endpoint.archive_reader import stream_telemetry_files
from detectors.endpoint.event_parser import parse_telemetry_content
from detectors.endpoint.field_mapper import find_alias_value, FIELD_ALIASES
from detectors.endpoint.event_normalizer import normalize_event, clear_stats, get_stats
from detectors.endpoint.process_window_builder import build_process_windows, parse_timestamp
from detectors.endpoint.feature_builder import build_features_for_window, FEATURE_CONTRACT

# ========================================================
# PATH RESOLUTION & DISCOVERY TESTS
# ========================================================

def test_get_otrf_path_error(monkeypatch):
    # Set to a non-existent path
    monkeypatch.setenv("OTRF_DATASET_PATH", "C:\\nonexistent_otrf_directory_abc_123")
    with pytest.raises(DatasetNotFoundError):
        get_otrf_path()

def test_discover_archives_and_manifests(tmp_path, monkeypatch):
    mock_otrf = tmp_path / "mock_otrf"
    mock_otrf.mkdir()
    monkeypatch.setenv("OTRF_DATASET_PATH", str(mock_otrf))

    # Create host directories
    tactic_dir = mock_otrf / "credential_access"
    technique_dir = tactic_dir / "t1003"
    host_dir = technique_dir / "host"
    host_dir.mkdir(parents=True)

    # Create a host zip archive
    zip_host_path = host_dir / "credential_dumping.zip"
    with zipfile.ZipFile(zip_host_path, "w") as z:
        z.writestr("events.json", "[]")

    # Create a non-host zip archive
    network_dir = technique_dir / "network"
    network_dir.mkdir(parents=True)
    zip_net_path = network_dir / "pcap.zip"
    with zipfile.ZipFile(zip_net_path, "w") as z:
        z.writestr("events.json", "[]")

    manifests = discover_archives()
    assert len(manifests) == 1
    assert manifests[0].archive_name == "credential_dumping.zip" if hasattr(manifests[0], "archive_name") else True
    assert "credential_dumping.zip" in manifests[0].archive_path

# ========================================================
# ARCHIVE READER & EVENT PARSER TESTS
# ========================================================

def test_archive_reader_and_event_parser(tmp_path):
    zip_path = tmp_path / "telemetry.zip"
    
    # Create synthetic events of various formats
    json_events = [{"EventID": 1, "Image": "cmd.exe", "UtcTime": "2026-07-09T12:00:00Z"}]
    ndjson_events = '{"EventID": 3, "Image": "svchost.exe", "UtcTime": "2026-07-09T12:01:00Z"}\n{"EventID": 7, "Image": "ntdll.dll", "UtcTime": "2026-07-09T12:02:00Z"}'
    csv_events = "EventID,Image,UtcTime\n10,lsass.exe,2026-07-09T12:03:00Z\n"
    yaml_events = "- EventID: 11\n  Image: notepad.exe\n  UtcTime: '2026-07-09T12:04:00Z'\n"

    with zipfile.ZipFile(zip_path, "w") as z:
        z.writestr("events.json", json.dumps(json_events))
        z.writestr("events.jsonl", ndjson_events)
        z.writestr("events.csv", csv_events)
        z.writestr("events.yaml", yaml_events)

    # Stream & Parse
    all_parsed = []
    for member_name, content in stream_telemetry_files(str(zip_path)):
        for ev in parse_telemetry_content(member_name, content):
            all_parsed.append(ev)

    assert len(all_parsed) == 5
    
    # Verify exact contents
    assert all_parsed[0]["Image"] == "cmd.exe"
    assert all_parsed[1]["Image"] == "svchost.exe"
    assert all_parsed[2]["Image"] == "ntdll.dll"
    assert all_parsed[3]["Image"] == "lsass.exe"
    assert all_parsed[4]["Image"] == "notepad.exe"

def test_malformed_archive_handling(tmp_path):
    # Setup bad file structure
    bad_zip = tmp_path / "bad.zip"
    with open(bad_zip, "w") as f:
        f.write("not a zip file content")

    # Verify stream_telemetry_files handles exception and yields nothing
    events = list(stream_telemetry_files(str(bad_zip)))
    assert len(events) == 0

# ========================================================
# FIELD ALIASING & EVENT NORMALIZATION TESTS
# ========================================================

def test_field_aliasing_and_normalization():
    clear_stats()

    # Heterogeneous raw event
    raw = {
        "event.code": "1",
        "process.name": "powershell.exe",
        "process.executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "process.parent.name": "explorer.exe",
        "process.pid": "1024",
        "process.parent.pid": "512",
        "process.command_line": "powershell.exe -enc abc",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "UtcTime": "2026-07-09T12:00:00.000Z",
        "user.name": "SYSTEM",
        "host.name": "SEC-HOST-01",
        "ProviderName": "Microsoft-Windows-Sysmon"
    }

    ev, discard = normalize_event(raw)
    assert ev is not None
    assert discard is None
    
    # Assert canonical values
    assert ev.event_id == "1"
    assert ev.process_name == "powershell.exe"
    assert ev.parent_process_name == "explorer.exe"
    assert ev.process_id == 1024
    assert ev.parent_process_id == 512
    assert ev.command_line == "powershell.exe -enc abc"
    assert ev.channel == "Microsoft-Windows-Sysmon/Operational"
    assert ev.timestamp == "2026-07-09T12:00:00.000Z"
    assert ev.host == "SEC-HOST-01"
    assert ev.user == "SYSTEM"
    assert ev.provider == "Microsoft-Windows-Sysmon"

    # Test discard of unrelated metadata (missing timestamp/channels)
    raw_bad = {"foo": "bar"}
    ev_bad, discard_bad = normalize_event(raw_bad)
    assert ev_bad is None
    assert discard_bad == "missing_timestamp"

# ========================================================
# PROCESS WINDOW GENERATION TESTS
# ========================================================

def test_window_generation():
    events = [
        EndpointEvent(timestamp="2026-07-09T12:00:00Z", host="H1", process_name="cmd.exe", process_id=100, event_id="1"),
        EndpointEvent(timestamp="2026-07-09T12:00:10Z", host="H1", process_name="cmd.exe", process_id=100, event_id="3", destination_ip="8.8.8.8"),
        EndpointEvent(timestamp="2026-07-09T12:00:30Z", host="H1", process_name="cmd.exe", process_id=100, event_id="11"),
        # Separate window for same process (outside 60s)
        EndpointEvent(timestamp="2026-07-09T12:02:00Z", host="H1", process_name="cmd.exe", process_id=100, event_id="22"),
        # Separate process
        EndpointEvent(timestamp="2026-07-09T12:00:05Z", host="H1", process_name="powershell.exe", process_id=200, event_id="1")
    ]

    windows = build_process_windows(events, window_duration_seconds=60)
    
    # We expect 3 windows: 2 for cmd.exe (split temporally) and 1 for powershell.exe
    assert len(windows) == 3
    
    cmd_wins = [w for w in windows if w["process"] == "cmd.exe"]
    ps_wins = [w for w in windows if w["process"] == "powershell.exe"]
    
    assert len(cmd_wins) == 2
    assert len(ps_wins) == 1
    
    # First cmd window has 3 events
    first_cmd = sorted(cmd_wins, key=lambda w: w["window_start"])[0]
    assert first_cmd["event_count"] == 3

# ========================================================
# FEATURE GENERATION TESTS
# ========================================================

def test_feature_generation():
    # Build mock process window
    events = [
        EndpointEvent(timestamp="2026-07-09T12:00:00Z", host="H1", process_name="powershell.exe", process_id=100, parent_process_name="cmd.exe", event_id="1", command_line="powershell.exe -enc abc", user="SYSTEM"),
        EndpointEvent(timestamp="2026-07-09T12:00:10Z", host="H1", process_name="powershell.exe", process_id=100, event_id="3", destination_ip="10.0.0.5", destination_port=443),
        EndpointEvent(timestamp="2026-07-09T12:00:20Z", host="H1", process_name="powershell.exe", process_id=100, event_id="7", image_loaded="C:\\Windows\\Temp\\inject.dll"),
        EndpointEvent(timestamp="2026-07-09T12:00:30Z", host="H1", process_name="powershell.exe", process_id=100, event_id="10", target_process="C:\\Windows\\System32\\lsass.exe", granted_access="0x1fffff")
    ]
    
    window = {
        "window_id": "mock_window_1",
        "host": "H1",
        "process": "powershell.exe",
        "parent_process": "cmd.exe",
        "window_start": "2026-07-09T12:00:00Z",
        "window_end": "2026-07-09T12:00:30Z",
        "event_count": 4,
        "events": events
    }
    
    features = build_features_for_window(window)
    
    # Check features
    assert features["process_depth"] == 2.0
    assert features["encoded_command_flag"] == 1.0
    assert features["powershell_flag"] == 1.0
    assert features["network_connection_count"] == 1.0
    assert features["unique_destination_count"] == 1.0
    assert features["destination_port_count"] == 1.0
    assert features["image_load_count"] == 1.0
    assert features["rare_image_load_count"] == 1.0 # loaded from C:\Windows\Temp\
    assert features["process_access_count"] == 1.0
    assert features["lsass_access_count"] == 1.0
    assert features["granted_access_entropy"] > 0.0
    assert features["lolbin_flag"] == 0.0

    # Ensure metadata keys are present but exclude from the feature contract
    for feature_name in FEATURE_CONTRACT.keys():
        assert feature_name in features
        assert feature_name not in ["archive_name", "scenario_name", "attack_tactic", "attack_technique"]

def test_no_permanent_extraction_integrity():
    # Make sure we don't leave trace folders in our test workspace
    workspace_dirs = list(Path(".").glob("temp_extract_*"))
    assert len(workspace_dirs) == 0
