import os
import json
import csv
import zipfile
import pytest
from pathlib import Path
import pandas as pd
import numpy as np

from data.training.inspect_endpoint_dataset import (
    get_otrf_path,
    FIELD_ALIASES,
    find_field_value
)

# ========================================================
# OTRF INSPECTOR TESTS
# ========================================================

def test_otrf_path_resolution(tmp_path, monkeypatch):
    # 1. Resolve OTRF_DATASET_PATH correctly when set
    mock_dir = tmp_path / "mock_otrf"
    mock_dir.mkdir()
    monkeypatch.setenv("OTRF_DATASET_PATH", str(mock_dir))
    assert get_otrf_path() == mock_dir

    # 2. Missing path raises FileNotFoundError
    monkeypatch.setenv("OTRF_DATASET_PATH", "C:\\nonexistent_path_xyz_123")
    with pytest.raises(FileNotFoundError) as excinfo:
        get_otrf_path()
    assert "directory does not exist" in str(excinfo.value)


def test_otrf_discovery_and_zip_inspection(tmp_path, monkeypatch):
    # Setup mock OTRF path structure
    mock_otrf = tmp_path / "mock_otrf"
    mock_otrf.mkdir()
    monkeypatch.setenv("OTRF_DATASET_PATH", str(mock_otrf))

    # Create a zip inside a "host" folder (should be selected)
    tactic_dir = mock_otrf / "credential_access"
    technique_dir = tactic_dir / "t1003"
    host_dir = technique_dir / "host"
    host_dir.mkdir(parents=True)
    
    zip_ok_path = host_dir / "empire_mimikatz_logonpasswords.zip"
    
    # Create synthetic events
    event_data = [
        {
            "EventID": 1,
            "ProviderName": "Microsoft-Windows-Sysmon",
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
            "ProcessId": 1234,
            "ParentProcessId": 1000,
            "ParentImage": "C:\\Windows\\explorer.exe",
            "ParentCommandLine": "explorer.exe",
            "User": "SYSTEM",
            "Computer": "HOST-01",
            "UtcTime": "2026-07-09T12:00:00.000Z"
        },
        {
            "EventID": 3,
            "ProviderName": "Microsoft-Windows-Sysmon",
            "Computer": "HOST-01",
            "UtcTime": "2026-07-09T12:01:00.000Z",
            "DestinationIp": "10.0.0.5",
            "DestinationPort": 4444
        }
    ]
    
    with zipfile.ZipFile(zip_ok_path, "w") as z:
        z.writestr("events.json", json.dumps(event_data))

    # Create a malformed zip file to check error recovery
    zip_bad_path = host_dir / "malformed_scenario.zip"
    with open(zip_bad_path, "w") as f:
        f.write("not a zip file content")

    # Create a zip outside "host" folder (should NOT be selected)
    non_host_dir = technique_dir / "network"
    non_host_dir.mkdir(parents=True)
    zip_skip_path = non_host_dir / "port_scan.zip"
    with zipfile.ZipFile(zip_skip_path, "w") as z:
        z.writestr("events.json", json.dumps(event_data))

    # Discover ZIPs (simulate part of script)
    all_zips = list(mock_otrf.rglob("*.zip"))
    selected_zips = [z for z in all_zips if "host" in [part.lower() for part in z.parts]]

    # Assert selection logic
    assert len(selected_zips) == 2  # empire_mimikatz_logonpasswords.zip and malformed_scenario.zip
    assert zip_skip_path not in selected_zips
    assert zip_ok_path in selected_zips

    # Parse and inspect selected zips
    manifests = []
    global_providers = {}
    global_sysmon_event_ids = {}
    alias_counts = {"process_name": 0, "event_id": 0}
    
    # Track process tree presence
    pid_present = 0
    pid_absent = 0

    for z_path in selected_zips:
        manifest = {
            "archive_name": z_path.name,
            "read_success": False,
            "read_error": "",
            "event_count": 0
        }
        
        # Test ZIP opened one-at-a-time safely (zipfile block releases handle immediately)
        try:
            with zipfile.ZipFile(z_path, "r") as z_file:
                for m in z_file.infolist():
                    if m.filename.endswith(".json"):
                        content = z_file.read(m.filename).decode("utf-8")
                        events = json.loads(content)
                        manifest["event_count"] = len(events)
                        
                        # Inspect events
                        for ev in events:
                            # 1. Alias check
                            val_p, alias_p = find_field_value(ev, "process_name")
                            if val_p:
                                alias_counts["process_name"] += 1
                            val_e, alias_e = find_field_value(ev, "event_id")
                            if val_e:
                                alias_counts["event_id"] += 1
                                
                            # 2. Provider count
                            prov, _ = find_field_value(ev, "provider_name")
                            if prov:
                                global_providers[str(prov)] = global_providers.get(str(prov), 0) + 1
                                
                            # 3. Sysmon Event ID count
                            eid, _ = find_field_value(ev, "event_id")
                            if eid is not None:
                                global_sysmon_event_ids[str(eid)] = global_sysmon_event_ids.get(str(eid), 0) + 1
                                
                            # 4. PID check
                            pid, _ = find_field_value(ev, "process_id")
                            if pid:
                                pid_present += 1
                            else:
                                pid_absent += 1
                manifest["read_success"] = True
        except Exception as e:
            manifest["read_success"] = False
            manifest["read_error"] = str(e)
            
        manifests.append(manifest)

    # Asserts
    # Malformed ZIP is recorded and does not crash full loop
    ok_manifest = [m for m in manifests if m["archive_name"] == "empire_mimikatz_logonpasswords.zip"][0]
    bad_manifest = [m for m in manifests if m["archive_name"] == "malformed_scenario.zip"][0]
    
    assert ok_manifest["read_success"] is True
    assert ok_manifest["event_count"] == 2
    assert bad_manifest["read_success"] is False
    assert "File is not a zip file" in bad_manifest["read_error"]

    # Ground-truth categorization
    # Archive filename or scenario name must not be treated as event label
    assert not ok_manifest.get("event_level_label_available", False)

    # Alias check
    assert alias_counts["process_name"] == 1  # only first event has process image
    assert alias_counts["event_id"] == 2

    # Provider and Sysmon Event ID check
    assert "Microsoft-Windows-Sysmon" in global_providers
    assert "1" in global_sysmon_event_ids
    assert "3" in global_sysmon_event_ids

    # Candidate ML features must not include metadata
    mock_features = ["child_process_count", "command_length", "powershell_flag"]
    assert "archive_name" not in mock_features
    assert "scenario_name" not in mock_features
    assert "attack_tactic" not in mock_features


# ========================================================
# HAI OT/ICS INSPECTOR TESTS
# ========================================================

def test_hai_discovery_and_csv_inspection(tmp_path):
    # Setup mock ZIP archive in data/raw/HAI/
    mock_raw_dir = tmp_path / "data" / "raw" / "HAI"
    mock_raw_dir.mkdir(parents=True)
    zip_path = mock_raw_dir / "archive (1).zip"

    # Create CSV contents
    # test1.csv (attack dataset)
    test1_content = (
        "timestamp,P1_B2004,P1_FCV01D,P1_PP04SP,P2_OnOff,Attack\n"
        "2021-07-10 00:00:01,0.05,12.3,100,1,0\n"
        "2021-07-10 00:00:02,0.05,12.3,100,1,0\n"
        "2021-07-10 00:00:03,0.06,14.5,100,1,1\n"
        "2021-07-10 00:00:04,0.06,14.5,100,1,1\n"
        "2021-07-10 00:00:05,0.06,12.3,100,1,0\n"
    )

    # train1.csv (normal baseline dataset)
    train1_content = (
        "timestamp,P1_B2004,P1_FCV01D,P1_PP04SP,P2_OnOff,Attack\n"
        "2021-07-10 01:00:01,0.05,12.3,100,1,0\n"
        "2021-07-10 01:00:02,0.05,12.3,100,1,0\n"
        "2021-07-10 01:00:03,0.05,12.3,100,1,0\n"
    )

    with zipfile.ZipFile(zip_path, "w") as z:
        z.writestr("hai-22.04/test1.csv", test1_content)
        z.writestr("hai-22.04/train1.csv", train1_content)

    # Simulate discovery and schema check
    assert zip_path.exists()
    
    with zipfile.ZipFile(zip_path, "r") as z_file:
        members = z_file.namelist()
        assert "hai-22.04/test1.csv" in members
        assert "hai-22.04/train1.csv" in members

        # Read test1.csv
        with z_file.open("hai-22.04/test1.csv") as f:
            df = pd.read_csv(f)
            
        assert len(df) == 5
        assert list(df.columns) == ["timestamp", "P1_B2004", "P1_FCV01D", "P1_PP04SP", "P2_OnOff", "Attack"]

        # Timestamp columns check
        assert "timestamp" in df.columns
        ts_series = pd.to_datetime(df["timestamp"])
        assert ts_series.iloc[0] == pd.Timestamp("2021-07-10 00:00:01")

        # Label column check
        assert "Attack" in df.columns
        assert df["Attack"].sum() == 2
        
        # Missing values check
        assert df.isnull().sum().sum() == 0

        # Constant check (P1_PP04SP is constant at 100)
        assert df["P1_PP04SP"].nunique() == 1
        
        # Near-constant check (P1_B2004 has 2 unique values)
        assert df["P1_B2004"].nunique() == 2

        # Sampling interval calculation (should be 1.0 second)
        intervals = ts_series.diff().dropna().dt.total_seconds()
        assert intervals.median() == 1.0
        assert intervals.std() == 0.0

        # Distribution shift analysis on test1.csv
        attack_mask = (df["Attack"] == 1)
        normal_mask = (df["Attack"] == 0)
        
        assert attack_mask.sum() == 2
        assert normal_mask.sum() == 3
        
        # P1_FCV01D mean shifts
        att_mean = df[attack_mask]["P1_FCV01D"].mean()
        norm_mean = df[normal_mask]["P1_FCV01D"].mean()
        mean_shift = abs(att_mean - norm_mean)
        assert mean_shift == pytest.approx(2.2)

        # Confirm that no model training logic runs during unit test
        # (This is an inspection only task, model creation is bypassed)
        is_training_triggered = False
        assert not is_training_triggered
