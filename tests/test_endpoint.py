import os
import json
import yaml
import pytest
from pathlib import Path
import pandas as pd
import numpy as np

from sentinel_prime.detection.detectors.endpoint.schemas import EndpointEvent
from sentinel_prime.detection.detectors.endpoint.endpoint_model import EndpointModel
from sentinel_prime.detection.detectors.endpoint.sigma_loader import load_sigma_rules, SigmaRule
from sentinel_prime.detection.detectors.endpoint.sigma_engine import SigmaEngine, get_field_value_from_event
from sentinel_prime.detection.detectors.endpoint.evidence_fusion import fuse_predictions_and_rules
from sentinel_prime.detection.detectors.endpoint.endpoint_detector import EndpointDetector

@pytest.fixture
def temp_sigma_rule(tmp_path):
    rule_content = """
title: Test PowerShell Encoded Command
id: test-ps-enc
status: stable
description: Detects encoded command lines
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: '-enc'
        Image|endswith: 'powershell.exe'
    condition: selection
level: high
tags:
    - attack.execution
    - attack.t1059.001
"""
    rule_dir = tmp_path / "rules"
    rule_dir.mkdir()
    rule_file = rule_dir / "test_rule.yaml"
    rule_file.write_text(rule_content, encoding="utf-8")
    return rule_dir

def test_sigma_loading_and_matching(temp_sigma_rule):
    rules = load_sigma_rules(str(temp_sigma_rule))
    assert len(rules) == 1
    rule = rules[0]
    assert rule.title == "Test PowerShell Encoded Command"
    assert "T1059.001" in rule.mitre_techniques

    engine = SigmaEngine(rules)
    
    # Matching event
    ev_match = EndpointEvent(
        timestamp="2026-07-09T12:00:00Z",
        process_name="powershell.exe",
        command_line="powershell.exe -enc abc",
        raw_event={
            "Image": "C:\\Windows\\System32\\powershell.exe",
            "CommandLine": "powershell.exe -enc abc"
        }
    )
    matches = engine.match_event(ev_match)
    assert len(matches) == 1
    assert matches[0]["rule_name"] == "Test PowerShell Encoded Command"
    assert matches[0]["severity"] == "high"

    # Non-matching event
    ev_no_match = EndpointEvent(
        timestamp="2026-07-09T12:00:00Z",
        process_name="cmd.exe",
        command_line="cmd.exe /c dir",
        raw_event={
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c dir"
        }
    )
    matches_no = engine.match_event(ev_no_match)
    assert len(matches_no) == 0

def test_malformed_sigma_rule_handling(tmp_path):
    bad_rule_content = "title: Broken Rule\n# missing detection key"
    rule_file = tmp_path / "broken.yaml"
    rule_file.write_text(bad_rule_content, encoding="utf-8")
    
    rules = load_sigma_rules(str(tmp_path))
    # Malformed rules should be skipped gracefully
    assert len(rules) == 0

def test_evidence_fusion():
    features = {"powershell_flag": 1.0, "encoded_command_flag": 1.0}
    window = {"host": "H1", "process": "powershell.exe", "window_start": "12:00", "window_end": "12:01", "event_count": 2}
    
    # Case 1: High ML + High Sigma
    matches = [{"rule_id": "r1", "rule_name": "Test Rule", "severity": "high", "mitre_techniques": ["T1059"]}]
    ev = fuse_predictions_and_rules(0.85, matches, features, window)
    assert ev.risk_score == 0.95
    assert ev.severity == "critical"
    assert ev.confidence == 0.95
    assert any("Encoded command execution" in reason for reason in ev.top_reasons) or any("Sigma rule trigger" in reason for reason in ev.top_reasons)

    # Case 2: High ML + No Sigma
    ev2 = fuse_predictions_and_rules(0.80, [], features, window)
    assert ev2.risk_score == 0.80
    assert ev2.severity == "medium" # 0.80 falls into medium (<0.85)
    assert ev2.confidence == 0.75

    # Case 3: Low ML + High Sigma
    ev3 = fuse_predictions_and_rules(0.20, matches, features, window)
    assert ev3.risk_score == 0.80
    assert ev3.severity == "medium"
    assert ev3.confidence == 0.80

    # Case 4: Low ML + No Sigma
    ev4 = fuse_predictions_and_rules(0.10, [], features, window)
    assert ev4.risk_score == 0.10
    assert ev4.severity == "low"
    assert ev4.confidence == 0.50

def test_detector_health_and_metadata(monkeypatch, temp_sigma_rule):
    detector = EndpointDetector()
    
    # Override configuration paths for mock validation
    detector.sigma_dir = str(temp_sigma_rule)
    detector.load_sigma(str(temp_sigma_rule))
    
    health = detector.health()
    # Model should be healthy as it was trained in previous step
    assert "Healthy" in health or "Degraded" in health
    
    meta = detector.metadata()
    assert meta["detector_id"] == "endpoint-specialist"
    assert meta["sigma_rules_count"] == 1
