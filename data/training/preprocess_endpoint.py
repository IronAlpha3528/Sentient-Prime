import os
import sys
import json
import logging
from pathlib import Path
from typing import List, Dict, Any
import numpy as np

# Ensure project root is in path if executing directly
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from sentinel_prime.detection.detectors.endpoint.dataset_discovery import discover_archives, DatasetNotFoundError
from sentinel_prime.detection.detectors.endpoint.archive_reader import stream_telemetry_files
from sentinel_prime.detection.detectors.endpoint.event_parser import parse_telemetry_content
from sentinel_prime.detection.detectors.endpoint.event_normalizer import normalize_event, get_stats, clear_stats
from sentinel_prime.detection.detectors.endpoint.process_window_builder import build_process_windows, parse_timestamp
from sentinel_prime.detection.detectors.endpoint.feature_builder import build_features_for_window, save_features

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def main() -> None:
    logger.info("Starting Endpoint Specialist preprocessing pipeline...")
    clear_stats()

    # Step 1: Discover archives
    try:
        manifests = discover_archives()
    except DatasetNotFoundError as e:
        logger.error(f"Preprocessing aborted: {e}")
        sys.exit(1)

    logger.info(f"Discovered {len(manifests)} host archives.")

    all_normalized_events = []
    archives_processed = 0
    total_parsed_events = 0

    # Step 2: Stream, Parse and Normalize events
    for manifest in manifests:
        archive_path = manifest.archive_path
        logger.info(f"Processing archive: {manifest.relative_path}")
        
        # Keep track of events within this archive
        archive_events_count = 0
        
        # Read archives one at a time safely
        for member_name, content in stream_telemetry_files(archive_path):
            for raw_ev in parse_telemetry_content(member_name, content):
                total_parsed_events += 1
                ev, discard_reason = normalize_event(raw_ev)
                if ev:
                    all_normalized_events.append(ev)
                    archive_events_count += 1
                    
        logger.info(f"Archive {manifest.relative_path}: normalized {archive_events_count} events.")
        archives_processed += 1

    # Fetch stats
    stats = get_stats()
    events_discarded = sum(stats["discards"].values())
    normalization_success = len(all_normalized_events)

    logger.info(f"Normalization complete. Total parsed: {total_parsed_events}, Discarded: {events_discarded}, Normalized: {normalization_success}")

    # Step 3: Build Process Windows
    logger.info("Building process-centric temporal windows...")
    windows = build_process_windows(all_normalized_events, window_duration_seconds=60)
    logger.info(f"Generated {len(windows)} process windows.")

    # Calculate window metrics
    avg_events_per_window = 0.0
    avg_window_duration = 0.0
    
    if windows:
        event_counts = [w["event_count"] for w in windows]
        avg_events_per_window = float(np.mean(event_counts))
        
        durations = []
        for w in windows:
            start = parse_timestamp(w["window_start"])
            end = parse_timestamp(w["window_end"])
            durations.append((end - start).total_seconds())
        avg_window_duration = float(np.mean(durations))

    # Step 4: Build Behavioural Features
    logger.info("Extracting behavioural features from windows...")
    feature_rows = []
    for w in windows:
        features = build_features_for_window(w)
        feature_rows.append(features)

    # Step 5: Save Parquet and Feature Contract
    out_dir = Path("data/processed/endpoint/features")
    out_parquet = out_dir / "endpoint_features.parquet"
    out_contract = out_dir / "feature_contract.json"
    
    if feature_rows:
        save_features(feature_rows, str(out_parquet), str(out_contract))
        output_shape = [len(feature_rows), len(feature_rows[0])]
    else:
        logger.warning("No features generated. Parquet output skipped.")
        output_shape = [0, 0]

    # Save Preprocessing Report
    top_event_ids = dict(sorted(stats["event_ids"].items(), key=lambda x: x[1], reverse=True)[:10])
    
    report = {
        "archives_processed": archives_processed,
        "events_parsed": total_parsed_events,
        "events_discarded": events_discarded,
        "discard_reasons": stats["discards"],
        "normalization_success": normalization_success,
        "provider_distribution": stats["providers"],
        "average_events_per_process_window": avg_events_per_window,
        "average_window_duration_seconds": avg_window_duration,
        "top_event_ids": top_event_ids,
        "output_dataset_shape": output_shape
    }

    metadata_dir = Path("data/processed/endpoint/metadata")
    metadata_dir.mkdir(parents=True, exist_ok=True)
    report_json_path = metadata_dir / "preprocessing_report.json"
    
    with open(report_json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    logger.info(f"Saved preprocessing report to: {report_json_path}")

    # Generate Markdown Report
    report_md_path = metadata_dir / "preprocessing_report.md"
    discard_lines = "\n".join(f"- {reason}: {count}" for reason, count in stats["discards"].items())
    provider_lines = "\n".join(f"- {prov}: {count}" for prov, count in stats["providers"].items())
    eid_lines = "\n".join(f"- Event ID {eid}: {count}" for eid, count in top_event_ids.items())
    
    md_content = f"""# Endpoint Specialist Preprocessing Report

This report summarizes the telemetry parsing, event normalization, and window building execution.

## Data Processing Overview
- **Archives Processed**: {archives_processed}
- **Events Parsed**: {total_parsed_events}
- **Events Discarded**: {events_discarded}
- **Events Successfully Normalized**: {normalization_success}

## Discard Reasons
{discard_lines if discard_lines else "None"}

## Telemetry Providers
{provider_lines if provider_lines else "None"}

## Top Sysmon Event IDs
{eid_lines if eid_lines else "None"}

## Process Window Statistics
- **Total Process Windows**: {len(windows)}
- **Average Events per Window**: {avg_events_per_window:.2f}
- **Average Window Duration**: {avg_window_duration:.2f} seconds

## Feature Extraction Details
- **Output Dataset Path**: `data/processed/endpoint/features/endpoint_features.parquet`
- **Output Dataset Shape**: {output_shape[0]} rows x {output_shape[1]} features
"""
    report_md_path.write_text(md_content, encoding="utf-8")
    logger.info(f"Saved markdown report to: {report_md_path}")
    logger.info("Endpoint preprocessing completed successfully.")

if __name__ == "__main__":
    main()
