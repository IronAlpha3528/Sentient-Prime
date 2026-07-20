import json
import sys
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from sentinel_prime.soar.orchestrator.phase1_pipeline import Phase1Pipeline  # noqa: E402


def run_network(pipeline: Phase1Pipeline) -> None:
    print("--- Simulating Network Telemetry ---")
    network_data_path = PROJECT_ROOT / "data/processed/network/test.parquet"
    network_metadata_path = PROJECT_ROOT / "data/processed/network/metadata.json"
    
    if not network_data_path.exists() or not network_metadata_path.exists():
        print(f"Error: Network data or metadata does not exist at {network_data_path.parent}. Run aggregation and splits first.")
        return

    test_net = pd.read_parquet(network_data_path)
    if test_net.empty:
        print("Error: Network test data is empty.")
        return

    with open(
        network_metadata_path,
        encoding="utf-8",
    ) as file:
        metadata_net = json.load(file)

    row_net = test_net.iloc[0]
    net_event = {
        "telemetry_type": "network",
        "entity_id": "DEMO-HOST-01",
        "data": {
            feature: row_net[feature]
            for feature in metadata_net["feature_columns"]
        },
    }

    net_evidence = pipeline.process(net_event)
    print("Network Evidence Generated:")
    print(json.dumps(net_evidence, indent=2, default=str))


def run_identity(pipeline: Phase1Pipeline) -> None:
    print("--- Simulating Identity Telemetry ---")
    identity_data_path = PROJECT_ROOT / "data/processed/identity/test.parquet"
    if not identity_data_path.exists():
        print(f"Error: {identity_data_path} does not exist. Run aggregation and splits first.")
        return

    test_id = pd.read_parquet(identity_data_path)
    if test_id.empty:
        print("Error: Identity test data is empty.")
        return

    row_id = test_id.iloc[0]

    # Send all aggregated features (excluding metadata index keys)
    exclude_keys = {"user", "window_id"}
    id_event = {
        "telemetry_type": "identity",
        "entity_id": str(row_id["user"]),
        "data": {
            col: row_id[col]
            for col in test_id.columns
            if col not in exclude_keys
        },
    }

    id_evidence = pipeline.process(id_event)
    print("Identity Evidence Generated:")
    print(json.dumps(id_evidence, indent=2, default=str))


def main() -> None:
    mode = "network"
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
        if arg in ["network", "identity"]:
            mode = arg
        else:
            print(f"Unknown mode: '{sys.argv[1]}'. Defaulting to 'network'.")
            print("Usage: python run_phase1.py [network|identity]")
            print()

    pipeline = Phase1Pipeline()

    if mode == "network":
        run_network(pipeline)
    elif mode == "identity":
        run_identity(pipeline)


if __name__ == "__main__":
    main()
