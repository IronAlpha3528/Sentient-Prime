import json
from pathlib import Path

import pandas as pd

from orchestrator.phase1_pipeline import Phase1Pipeline


def main() -> None:
    pipeline = Phase1Pipeline()

    # 1. Simulate Network Telemetry
    print("--- Simulating Network Telemetry ---")
    test_net = pd.read_parquet("data/processed/network/test.parquet")
    with open(
        "data/processed/network/metadata.json",
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

    # 2. Simulate Identity/UEBA Telemetry
    print("\n--- Simulating Identity Telemetry ---")
    identity_data_path = Path("data/processed/identity/lanl_user_hour_windows.parquet")
    if not identity_data_path.exists():
        print(f"Skipping identity simulation: {identity_data_path} does not exist.")
        return

    test_id = pd.read_parquet(identity_data_path)
    with open(
        "data/models/identity/feature_columns.json",
        encoding="utf-8",
    ) as file:
        features_id = json.load(file)

    row_id = test_id.iloc[0]
    id_event = {
        "telemetry_type": "identity",
        "entity_id": str(row_id["user"]),
        "data": {
            feature: row_id[feature]
            for feature in features_id
        },
    }

    id_evidence = pipeline.process(id_event)
    print("Identity Evidence Generated:")
    print(json.dumps(id_evidence, indent=2, default=str))


if __name__ == "__main__":
    main()
