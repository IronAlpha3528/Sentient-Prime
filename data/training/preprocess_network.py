import json
import pandas as pd
from sklearn.model_selection import train_test_split

from data.training.network_common import (
    PROCESSED_DIR,
    clean_frame,
    find_label_column,
    parquet_files,
)

DROP_IF_PRESENT = [
    "flow_id",
    "src_ip",
    "source_ip",
    "dst_ip",
    "destination_ip",
    "timestamp",
]

ATTACK_FAMILY_MAPPING = {
    "Benign": "Benign",
    "Bot": "Botnet",
    "Brute Force -Web": "BruteForce",
    "FTP-BruteForce": "BruteForce",
    "SSH-Bruteforce": "BruteForce",
    "DDOS attack-HOIC": "DDoS",
    "DDOS attack-LOIC-UDP": "DDoS",
    "DDoS attacks-LOIC-HTTP": "DDoS",
    "DoS attacks-GoldenEye": "DoS",
    "DoS attacks-Hulk": "DoS",
    "DoS attacks-SlowHTTPTest": "DoS",
    "DoS attacks-Slowloris": "DoS",
    "Infilteration": "Infiltration",
    "Brute Force -XSS": "WebAttack",
    "SQL Injection": "WebAttack",
}


def map_family(label: str) -> str:
    if label not in ATTACK_FAMILY_MAPPING:
        raise ValueError(f"Unknown attack class: '{label}' encountered in dataset.")
    return ATTACK_FAMILY_MAPPING[label]


def main() -> None:
    files = parquet_files()
    if not files:
        raise FileNotFoundError(
            "No CSE-CIC-IDS2018 Parquet files under data/raw/cse-cic/archive (1)/"
        )

    frames = []
    label_column = None

    for path in files:
        print("Reading:", path)
        frame = clean_frame(pd.read_parquet(path))
        current_label = find_label_column(frame)

        if label_column is None:
            label_column = current_label
        elif current_label != label_column:
            frame = frame.rename(columns={current_label: label_column})

        frames.append(frame)

    data = pd.concat(frames, ignore_index=True)
    data[label_column] = data[label_column].astype(str).str.strip()
    data = data.dropna(subset=[label_column])
    data = data.drop(
        columns=[c for c in DROP_IF_PRESENT if c in data.columns]
    )

    family_label_column = "family"
    # Populate the family column with validation check
    data[family_label_column] = data[label_column].apply(map_family)

    feature_columns = [
        c for c in data.columns if c not in (label_column, family_label_column)
    ]
    for column in feature_columns:
        data[column] = pd.to_numeric(data[column], errors="coerce")
    data[feature_columns] = data[feature_columns].fillna(0)

    class_counts = data[label_column].value_counts()
    too_small = class_counts[class_counts < 7]
    if not too_small.empty:
        raise ValueError(
            "Some classes are too small for a stratified 70/15/15 split. "
            f"Inspect/merge/remove these classes explicitly: {too_small.to_dict()}"
        )

    train, temp = train_test_split(
        data,
        test_size=0.30,
        random_state=42,
        stratify=data[label_column],
    )
    valid, test = train_test_split(
        temp,
        test_size=0.50,
        random_state=42,
        stratify=temp[label_column],
    )

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    train.to_parquet(PROCESSED_DIR / "train.parquet", index=False)
    valid.to_parquet(PROCESSED_DIR / "valid.parquet", index=False)
    test.to_parquet(PROCESSED_DIR / "test.parquet", index=False)

    metadata = {
        "label_column": label_column,
        "family_label_column": family_label_column,
        "feature_columns": feature_columns,
        "original_class_counts": class_counts.to_dict(),
        "family_class_counts": data[family_label_column].value_counts().to_dict(),
        "train_rows": len(train),
        "valid_rows": len(valid),
        "test_rows": len(test),
        "attack_family_mapping": ATTACK_FAMILY_MAPPING,
    }
    
    (PROCESSED_DIR / "metadata.json").write_text(
        json.dumps(metadata, indent=2),
        encoding="utf-8",
    )
    
    print("\n--- Preprocessing Complete ---")
    print(f"Total Rows: {len(data)}")
    print(f"Train Rows: {len(train)}")
    print(f"Valid Rows: {len(valid)}")
    print(f"Test Rows: {len(test)}")
    print("This is a stratified flow-level evaluation and not a fully unseen-campaign evaluation.")


if __name__ == "__main__":
    main()
