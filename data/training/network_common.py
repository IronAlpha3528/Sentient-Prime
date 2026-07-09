from pathlib import Path
import re

import numpy as np


RAW_DIR = Path("data/raw/cse-cic/archive (1)")
PROCESSED_DIR = Path("data/processed/network")
MODEL_DIR = Path("data/models/network")
LABEL_CANDIDATES = ("label", "class", "attack", "attack_label")


def clean_column_name(name: str) -> str:
    name = re.sub(r"\s+", "_", str(name).strip())
    return re.sub(r"[^0-9a-zA-Z_]+", "", name).lower()


def clean_frame(frame):
    frame = frame.copy()
    frame.columns = [clean_column_name(c) for c in frame.columns]
    return frame.replace([np.inf, -np.inf], np.nan)


def find_label_column(frame) -> str:
    for candidate in LABEL_CANDIDATES:
        if candidate in frame.columns:
            return candidate
    raise ValueError(
        f"Could not find label column. First columns: {list(frame.columns)[:20]}"
    )


def parquet_files():
    return sorted(RAW_DIR.rglob("*.parquet"))
