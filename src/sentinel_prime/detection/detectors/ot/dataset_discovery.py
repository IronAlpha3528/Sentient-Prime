import os
import zipfile
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
import pandas as pd
from sentinel_prime.detection.detectors.ot.schemas import DatasetManifest

logger = logging.getLogger(__name__)

def estimate_csv_metrics(file_or_stream, size_bytes: int) -> tuple[int, int, Optional[str], Optional[str]]:
    """
    Reads the header and first few lines to find columns and estimate row count.
    Detects delimiter dynamically from the first line.
    """
    try:
        # Read a chunk from stream
        chunk = file_or_stream.read(30000)
        if not chunk:
            return 0, 0, None, None
            
        # Detect delimiter from first line
        first_line = chunk.split("\n")[0]
        sep = ";" if ";" in first_line else ","
        
        # Use StringIO to parse the sample
        import io
        sample_io = io.StringIO(chunk)
        sample = pd.read_csv(sample_io, sep=sep, nrows=100)
        col_count = len(sample.columns)
        
        # Heuristically find timestamp and label columns
        timestamp_col = None
        label_col = None
        for col in sample.columns:
            col_lower = str(col).lower()
            if col_lower in ["timestamp", "time", "date", "datetime"]:
                timestamp_col = col
            if col_lower in ["attack", "label", "class", "is_attack", "anomaly"]:
                label_col = col
                
        # Estimate rows: total size / avg row size in bytes
        avg_row_size = 120 # Default fallback
        if not sample.empty:
            sample_str = sample.to_csv(index=False, sep=sep)
            avg_row_size = len(sample_str.encode("utf-8")) / len(sample)
            
        row_estimate = int(size_bytes / avg_row_size) if avg_row_size > 0 else 0
        return row_estimate, col_count, timestamp_col, label_col
    except Exception as e:
        logger.warning(f"Failed to estimate CSV metrics: {e}")
        return 0, 0, None, None

def discover_ot_datasets(directory_path: str) -> List[DatasetManifest]:
    """
    Recursively scans the directory for ZIP, CSV, Parquet, and JSON files.
    For ZIP files, it also recursively discovers CSV/Parquet members inside.
    """
    dir_path = Path(directory_path)
    if not dir_path.exists():
        logger.warning(f"OT raw directory does not exist: {directory_path}")
        return []

    manifests = []
    
    # We walk recursively
    for root, _, files in os.walk(dir_path):
        for file in files:
            f_path = Path(root) / file
            rel_path = f_path.relative_to(dir_path)
            ext = f_path.suffix.lower()
            size = f_path.stat().st_size
            
            if ext == ".csv":
                try:
                    with open(f_path, "r", encoding="utf-8", errors="ignore") as f:
                        row_est, col_cnt, ts_col, lbl_col = estimate_csv_metrics(f, size)
                    manifests.append(DatasetManifest(
                        file_path=str(f_path),
                        relative_path=str(rel_path),
                        row_estimate=row_est,
                        column_count=col_cnt,
                        file_size_bytes=size,
                        timestamp_column=ts_col,
                        label_column=lbl_col,
                        sampling_interval_seconds=1.0 # default for HAI
                    ))
                except Exception as e:
                    logger.warning(f"Error inspecting CSV file {f_path}: {e}")

            elif ext == ".zip":
                try:
                    with zipfile.ZipFile(f_path, "r") as z:
                        for z_info in z.infolist():
                            if z_info.is_dir():
                                continue
                            z_ext = Path(z_info.filename).suffix.lower()
                            if z_ext in [".csv", ".txt"]:
                                try:
                                    with z.open(z_info) as z_file:
                                        # Decode/wrap in TextIOWrapper or read raw
                                        import io
                                        text_file = io.TextIOWrapper(z_file, encoding="utf-8", errors="ignore")
                                        row_est, col_cnt, ts_col, lbl_col = estimate_csv_metrics(text_file, z_info.file_size)
                                        
                                    manifests.append(DatasetManifest(
                                        file_path=f"{f_path}::{z_info.filename}",
                                        relative_path=f"{rel_path}::{z_info.filename}",
                                        row_estimate=row_est,
                                        column_count=col_cnt,
                                        file_size_bytes=z_info.file_size,
                                        timestamp_column=ts_col,
                                        label_column=lbl_col,
                                        sampling_interval_seconds=1.0
                                    ))
                                except Exception as ez:
                                    logger.warning(f"Error inspecting ZIP member {z_info.filename} in {f_path}: {ez}")
                except Exception as e:
                    logger.warning(f"Error inspecting ZIP file {f_path}: {e}")
                    
            elif ext == ".parquet":
                try:
                    # Use fast metadata read for Parquet
                    import pyarrow.parquet as pq
                    meta = pq.read_metadata(f_path)
                    col_cnt = meta.num_columns
                    row_est = meta.num_rows
                    
                    # Read schema to find timestamp/label
                    schema = pq.read_schema(f_path)
                    ts_col = None
                    lbl_col = None
                    for name in schema.names:
                        name_lower = name.lower()
                        if name_lower in ["timestamp", "time", "date"]:
                            ts_col = name
                        if name_lower in ["attack", "label", "class"]:
                            lbl_col = name
                            
                    manifests.append(DatasetManifest(
                        file_path=str(f_path),
                        relative_path=str(rel_path),
                        row_estimate=row_est,
                        column_count=col_cnt,
                        file_size_bytes=size,
                        timestamp_column=ts_col,
                        label_column=lbl_col,
                        sampling_interval_seconds=1.0
                    ))
                except Exception as e:
                    logger.warning(f"Error inspecting Parquet file {f_path}: {e}")

    logger.info(f"Discovered {len(manifests)} OT dataset resources.")
    return manifests
