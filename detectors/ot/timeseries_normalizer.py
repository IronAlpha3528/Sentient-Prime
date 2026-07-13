import logging
import json
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
import pandas as pd
import numpy as np

from detectors.ot.schemas import NormalizedOTRow

logger = logging.getLogger(__name__)

def classify_columns(df: pd.DataFrame, timestamp_col: str, label_col: Optional[str]) -> Dict[str, str]:
    """
    Heuristically classifies columns into Sensor, Actuator, Setpoint, Controller, Status, Label, Timestamp.
    """
    classification = {}
    for col in df.columns:
        if col == timestamp_col:
            classification[col] = "Timestamp"
            continue
        if label_col and col == label_col:
            classification[col] = "Label"
            continue
            
        col_lower = str(col).lower()
        
        # Sample non-null values to assess cardinality
        non_null = df[col].dropna()
        if non_null.empty:
            classification[col] = "Unknown"
            continue
            
        unique_vals = non_null.unique()
        cardinality = len(unique_vals)
        dtype = df[col].dtype
        
        # Heuristics
        if cardinality == 2 or any(kw in col_lower for kw in ["fcv", "vlv", "valve", "pump", "state", "status_flag", "pmp", "sv"]):
            classification[col] = "Actuator"
        elif any(kw in col_lower for kw in ["setpoint", "_sp", "set_point", "ref", "setpoint"]):
            classification[col] = "Setpoint"
        elif any(kw in col_lower for kw in ["ctrl", "pid", "mv", "_op", "control"]):
            classification[col] = "Controller"
        elif cardinality <= 10 and not pd.api.types.is_float_dtype(dtype):
            classification[col] = "Status"
        elif pd.api.types.is_numeric_dtype(dtype):
            classification[col] = "Sensor"
        else:
            classification[col] = "Unknown"
            
    return classification

def analyze_temporal_integrity(df: pd.DataFrame, timestamp_col: str) -> Dict[str, Any]:
    """
    Verifies monotonic ordering, duplicate timestamps, missing intervals, and gap statistics.
    """
    report = {}
    ts = pd.to_datetime(df[timestamp_col])
    
    # 1. Monotonic check
    is_monotonic = ts.is_monotonic_increasing
    
    # 2. Duplicates
    dup_count = int(ts.duplicated().sum())
    
    # 3. Sampling interval estimation
    diffs = ts.drop_duplicates().diff().dt.total_seconds().dropna()
    sampling_interval = float(diffs.median()) if not diffs.empty else 1.0
    
    # 4. Gaps (where delta > 1.5 * sampling_interval)
    gap_count = 0
    if not diffs.empty:
        gap_count = int((diffs > 1.5 * sampling_interval).sum())
        
    # 5. Missing estimate
    total_duration = 0.0
    missing_count = 0
    if len(ts) > 1:
        total_duration = (ts.max() - ts.min()).total_seconds()
        expected_rows = int(total_duration / sampling_interval) + 1
        missing_count = max(0, expected_rows - len(ts.drop_duplicates()))
        
    report = {
        "is_monotonic": is_monotonic,
        "sampling_interval_seconds": sampling_interval,
        "duplicate_count": dup_count,
        "gap_count": gap_count,
        "missing_count": missing_count,
        "total_duration_seconds": total_duration,
        "row_count": len(df)
    }
    return report

def analyze_missing_values(df: pd.DataFrame, classification: Dict[str, str]) -> Dict[str, Any]:
    """
    Computes missing percentage and detects constant/near-constant columns.
    """
    report = {}
    for col in df.columns:
        if classification.get(col) in ["Timestamp", "Label"]:
            continue
            
        series = df[col]
        total_len = len(series)
        null_count = int(series.isnull().sum())
        null_pct = (null_count / total_len) * 100.0 if total_len > 0 else 0.0
        
        # Max consecutive missing segments
        consecutive_missing = 0
        if null_count > 0:
            is_null = series.isnull().astype(int)
            consecutive_missing = int(is_null.groupby(series.notnull().cumsum()).sum().max())
            
        # Constant / Near-constant
        nunique = int(series.nunique())
        status = "variable"
        if nunique <= 1:
            status = "constant"
        elif nunique <= 5:
            status = "near-constant"
            
        report[col] = {
            "missing_percentage": null_pct,
            "max_consecutive_missing": consecutive_missing,
            "unique_values_count": nunique,
            "status": status,
            "type": classification.get(col, "Unknown")
        }
    return report

class TimeseriesNormalizer:
    def __init__(self, timestamp_col: str = "timestamp", label_col: Optional[str] = "attack"):
        self.timestamp_col = timestamp_col
        self.label_col = label_col
        self.classification: Dict[str, str] = {}
        self.temporal_report: Dict[str, Any] = {}
        self.missing_report: Dict[str, Any] = {}

    def fit_normalize(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Fits column classifications and returns a normalized flat DataFrame.
        """
        # Sort chronologically
        df = df.copy()
        if self.timestamp_col in df.columns:
            df[self.timestamp_col] = pd.to_datetime(df[self.timestamp_col])
            df = df.sort_values(by=self.timestamp_col).reset_index(drop=True)
            
        # Classify columns
        self.classification = classify_columns(df, self.timestamp_col, self.label_col)
        
        # Analyze temporal structure
        if self.timestamp_col in df.columns:
            self.temporal_report = analyze_temporal_integrity(df, self.timestamp_col)
            
        # Analyze missing values
        self.missing_report = analyze_missing_values(df, self.classification)
        
        # Perform flat normalization mapping
        normalized_df = pd.DataFrame()
        normalized_df["timestamp"] = df[self.timestamp_col].dt.strftime("%Y-%m-%d %H:%M:%S")
        normalized_df["window_index"] = normalized_df.index
        
        if self.label_col and self.label_col in df.columns:
            # Map labels to binary integer (0 or 1)
            normalized_df["attack_label"] = df[self.label_col].fillna(0).astype(int)
        else:
            normalized_df["attack_label"] = 0

        # Build dynamic fields based on classifications
        for col, group in self.classification.items():
            if group in ["Timestamp", "Label"]:
                continue
            
            # Map value, handle NaNs
            val = df[col].astype(float) if pd.api.types.is_numeric_dtype(df[col].dtype) else df[col]
            
            # We prefix the column name to keep track of its role
            normalized_df[f"{group.lower()}_{col}"] = val

        return normalized_df

    def to_normalized_rows(self, normalized_df: pd.DataFrame) -> List[NormalizedOTRow]:
        """
        Converts normalized DataFrame rows into NormalizedOTRow object representations.
        """
        rows = []
        for idx, row in normalized_df.iterrows():
            sensor_vals = {}
            actuator_states = {}
            controller_states = {}
            setpoints = {}
            status_flags = {}
            
            for col, val in row.items():
                if col.startswith("sensor_"):
                    sensor_vals[col.replace("sensor_", "")] = float(val) if pd.notna(val) else np.nan
                elif col.startswith("actuator_"):
                    actuator_states[col.replace("actuator_", "")] = float(val) if pd.notna(val) else np.nan
                elif col.startswith("controller_"):
                    controller_states[col.replace("controller_", "")] = float(val) if pd.notna(val) else np.nan
                elif col.startswith("setpoint_"):
                    setpoints[col.replace("setpoint_", "")] = float(val) if pd.notna(val) else np.nan
                elif col.startswith("status_"):
                    status_flags[col.replace("status_", "")] = float(val) if pd.notna(val) else np.nan
                    
            rows.append(NormalizedOTRow(
                timestamp=str(row["timestamp"]),
                window_index=int(row["window_index"]),
                attack_label=int(row["attack_label"]),
                sensor_values=sensor_vals,
                actuator_states=actuator_states,
                controller_states=controller_states,
                setpoints=setpoints,
                status_flags=status_flags,
                raw_row=row.to_dict()
            ))
        return rows
