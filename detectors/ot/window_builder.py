import logging
from typing import Generator, Dict, Any, List
import pandas as pd
from detectors.ot.schemas import WindowMetadata

logger = logging.getLogger(__name__)

def build_sliding_windows(
    df: pd.DataFrame,
    window_length: int = 60,
    stride: int = 10,
    host_name: str = "CNI-Process-PLC"
) -> Generator[Dict[str, Any], None, None]:
    """
    Slices the normalized flat DataFrame into sliding windows of fixed length.
    Ensures that every window has exactly `window_length` rows.
    """
    total_rows = len(df)
    if total_rows < window_length:
        logger.warning(f"Dataset length {total_rows} is less than window length {window_length}. No windows generated.")
        return

    num_windows = (total_rows - window_length) // stride + 1
    logger.info(f"Generating {num_windows} sliding windows of length {window_length} with stride {stride}")

    for i in range(0, total_rows - window_length + 1, stride):
        win_df = df.iloc[i : i + window_length]
        
        start_ts = str(win_df["timestamp"].iloc[0])
        end_ts = str(win_df["timestamp"].iloc[-1])
        
        # Format window ID
        win_id = f"win_{start_ts.replace(' ', '_').replace(':', '-')}_{end_ts.replace(' ', '_').replace(':', '-')}"
        
        # Calculate labels and ratio
        attack_vals = win_df["attack_label"].fillna(0).astype(int)
        attack_sum = int(attack_vals.sum())
        attack_ratio = float(attack_vals.mean())
        label = 1 if attack_sum > 0 else 0
        
        meta = WindowMetadata(
            window_id=win_id,
            start_time=start_ts,
            end_time=end_ts,
            host=host_name,
            label=label,
            duration_seconds=float(window_length), # 1s sampling rate
            row_count=window_length,
            attack_ratio=attack_ratio
        )
        
        yield {
            "metadata": meta,
            "data": win_df
        }
