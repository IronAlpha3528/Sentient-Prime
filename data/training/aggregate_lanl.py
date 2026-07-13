import bz2
import csv
import json
from collections import defaultdict
from pathlib import Path
import numpy as np
import pandas as pd

INPUT = Path("data/raw/lanl-auth/lanl-auth-dataset-1-00.bz2")
OUTPUT_DIR = Path("data/processed/identity")
FULL_OUTPUT = OUTPUT_DIR / "lanl_user_hour_windows.parquet"
TRAIN_OUTPUT = OUTPUT_DIR / "train.parquet"
TEST_OUTPUT = OUTPUT_DIR / "test.parquet"
METADATA_OUTPUT = OUTPUT_DIR / "metadata.json"

WINDOW_SECONDS = 3600
MAX_ROWS = 5_000_000
MIN_HISTORY_WINDOWS = 3
NORMAL_HOURS_START = 8
NORMAL_HOURS_END = 20
MINIMUM_DURATION_HOURS = 0.001
MIN_STD_EPSILON = 0.0001
ZSCORE_CLIP_MIN = -10.0
ZSCORE_CLIP_MAX = 10.0


def process_window(window_id, window_data, user_seen_computers, user_history):
    rows = []
    for user, state in window_data.items():
        times = sorted(state["times"])
        computers = state["computers"]

        auth_count = len(times)
        unique_computers = len(computers)

        # 1. Active duration and fanout rate
        active_duration_seconds = times[-1] - times[0]
        active_duration_hours = active_duration_seconds / 3600.0
        fanout_rate = unique_computers / max(active_duration_hours, MINIMUM_DURATION_HOURS)

        # 2. Auth gap statistics
        gaps = [times[i] - times[i - 1] for i in range(1, len(times))]
        mean_auth_gap = sum(gaps) / len(gaps) if gaps else 0.0
        min_auth_gap = min(gaps) if gaps else 0.0
        max_auth_gap = max(gaps) if gaps else 0.0

        # 3. New computer features (using state BEFORE update)
        seen = user_seen_computers[user]
        new_computers = computers - seen
        new_computer_count = len(new_computers)
        new_computer_ratio = new_computer_count / unique_computers

        # 4. User historical stats & z-scores (using state BEFORE update)
        prev_auth_counts = user_history[user]["auth_counts"]
        prev_unique_computers = user_history[user]["unique_computers_counts"]
        
        # Ensure backward compatibility with existing unit tests
        if "mean_auth_gaps" not in user_history[user]:
            user_history[user]["mean_auth_gaps"] = []
        if "fanout_rates" not in user_history[user]:
            user_history[user]["fanout_rates"] = []
            
        prev_gaps = user_history[user]["mean_auth_gaps"]
        prev_fanout_rates = user_history[user]["fanout_rates"]

        # auth_count baseline
        history_len = len(prev_auth_counts)
        if history_len >= MIN_HISTORY_WINDOWS:
            auth_mean = sum(prev_auth_counts) / history_len
            auth_variance = sum((x - auth_mean) ** 2 for x in prev_auth_counts) / history_len
            auth_std = auth_variance ** 0.5
            if auth_std < MIN_STD_EPSILON:
                raw_auth_count_zscore = 0.0
            else:
                raw_auth_count_zscore = (auth_count - auth_mean) / auth_std

            comp_mean = sum(prev_unique_computers) / history_len
            comp_variance = sum((x - comp_mean) ** 2 for x in prev_unique_computers) / history_len
            comp_std = comp_variance ** 0.5
            if comp_std < MIN_STD_EPSILON:
                raw_unique_computers_zscore = 0.0
            else:
                raw_unique_computers_zscore = (unique_computers - comp_mean) / comp_std
        else:
            auth_mean = 0.0
            auth_std = 0.0
            raw_auth_count_zscore = 0.0
            comp_mean = 0.0
            comp_std = 0.0
            raw_unique_computers_zscore = 0.0

        # fanout_rate baseline
        history_len_fanout = len(prev_fanout_rates)
        if history_len_fanout >= MIN_HISTORY_WINDOWS:
            fanout_mean = sum(prev_fanout_rates) / history_len_fanout
            fanout_variance = sum((x - fanout_mean) ** 2 for x in prev_fanout_rates) / history_len_fanout
            fanout_std = fanout_variance ** 0.5
            if fanout_std < MIN_STD_EPSILON:
                raw_fanout_rate_zscore = 0.0
            else:
                raw_fanout_rate_zscore = (fanout_rate - fanout_mean) / fanout_std
        else:
            fanout_mean = 0.0
            fanout_std = 0.0
            raw_fanout_rate_zscore = 0.0

        # mean_auth_gap baseline (explicit timing gap checks)
        history_len_gaps = len(prev_gaps)
        if auth_count < 2:
            has_auth_gap = 0
            raw_mean_auth_gap_zscore = 0.0
            gap_mean = 0.0
            gap_std = 0.0
        else:
            has_auth_gap = 1
            if history_len_gaps >= MIN_HISTORY_WINDOWS:
                gap_mean = sum(prev_gaps) / history_len_gaps
                gap_variance = sum((x - gap_mean) ** 2 for x in prev_gaps) / history_len_gaps
                gap_std = gap_variance ** 0.5
                if gap_std < MIN_STD_EPSILON:
                    raw_mean_auth_gap_zscore = 0.0
                else:
                    raw_mean_auth_gap_zscore = (mean_auth_gap - gap_mean) / gap_std
            else:
                gap_mean = 0.0
                gap_std = 0.0
                raw_mean_auth_gap_zscore = 0.0

        # Clip z-scores for ML model, keeping raw z-scores for context
        auth_count_zscore = float(np.clip(raw_auth_count_zscore, ZSCORE_CLIP_MIN, ZSCORE_CLIP_MAX))
        unique_computers_zscore = float(np.clip(raw_unique_computers_zscore, ZSCORE_CLIP_MIN, ZSCORE_CLIP_MAX))
        mean_auth_gap_zscore = float(np.clip(raw_mean_auth_gap_zscore, ZSCORE_CLIP_MIN, ZSCORE_CLIP_MAX))
        fanout_rate_zscore = float(np.clip(raw_fanout_rate_zscore, ZSCORE_CLIP_MIN, ZSCORE_CLIP_MAX))

        # 5. Hour and off-hours flag
        hour_of_day = int(window_id % 24)
        off_hours_flag = 1 if (hour_of_day < NORMAL_HOURS_START or hour_of_day > NORMAL_HOURS_END) else 0

        rows.append({
            "user": user,
            "window_id": window_id,
            "auth_count": auth_count,
            "unique_computers": unique_computers,
            "fanout_rate": fanout_rate,
            "mean_auth_gap": mean_auth_gap,
            "min_auth_gap": min_auth_gap,
            "max_auth_gap": max_auth_gap,
            "new_computer_count": new_computer_count,
            "new_computer_ratio": new_computer_ratio,
            "auth_count_user_mean": auth_mean,
            "auth_count_user_std": auth_std,
            "raw_auth_count_zscore": raw_auth_count_zscore,
            "auth_count_zscore": auth_count_zscore,
            "unique_computers_user_mean": comp_mean,
            "unique_computers_user_std": comp_std,
            "raw_unique_computers_zscore": raw_unique_computers_zscore,
            "unique_computers_zscore": unique_computers_zscore,
            "mean_auth_gap_user_mean": gap_mean,
            "mean_auth_gap_user_std": gap_std,
            "raw_mean_auth_gap_zscore": raw_mean_auth_gap_zscore,
            "mean_auth_gap_zscore": mean_auth_gap_zscore,
            "has_auth_gap": has_auth_gap,
            "fanout_rate_user_mean": fanout_mean,
            "fanout_rate_user_std": fanout_std,
            "raw_fanout_rate_zscore": raw_fanout_rate_zscore,
            "fanout_rate_zscore": fanout_rate_zscore,
            "hour_of_day": hour_of_day,
            "off_hours_flag": off_hours_flag
        })

        # 6. AFTER feature calculation, update state (Data Leakage Prevention!)
        user_seen_computers[user].update(computers)
        user_history[user]["auth_counts"].append(auth_count)
        user_history[user]["unique_computers_counts"].append(unique_computers)
        if auth_count >= 2:
            user_history[user]["mean_auth_gaps"].append(mean_auth_gap)
        user_history[user]["fanout_rates"].append(fanout_rate)

    return rows


def main() -> None:
    if not INPUT.exists():
        raise FileNotFoundError(INPUT)

    user_seen_computers = defaultdict(set)
    user_history = defaultdict(lambda: {
        "auth_counts": [],
        "unique_computers_counts": [],
        "mean_auth_gaps": [],
        "fanout_rates": []
    })

    current_window_id = None
    current_window_data = defaultdict(lambda: {"times": [], "computers": set()})
    processed = 0
    all_rows = []

    print("Streaming and aggregating LANL dataset chronologically...")
    with bz2.open(INPUT, "rt", encoding="utf-8") as source:
        reader = csv.reader(source)
        for row in reader:
            if len(row) != 3:
                continue

            timestamp, user, computer = int(row[0]), row[1], row[2]
            window_id = timestamp // WINDOW_SECONDS

            if current_window_id is None:
                current_window_id = window_id

            if window_id > current_window_id:
                # Process completed window
                window_rows = process_window(
                    current_window_id, current_window_data,
                    user_seen_computers, user_history
                )
                all_rows.extend(window_rows)
                current_window_data = defaultdict(lambda: {"times": [], "computers": set()})
                current_window_id = window_id

            current_window_data[user]["times"].append(timestamp)
            current_window_data[user]["computers"].add(computer)

            processed += 1
            if MAX_ROWS is not None and processed >= MAX_ROWS:
                break

        # Process final active window
        if current_window_data:
            window_rows = process_window(
                current_window_id, current_window_data,
                user_seen_computers, user_history
            )
            all_rows.extend(window_rows)

    df = pd.DataFrame(all_rows)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    # Save full parquet
    df.to_parquet(FULL_OUTPUT, index=False)

    # Perform a Temporal Split (80% training / 20% test based on window_id time boundary)
    unique_windows = sorted(df["window_id"].unique())
    cutoff_idx = int(0.8 * len(unique_windows))
    
    if cutoff_idx == 0 or cutoff_idx >= len(unique_windows):
        temporal_cutoff = unique_windows[0]
    else:
        temporal_cutoff = unique_windows[cutoff_idx - 1]

    train_df = df[df["window_id"] <= temporal_cutoff]
    test_df = df[df["window_id"] > temporal_cutoff]

    train_df.to_parquet(TRAIN_OUTPUT, index=False)
    test_df.to_parquet(TEST_OUTPUT, index=False)

    feature_columns = [
        "auth_count",
        "unique_computers",
        "fanout_rate",
        "mean_auth_gap",
        "min_auth_gap",
        "max_auth_gap",
        "new_computer_count",
        "new_computer_ratio",
        "raw_auth_count_zscore",
        "auth_count_zscore",
        "raw_unique_computers_zscore",
        "unique_computers_zscore",
        "raw_mean_auth_gap_zscore",
        "mean_auth_gap_zscore",
        "has_auth_gap",
        "raw_fanout_rate_zscore",
        "fanout_rate_zscore",
        "hour_of_day",
        "off_hours_flag"
    ]

    metadata = {
        "feature_columns": feature_columns,
        "train_rows": len(train_df),
        "test_rows": len(test_df),
        "train_min_window": int(train_df["window_id"].min()) if not train_df.empty else 0,
        "train_max_window": int(train_df["window_id"].max()) if not train_df.empty else 0,
        "test_min_window": int(test_df["window_id"].min()) if not test_df.empty else 0,
        "test_max_window": int(test_df["window_id"].max()) if not test_df.empty else 0,
        "temporal_cutoff": int(temporal_cutoff),
        "min_history_windows": MIN_HISTORY_WINDOWS,
        "min_std_epsilon": MIN_STD_EPSILON,
        "zscore_clip_min": ZSCORE_CLIP_MIN,
        "zscore_clip_max": ZSCORE_CLIP_MAX,
        "raw_events_processed": processed,
        "behavioural_windows_created": len(df)
    }

    METADATA_OUTPUT.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    print("\n--- Aggregation and Temporal Split Complete ---")
    print(f"Total raw events processed: {processed}")
    print(f"Total behavioural windows created: {len(df)}")
    print(f"Temporal cutoff window_id: {temporal_cutoff}")
    print(f"Train rows: {len(train_df)} (Windows: {metadata['train_min_window']} to {metadata['train_max_window']})")
    print(f"Test rows: {len(test_df)} (Windows: {metadata['test_min_window']} to {metadata['test_max_window']})")
    print(f"Metadata saved to: {METADATA_OUTPUT}")


if __name__ == "__main__":
    main()
