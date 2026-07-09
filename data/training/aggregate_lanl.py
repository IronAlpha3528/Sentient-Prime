import bz2
import csv
from collections import defaultdict
from pathlib import Path

import pandas as pd


INPUT = Path("data/raw/lanl-auth/lanl-auth-dataset-1-00.bz2")
OUTPUT = Path("data/processed/identity/lanl_user_hour_windows.parquet")
WINDOW_SECONDS = 3600
MAX_ROWS = 5_000_000


def main() -> None:
    if not INPUT.exists():
        raise FileNotFoundError(INPUT)

    windows = defaultdict(
        lambda: {"auth_count": 0, "computers": set(), "times": []}
    )
    processed = 0

    with bz2.open(INPUT, "rt", encoding="utf-8") as source:
        for row in csv.reader(source):
            if len(row) != 3:
                continue

            timestamp, user, computer = int(row[0]), row[1], row[2]
            key = (user, timestamp // WINDOW_SECONDS)
            state = windows[key]
            state["auth_count"] += 1
            state["computers"].add(computer)
            state["times"].append(timestamp)

            processed += 1
            if MAX_ROWS is not None and processed >= MAX_ROWS:
                break

    rows = []
    for (user, window_id), state in windows.items():
        times = sorted(state["times"])
        gaps = [
            times[index] - times[index - 1]
            for index in range(1, len(times))
        ]
        rows.append(
            {
                "user": user,
                "window_id": window_id,
                "auth_count": state["auth_count"],
                "unique_computers": len(state["computers"]),
                "computer_fanout": len(state["computers"]),
                "mean_auth_gap": sum(gaps) / len(gaps) if gaps else 0.0,
                "min_auth_gap": min(gaps) if gaps else 0.0,
                "max_auth_gap": max(gaps) if gaps else 0.0,
            }
        )

    frame = pd.DataFrame(rows)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    frame.to_parquet(OUTPUT, index=False)

    print(frame.head())
    print("Events processed:", processed)
    print("Behaviour windows:", len(frame))
    print("Saved:", OUTPUT)


if __name__ == "__main__":
    main()
