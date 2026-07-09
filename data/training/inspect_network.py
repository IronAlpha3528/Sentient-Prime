import pandas as pd

from data.training.network_common import clean_frame, find_label_column, parquet_files


def main() -> None:
    files = parquet_files()
    if not files:
        raise FileNotFoundError(
            "No Parquet files found under data/raw/cse-cic/archive (1)/"
        )

    print(f"Found {len(files)} Parquet files")
    for path in files:
        frame = clean_frame(pd.read_parquet(path).head(5000))
        label = find_label_column(frame)
        print("\nFILE:", path)
        print("ROWS INSPECTED:", len(frame))
        print("COLUMN COUNT:", len(frame.columns))
        print("LABEL COLUMN:", label)
        print("LABEL COUNTS:")
        print(frame[label].astype(str).str.strip().value_counts().head(20))


if __name__ == "__main__":
    main()
