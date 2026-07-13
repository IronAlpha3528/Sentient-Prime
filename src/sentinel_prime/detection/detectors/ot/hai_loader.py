import zipfile
import logging
import io
from pathlib import Path
from typing import Generator, Dict, Any, Optional
import pandas as pd

logger = logging.getLogger(__name__)

def load_ot_dataset_incremental(
    file_path: str,
    chunk_size: int = 10000,
    timestamp_col: Optional[str] = None
) -> Generator[pd.DataFrame, None, None]:
    """
    Incrementally loads CSV or Parquet files in chunks.
    Supports nested zip paths containing "::" to read directly from compressed members.
    """
    if "::" in file_path:
        parts = file_path.split("::")
        zip_path = parts[0]
        member_name = parts[1]
        
        logger.info(f"Streaming ZIP member '{member_name}' from '{zip_path}' in chunks of {chunk_size}")
        try:
            with zipfile.ZipFile(zip_path, "r") as z:
                # Detect separator
                with z.open(member_name) as z_file:
                    first_bytes = z_file.read(2000)
                    sep = ";" if b";" in first_bytes else ","
                
                # Open again to read CSV
                with z.open(member_name) as z_file:
                    reader = pd.read_csv(z_file, sep=sep, chunksize=chunk_size, low_memory=False)
                    for chunk in reader:
                        chunk = _clean_chunk(chunk, timestamp_col)
                        yield chunk
        except Exception as e:
            logger.error(f"Error loading ZIP member {member_name}: {e}")
            raise
    else:
        logger.info(f"Streaming flat dataset '{file_path}' in chunks of {chunk_size}")
        ext = Path(file_path).suffix.lower()
        try:
            if ext == ".parquet":
                # For Parquet, chunking is done by reading row groups
                import pyarrow.parquet as pq
                pf = pq.ParquetFile(file_path)
                for i in range(pf.num_row_groups):
                    df = pf.read_row_group(i).to_pandas()
                    df = _clean_chunk(df, timestamp_col)
                    yield df
            else:
                # Detect separator
                with open(file_path, "rb") as f:
                    first_bytes = f.read(2000)
                    sep = ";" if b";" in first_bytes else ","
                
                # Default CSV chunking
                reader = pd.read_csv(file_path, sep=sep, chunksize=chunk_size, low_memory=False)
                for chunk in reader:
                    chunk = _clean_chunk(chunk, timestamp_col)
                    yield chunk
        except Exception as e:
            logger.error(f"Error loading flat dataset {file_path}: {e}")
            raise

def _clean_chunk(df: pd.DataFrame, timestamp_col: Optional[str]) -> pd.DataFrame:
    """
    Applies standard cleanup on the chunk: parses timestamp, trims whitespace, maps nulls.
    """
    df = df.copy()
    
    # Strip whitespace from string columns
    for col in df.select_dtypes(include="object").columns:
        try:
            df[col] = df[col].astype(str).str.strip()
        except Exception:
            pass

    # Standardize timestamp if specified
    if timestamp_col and timestamp_col in df.columns:
        df[timestamp_col] = pd.to_datetime(df[timestamp_col])
        
    return df
