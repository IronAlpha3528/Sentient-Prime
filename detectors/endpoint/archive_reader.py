import zipfile
import logging
from typing import Generator, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)

def stream_telemetry_files(archive_path: str) -> Generator[Tuple[str, str], None, None]:
    """
    Opens a single archive, streams the content of telemetry files, and closes it immediately.
    Yields (member_name, text_content).
    """
    path = Path(archive_path)
    if not path.exists():
        logger.error(f"Archive path does not exist: {archive_path}")
        return

    try:
        with zipfile.ZipFile(path, "r") as z_file:
            for member in z_file.infolist():
                ext = Path(member.filename).suffix.lower()
                if ext in [".json", ".jsonl", ".ndjson", ".csv", ".yaml", ".yml"]:
                    try:
                        with z_file.open(member.filename) as f:
                            content = f.read().decode("utf-8", errors="ignore")
                            yield member.filename, content
                    except Exception as e:
                        logger.error(f"Failed to read member {member.filename} from {path.name}: {e}")
    except Exception as e:
        logger.error(f"Failed to open zip archive {archive_path}: {e}")
