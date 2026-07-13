import json
import csv
import io
import yaml
import logging
from typing import Generator, Dict, Any, List

logger = logging.getLogger(__name__)

def parse_telemetry_content(member_name: str, content: str) -> Generator[Dict[str, Any], None, None]:
    """
    Parses a telemetry file's raw content and yields raw dict events.
    """
    ext = member_name.split(".")[-1].lower() if "." in member_name else ""
    content_stripped = content.strip()
    if not content_stripped:
        return

    if ext in ["json", "jsonl", "ndjson"]:
        # Try parsing as JSON array
        if content_stripped.startswith("[") and content_stripped.endswith("]"):
            try:
                events = json.loads(content_stripped)
                if isinstance(events, list):
                    for ev in events:
                        if isinstance(ev, dict):
                            yield ev
                elif isinstance(events, dict):
                    yield events
            except json.JSONDecodeError:
                # Fallback to line-by-line NDJSON
                for line in content_stripped.splitlines():
                    line = line.strip()
                    if line:
                        try:
                            yield json.loads(line)
                        except json.JSONDecodeError as e:
                            logger.warning(f"Failed to parse line in {member_name}: {e}")
        else:
            # Parse line by line (NDJSON/JSONL)
            for line in content_stripped.splitlines():
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse JSON line in {member_name}: {e}")

    elif ext == "csv":
        try:
            f = io.StringIO(content_stripped)
            reader = csv.DictReader(f)
            for row in reader:
                # Convert csv fields into a dictionary
                yield dict(row)
        except Exception as e:
            logger.warning(f"Failed to parse CSV in {member_name}: {e}")

    elif ext in ["yaml", "yml"]:
        try:
            data = yaml.safe_load(content_stripped)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        yield item
            elif isinstance(data, dict):
                yield data
        except Exception as e:
            logger.warning(f"Failed to parse YAML in {member_name}: {e}")
    else:
        logger.warning(f"Unknown telemetry format for {member_name}")
