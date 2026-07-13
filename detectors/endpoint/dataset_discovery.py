import os
from pathlib import Path
from typing import List
import zipfile
import logging

from detectors.endpoint.schemas import ArchiveManifest

logger = logging.getLogger(__name__)

class DatasetNotFoundError(FileNotFoundError):
    """Custom exception raised when the OTRF dataset directory cannot be found."""
    pass

def get_otrf_path() -> Path:
    env_path = os.environ.get("OTRF_DATASET_PATH")
    if env_path:
        path = Path(env_path)
        if path.exists():
            return path
        raise DatasetNotFoundError(
            f"Configured OTRF_DATASET_PATH does not exist: {env_path}"
        )

    # Preferred local development path
    default_dev_path = Path(r"C:\Users\Aanoush Surana\OneDrive\Desktop\ET Hackathon\OTRF-Endpoint-Data\datasets\atomic\windows")
    if default_dev_path.exists():
        return default_dev_path

    # Attempt relative path discovery relative to Sentient-Prime repository folder
    # Sentient-Prime/detectors/endpoint/dataset_discovery.py is 3 levels deep from root
    relative_path = Path(__file__).resolve().parents[3] / "OTRF-Endpoint-Data" / "datasets" / "atomic" / "windows"
    if relative_path.exists():
        return relative_path

    raise DatasetNotFoundError(
        "OTRF dataset path not found. Please set the environment variable 'OTRF_DATASET_PATH' "
        "pointing to datasets/atomic/windows in the OTRF repository."
    )

def discover_archives() -> List[ArchiveManifest]:
    otrf_path = get_otrf_path()
    logger.info(f"Discovering archives under OTRF path: {otrf_path}")
    
    all_zips = list(otrf_path.rglob("*.zip"))
    host_zips = []
    
    for z_path in all_zips:
        # Select only archives whose path contains a 'host' directory
        if "host" in [part.lower() for part in z_path.parts]:
            host_zips.append(z_path)

    manifests = []
    for z_path in host_zips:
        try:
            stat_info = z_path.stat()
            archive_size = stat_info.st_size
            
            with zipfile.ZipFile(z_path, "r") as z_file:
                members = z_file.infolist()
                member_names = [m.filename for m in members]
                compressed_size = sum(m.compress_size for m in members)
                
                telemetry_files = []
                metadata_files = []
                
                for m in members:
                    ext = Path(m.filename).suffix.lower()
                    if ext in [".json", ".jsonl", ".ndjson", ".csv"]:
                        telemetry_files.append(m.filename)
                    elif ext in [".yaml", ".yml", ".md", ".txt"]:
                        metadata_files.append(m.filename)

                manifest = ArchiveManifest(
                    archive_path=str(z_path),
                    relative_path=str(z_path.relative_to(otrf_path)),
                    archive_size=archive_size,
                    compressed_size=compressed_size,
                    member_list=member_names,
                    telemetry_files=telemetry_files,
                    metadata_files=metadata_files
                )
                manifests.append(manifest)
        except Exception as e:
            logger.error(f"Error reading archive metadata for {z_path}: {e}")
            # Continue on a malformed archive but don't include it or handle gracefully
            
    return manifests
