import os
import logging
from pathlib import Path
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[3]
# Attempt to load a .env file from the project root if it exists
load_dotenv(PROJECT_ROOT / ".env")

class ConfigManager:
    """Central configuration manager for Sentinel-Prime.
    
    All runtime configuration is centralised here. Modules should import
    `from sentinel_prime.core.config_manager import config` and read values
    as `config.SOME_KEY` rather than calling os.getenv directly.
    """
    
    # ── AI / LLM ──────────────────────────────────────────────────────────────
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    
    # ── Elasticsearch / SIEM ─────────────────────────────────────────────────
    ES_HOST: str = os.getenv("ES_HOST", "http://localhost:9200")
    ES_INDEX: str = os.getenv("ES_INDEX", "sentinel-honeypot")
    ES_API_KEY: str = os.getenv("ES_API_KEY", "")
    
    # ── Webhook Receiver (Honeypot) ───────────────────────────────────────────
    HONEYPOT_LOG_DIR: Path = Path(os.getenv("HONEYPOT_LOG_DIR", str(PROJECT_ROOT / "data" / "honeypot_events")))
    RECEIVER_PORT: int = int(os.getenv("RECEIVER_PORT", "5050"))
    RECEIVER_HOST: str = os.getenv("RECEIVER_HOST", "0.0.0.0")
    HONEYPOT_API_KEY: str = os.getenv("HONEYPOT_API_KEY", "")
    
    # ── API Server ────────────────────────────────────────────────────────────
    API_PORT: int = int(os.getenv("PORT", "8000"))
    API_HOST: str = os.getenv("API_HOST", "127.0.0.1")
    
    # ── Data Paths ────────────────────────────────────────────────────────────
    DATA_DIR: Path = Path(os.getenv("DATA_DIR", str(PROJECT_ROOT / "data")))
    PROCESSED_DIR: Path = Path(os.getenv("PROCESSED_DIR", str(PROJECT_ROOT / "processed")))
    DECOY_DIR: Path = Path(os.getenv("DECOY_DIR", str(PROJECT_ROOT / "data" / "decoys")))
    AUDIT_LEDGER_PATH: Path = Path(os.getenv("AUDIT_LEDGER_PATH", str(PROJECT_ROOT / "data" / "audit_ledger.jsonl")))
    
    # ── ML Model Artifacts ────────────────────────────────────────────────────
    MODEL_PATH: Path = Path(os.getenv("MODEL_PATH", str(PROJECT_ROOT / "models")))
    OTRF_DATASET_PATH: str = os.getenv("OTRF_DATASET_PATH", "")
    
    # ── Logging ───────────────────────────────────────────────────────────────
    LOG_LEVEL: int = getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO)

config = ConfigManager()
