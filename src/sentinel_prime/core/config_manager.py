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
    @property
    def GEMINI_API_KEY(self) -> str:
        return os.getenv("GEMINI_API_KEY", "")
        
    @property
    def GEMINI_API_KEY_ANALYSIS(self) -> str:
        return self.GEMINI_API_KEY
        
    @property
    def GEMINI_API_KEY_CRITIQUE(self) -> str:
        return self.GEMINI_API_KEY
        
    @property
    def GEMINI_API_KEY_ACTION(self) -> str:
        return self.GEMINI_API_KEY
    
    # ── Elasticsearch / SIEM ─────────────────────────────────────────────────
    @property
    def ES_HOST(self) -> str:
        return os.getenv("ES_HOST", "http://localhost:9200")
    
    @property
    def ES_INDEX(self) -> str:
        return os.getenv("ES_INDEX", "sentinel-honeypot")
    
    @property
    def ES_API_KEY(self) -> str:
        return os.getenv("ES_API_KEY", "")
    
    # ── Webhook Receiver (Honeypot) ───────────────────────────────────────────
    @property
    def HONEYPOT_LOG_DIR(self) -> Path:
        return Path(os.getenv("HONEYPOT_LOG_DIR", str(PROJECT_ROOT / "data" / "honeypot_events")))
    
    @property
    def RECEIVER_PORT(self) -> int:
        return int(os.getenv("RECEIVER_PORT", "5050"))
    
    @property
    def RECEIVER_HOST(self) -> str:
        return os.getenv("RECEIVER_HOST", "0.0.0.0")
    
    @property
    def HONEYPOT_API_KEY(self) -> str:
        return os.getenv("HONEYPOT_API_KEY", "")
    
    # ── API Server ────────────────────────────────────────────────────────────
    @property
    def API_PORT(self) -> int:
        return int(os.getenv("PORT", "8000"))
    
    @property
    def API_HOST(self) -> str:
        return os.getenv("API_HOST", "127.0.0.1")
    
    # ── Data Paths ────────────────────────────────────────────────────────────
    @property
    def DATA_DIR(self) -> Path:
        return Path(os.getenv("DATA_DIR", str(PROJECT_ROOT / "data")))
    
    @property
    def PROCESSED_DIR(self) -> Path:
        return Path(os.getenv("PROCESSED_DIR", str(PROJECT_ROOT / "processed")))
    
    @property
    def DECOY_DIR(self) -> Path:
        return Path(os.getenv("DECOY_DIR", str(PROJECT_ROOT / "data" / "decoys")))
    
    @property
    def AUDIT_LEDGER_PATH(self) -> Path:
        return Path(os.getenv("AUDIT_LEDGER_PATH", str(PROJECT_ROOT / "data" / "audit_ledger.jsonl")))
    
    # ── ML Model Artifacts ────────────────────────────────────────────────────
    @property
    def MODEL_PATH(self) -> Path:
        return Path(os.getenv("MODEL_PATH", str(PROJECT_ROOT / "models")))
    
    @property
    def OTRF_DATASET_PATH(self) -> str:
        return os.getenv("OTRF_DATASET_PATH", "")
    
    # ── Logging ───────────────────────────────────────────────────────────────
    @property
    def LOG_LEVEL(self) -> int:
        return getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO)

config = ConfigManager()
