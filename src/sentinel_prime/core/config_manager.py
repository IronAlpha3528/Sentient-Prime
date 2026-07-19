import os
from pathlib import Path
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[3]
# Attempt to load a .env file from the project root if it exists
load_dotenv(PROJECT_ROOT / ".env")

class ConfigManager:
    """Central configuration manager for Sentinel-Prime."""
    
    # AI Config
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
    
    # Elasticsearch Config
    ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")
    ES_INDEX = os.getenv("ES_INDEX", "sentinel-honeypot")
    ES_API_KEY = os.getenv("ES_API_KEY", "")
    
    # Webhook Receiver Config
    HONEYPOT_LOG_DIR = Path(os.getenv("HONEYPOT_LOG_DIR", str(PROJECT_ROOT / "data" / "honeypot_events")))
    RECEIVER_PORT = int(os.getenv("RECEIVER_PORT", "5050"))
    RECEIVER_HOST = os.getenv("RECEIVER_HOST", "0.0.0.0")
    HONEYPOT_API_KEY = os.getenv("HONEYPOT_API_KEY", "")
    
    # API Server Config
    API_PORT = int(os.getenv("PORT", "8000"))
    API_HOST = os.getenv("API_HOST", "127.0.0.1")
    
    # Dataset Config
    OTRF_DATASET_PATH = os.getenv("OTRF_DATASET_PATH", "")

config = ConfigManager()
