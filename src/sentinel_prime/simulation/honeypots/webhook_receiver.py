"""
Sentinel — Canarytoken Webhook Receiver

A FastAPI application that accepts Canarytoken webhook POST requests,
normalizes them into the Sentinel unified event schema, and forwards
them to Elasticsearch (or falls back to a local JSON log file).

Usage:
    python -m honeypots.webhook_receiver

    # Or with environment variables:
    ES_HOST=https://localhost:9200 ES_INDEX=sentinel-honeypot python -m honeypots.webhook_receiver
"""

import hashlib
import json
import logging
import time
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

# Configuration (from environment or defaults)
from sentinel_prime.core.config_manager import config

ES_HOST = config.ES_HOST
ES_INDEX = config.ES_INDEX
ES_API_KEY = config.ES_API_KEY
LOG_DIR = config.HONEYPOT_LOG_DIR
RECEIVER_PORT = config.RECEIVER_PORT
RECEIVER_HOST = config.RECEIVER_HOST

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sentinel.honeypot.receiver")

# ---------------------------------------------------------------------------
# Elasticsearch client (lazy init)
# ---------------------------------------------------------------------------

_es_client = None


def _get_es_client():
    """Lazily initialize the Elasticsearch client if ES_HOST is configured."""
    global _es_client
    if _es_client is not None:
        return _es_client

    if not ES_HOST:
        return None

    try:
        from elasticsearch import Elasticsearch

        connect_kwargs = {"hosts": [ES_HOST], "verify_certs": False}
        if ES_API_KEY:
            connect_kwargs["api_key"] = ES_API_KEY

        _es_client = Elasticsearch(**connect_kwargs)
        info = _es_client.info()
        logger.info(
            "Connected to Elasticsearch %s at %s",
            info["version"]["number"],
            ES_HOST,
        )
        return _es_client
    except Exception as exc:
        logger.warning("Elasticsearch unavailable (%s) — falling back to local log", exc)
        return None


# ---------------------------------------------------------------------------
# Event normalization
# ---------------------------------------------------------------------------


def normalize_canarytoken_event(payload: dict) -> dict:
    """
    Normalize a raw Canarytoken webhook payload into the Sentinel
    unified event schema.

    Canarytoken payloads vary by token type but typically include:
    - memo: description set when creating the token
    - channel: alert channel (e.g., "DNS", "HTTP")
    - src_ip: source IP that triggered the token
    - token: the token identifier
    - time: timestamp of the trigger

    Returns a normalized event dict.
    """
    now = datetime.now(timezone.utc).isoformat()

    # Extract source IP — Canarytokens may nest it in different places
    src_ip = (
        payload.get("src_ip")
        or payload.get("source_ip")
        or payload.get("ip", "unknown")
    )

    # Determine token type from the payload
    token_type = payload.get("channel", payload.get("type", "unknown"))
    memo = payload.get("memo", "")
    token_id = payload.get("token", payload.get("token_id", "unknown"))

    # Build a deterministic event ID from the raw payload
    raw_json = json.dumps(payload, sort_keys=True, default=str)
    event_id = hashlib.sha256(raw_json.encode()).hexdigest()[:16]

    normalized = {
        "event_id": event_id,
        "timestamp": payload.get("time", now),
        "received_at": now,
        "source": "canarytoken",
        "event_type": "honeypot",
        "severity": "critical",  # honeypot interactions are always high-confidence
        "entity_id": f"ip:{src_ip}",
        "details": {
            "token_type": token_type,
            "token_id": token_id,
            "memo": memo,
            "src_ip": src_ip,
            "description": f"Canarytoken triggered: {token_type} token "
            f"'{memo}' accessed from {src_ip}",
        },
        "raw_payload": payload,
        "tags": ["honeypot", "canarytoken", "high_confidence", "ground_truth"],
    }

    return normalized


def normalize_conpot_event(payload: dict) -> dict:
    """
    Normalize a Conpot OT/ICS honeypot event into the Sentinel
    unified event schema.
    """
    now = datetime.now(timezone.utc).isoformat()
    src_ip = payload.get("src_ip", payload.get("source_ip", "unknown"))
    protocol = payload.get("protocol", payload.get("data_type", "unknown"))

    raw_json = json.dumps(payload, sort_keys=True, default=str)
    event_id = hashlib.sha256(raw_json.encode()).hexdigest()[:16]

    normalized = {
        "event_id": event_id,
        "timestamp": payload.get("timestamp", now),
        "received_at": now,
        "source": "conpot",
        "event_type": "honeypot_ot",
        "severity": "critical",
        "entity_id": f"ip:{src_ip}",
        "details": {
            "protocol": protocol,
            "src_ip": src_ip,
            "src_port": payload.get("src_port"),
            "dst_port": payload.get("dst_port"),
            "request_data": payload.get("request", payload.get("data", "")),
            "description": f"OT/ICS honeypot interaction: {protocol} from {src_ip}",
        },
        "raw_payload": payload,
        "tags": ["honeypot", "honeypot_ot", "conpot", "high_confidence", "ground_truth"],
    }

    return normalized


# ---------------------------------------------------------------------------
# Event forwarding (Elasticsearch or local file)
# ---------------------------------------------------------------------------


def forward_event(event: dict) -> bool:
    """
    Forward a normalized event to Elasticsearch.
    Falls back to appending to a local JSONL file if ES is unavailable.
    Returns True if the event was stored successfully.
    """
    es = _get_es_client()

    if es is not None:
        try:
            result = es.index(index=ES_INDEX, document=event)
            logger.info(
                "Indexed event %s to ES (id=%s)",
                event["event_id"],
                result["_id"],
            )
            return True
        except Exception as exc:
            logger.error("Failed to index to ES: %s — falling back to local", exc)

    # Fallback: write to local JSONL file
    return _write_local(event)


def _write_local(event: dict) -> bool:
    """Append event to a local JSONL file, organized by date."""
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        log_file = LOG_DIR / f"honeypot_events_{date_str}.jsonl"

        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, default=str) + "\n")

        logger.info("Wrote event %s to local log %s", event["event_id"], log_file)
        return True
    except Exception as exc:
        logger.error("Failed to write local log: %s", exc)
        return False


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(title="Sentinel Honeypot Webhook Receiver")

# --- RATE LIMITING ---
RATE_LIMIT = 20  # requests per minute
RATE_LIMIT_WINDOW = 60  # seconds
ip_tracker: dict[str, list[float]] = {}


async def rate_limit(request: Request) -> None:
    """FastAPI dependency that enforces a per-IP rate limit."""
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    if client_ip in ip_tracker:
        ip_tracker[client_ip] = [t for t in ip_tracker[client_ip] if now - t < RATE_LIMIT_WINDOW]
    else:
        ip_tracker[client_ip] = []

    if len(ip_tracker[client_ip]) >= RATE_LIMIT:
        raise HTTPException(status_code=429, detail="Too Many Requests (Rate Limited)")

    ip_tracker[client_ip].append(now)


async def require_api_key(request: Request) -> None:
    """FastAPI dependency that validates the X-API-Key header when configured."""
    honeypot_api_key = config.HONEYPOT_API_KEY
    if honeypot_api_key:
        api_key = request.headers.get("X-API-Key")
        if not api_key or api_key != honeypot_api_key:
            logger.warning("Unauthorized webhook attempt from %s", request.client.host if request.client else "unknown")
            raise HTTPException(status_code=401, detail="Unauthorized")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/health")
def health() -> JSONResponse:
    """Health check endpoint."""
    es = _get_es_client()
    return JSONResponse(
        {
            "status": "healthy",
            "service": "sentinel-honeypot-receiver",
            "elasticsearch": "connected" if es else "unavailable (using local log)",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


@app.post("/webhook/canarytoken", dependencies=[Depends(rate_limit), Depends(require_api_key)])
async def canarytoken_webhook(request: Request) -> JSONResponse:
    """
    Receive a Canarytoken webhook POST.

    Canarytokens can send data as JSON or form-encoded depending on
    the token type and version — we handle both.
    """
    try:
        content_type = request.headers.get("content-type", "")
        if "application/json" in content_type:
            payload = await request.json()
        else:
            # Form-encoded fallback
            form_data = await request.form()
            payload = dict(form_data)

        if not payload:
            logger.warning("Empty payload received on /webhook/canarytoken")
            return JSONResponse({"error": "empty payload"}, status_code=400)

        logger.info("Received Canarytoken webhook: %s", json.dumps(payload, default=str)[:200])

        event = normalize_canarytoken_event(payload)
        success = await run_in_threadpool(forward_event, event)

        return JSONResponse(
            {
                "status": "accepted" if success else "accepted_with_warning",
                "event_id": event["event_id"],
                "stored": success,
            },
            status_code=200,
        )

    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Error processing Canarytoken webhook")
        return JSONResponse({"error": str(exc)}, status_code=500)


@app.post("/webhook/conpot", dependencies=[Depends(rate_limit), Depends(require_api_key)])
async def conpot_webhook(request: Request) -> JSONResponse:
    """
    Receive a Conpot OT/ICS honeypot event POST.

    This endpoint can be used by a Conpot log forwarder script
    that watches Conpot's log output and POSTs events here.
    """
    try:
        content_type = request.headers.get("content-type", "")
        if "application/json" in content_type:
            payload = await request.json()
        else:
            form_data = await request.form()
            payload = dict(form_data)

        if not payload:
            logger.warning("Empty payload received on /webhook/conpot")
            return JSONResponse({"error": "empty payload"}, status_code=400)

        logger.info("Received Conpot event: %s", json.dumps(payload, default=str)[:200])

        event = normalize_conpot_event(payload)
        success = await run_in_threadpool(forward_event, event)

        return JSONResponse(
            {
                "status": "accepted" if success else "accepted_with_warning",
                "event_id": event["event_id"],
                "stored": success,
            },
            status_code=200,
        )

    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Error processing Conpot webhook")
        return JSONResponse({"error": str(exc)}, status_code=500)


@app.get("/events")
def list_events() -> JSONResponse:
    """
    List recent honeypot events (for debugging / dashboard use).
    Reads from local log files. In production, query Elasticsearch directly.
    """
    try:
        events = []
        if LOG_DIR.exists():
            # Read the most recent log file
            log_files = sorted(LOG_DIR.glob("honeypot_events_*.jsonl"), reverse=True)
            if log_files:
                with open(log_files[0], "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            events.append(json.loads(line))

        # Return last 50 events, newest first
        events.reverse()
        return JSONResponse({"count": len(events[:50]), "events": events[:50]})

    except Exception as exc:
        logger.exception("Error listing events")
        return JSONResponse({"error": str(exc)}, status_code=500)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    logger.info("Starting Sentinel Honeypot Webhook Receiver on %s:%s", RECEIVER_HOST, RECEIVER_PORT)
    logger.info("Elasticsearch: %s", ES_HOST or "(disabled — using local log)")
    logger.info("Local log directory: %s", LOG_DIR.resolve())

    uvicorn.run(
        "sentinel_prime.simulation.honeypots.webhook_receiver:app",
        host=RECEIVER_HOST,
        port=RECEIVER_PORT,
        reload=False,
    )
