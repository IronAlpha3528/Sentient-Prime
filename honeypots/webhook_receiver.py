"""
Sentinel — Canarytoken Webhook Receiver

A Flask application that accepts Canarytoken webhook POST requests,
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
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, request

# ---------------------------------------------------------------------------
# Configuration (from environment or defaults)
# ---------------------------------------------------------------------------

ES_HOST = os.getenv("ES_HOST", "")  # empty = skip Elasticsearch, log locally
ES_INDEX = os.getenv("ES_INDEX", "sentinel-honeypot")
ES_API_KEY = os.getenv("ES_API_KEY", "")
LOG_DIR = Path(os.getenv("HONEYPOT_LOG_DIR", "data/honeypot_events"))
RECEIVER_PORT = int(os.getenv("RECEIVER_PORT", "5050"))
RECEIVER_HOST = os.getenv("RECEIVER_HOST", "0.0.0.0")

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
# Flask application
# ---------------------------------------------------------------------------

app = Flask(__name__)


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    es = _get_es_client()
    return jsonify(
        {
            "status": "healthy",
            "service": "sentinel-honeypot-receiver",
            "elasticsearch": "connected" if es else "unavailable (using local log)",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


@app.route("/webhook/canarytoken", methods=["POST"])
def canarytoken_webhook():
    """
    Receive a Canarytoken webhook POST.

    Canarytokens can send data as JSON or form-encoded depending on
    the token type and version — we handle both.
    """
    try:
        if request.is_json:
            payload = request.get_json(force=True)
        else:
            # Form-encoded fallback
            payload = request.form.to_dict()

        if not payload:
            logger.warning("Empty payload received on /webhook/canarytoken")
            return jsonify({"error": "empty payload"}), 400

        logger.info("Received Canarytoken webhook: %s", json.dumps(payload, default=str)[:200])

        event = normalize_canarytoken_event(payload)
        success = forward_event(event)

        return jsonify(
            {
                "status": "accepted" if success else "accepted_with_warning",
                "event_id": event["event_id"],
                "stored": success,
            }
        ), 200

    except Exception as exc:
        logger.exception("Error processing Canarytoken webhook")
        return jsonify({"error": str(exc)}), 500


@app.route("/webhook/conpot", methods=["POST"])
def conpot_webhook():
    """
    Receive a Conpot OT/ICS honeypot event POST.

    This endpoint can be used by a Conpot log forwarder script
    that watches Conpot's log output and POSTs events here.
    """
    try:
        if request.is_json:
            payload = request.get_json(force=True)
        else:
            payload = request.form.to_dict()

        if not payload:
            logger.warning("Empty payload received on /webhook/conpot")
            return jsonify({"error": "empty payload"}), 400

        logger.info("Received Conpot event: %s", json.dumps(payload, default=str)[:200])

        event = normalize_conpot_event(payload)
        success = forward_event(event)

        return jsonify(
            {
                "status": "accepted" if success else "accepted_with_warning",
                "event_id": event["event_id"],
                "stored": success,
            }
        ), 200

    except Exception as exc:
        logger.exception("Error processing Conpot webhook")
        return jsonify({"error": str(exc)}), 500


@app.route("/events", methods=["GET"])
def list_events():
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
        return jsonify({"count": len(events[:50]), "events": events[:50]})

    except Exception as exc:
        logger.exception("Error listing events")
        return jsonify({"error": str(exc)}), 500


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logger.info("Starting Sentinel Honeypot Webhook Receiver on %s:%s", RECEIVER_HOST, RECEIVER_PORT)
    logger.info("Elasticsearch: %s", ES_HOST or "(disabled — using local log)")
    logger.info("Local log directory: %s", LOG_DIR.resolve())

    app.run(host=RECEIVER_HOST, port=RECEIVER_PORT, debug=True)
