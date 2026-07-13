import datetime
import json
import logging
import os
import pathlib
import threading
import time
from typing import Any, Dict, List, Optional, Union

import yaml

from sentinel_prime.core.evidence.base_evidence import BaseEvidence
from sentinel_prime.core.evidence.cache import EvidenceCache
from sentinel_prime.core.evidence.event import EvidenceEvent, EventPriority, EventStatus
from sentinel_prime.core.evidence.event_queue import EventQueue
from sentinel_prime.core.evidence.normalizer import normalize_evidence_object
from sentinel_prime.core.evidence.subscriber import Subscriber
from sentinel_prime.core.evidence.validator import validate_evidence

logger = logging.getLogger(__name__)

class StreamManager:
    """Manages the full lifecycle of evidence streaming, including:

    - Validation & Normalization
    - Cache deduplication
    - Event queueing & prioritization
    - Subscriber routing & filtering
    - Performance diagnostics & health checking
    """

    def __init__(self, config_path: str = "config/evidence_bus.yaml"):
        self.config_path = pathlib.Path(config_path)
        self.config: Dict[str, Any] = {}
        self.load_config()

        # Initialize core components
        self.queue = EventQueue(max_size=self.config.get("queue_size", 10000))
        self.cache = EvidenceCache(
            max_size=self.config.get("cache_size", 10000),
            ttl_seconds=self.config.get("cache_ttl", 600)
        )
        self.subscribers: List[Subscriber] = []
        self.subscribers_lock = threading.Lock()

        # Metrics collection
        self._metrics = {
            "events_received": 0,
            "events_published": 0,
            "events_dropped": 0,
            "validation_failures": 0,
            "duplicates_removed": 0,
            "average_latency": 0.0,
            "peak_queue_size": 0
        }
        self.metrics_lock = threading.Lock()

        # Priority mapping config
        self.priority_mapping = self.config.get("priority_mapping", {
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH",
            "MEDIUM": "NORMAL",
            "LOW": "LOW",
            "INFO": "LOW"
        })

        # Background dispatcher thread
        self._stop_event = threading.Event()
        self._dispatcher_thread = threading.Thread(
            target=self._dispatcher_loop,
            name="EvidenceBusDispatcher",
            daemon=True
        )
        self._dispatcher_thread.start()

    def load_config(self) -> None:
        """Loads configuration from YAML file or uses defaults."""
        if self.config_path.exists():
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    self.config = yaml.safe_load(f) or {}
            except Exception as e:
                logger.error(f"Failed to load config from {self.config_path}: {e}")
                self.config = {}
        else:
            logger.warning(f"Config path {self.config_path} not found. Using default settings.")
            self.config = {}

    def push(self, evidence: BaseEvidence) -> bool:
        """Processes and enqueues an evidence object.

        Validates, normalizes, performs duplicate detection, wraps, and pushes to queue.
        """
        # 1. Validation
        val_res = validate_evidence(evidence)
        if not val_res.valid:
            logger.error(f"Evidence validation failed. Errors: {val_res.errors}")
            with self.metrics_lock:
                self._metrics["validation_failures"] += 1
                self._metrics["events_dropped"] += 1
            return False

        # 2. Normalization
        normalized_evidence = normalize_evidence_object(evidence)

        # 3. Duplicate Detection
        # Wrap temp event ID to check duplicate hash
        import uuid
        temp_event_id = str(uuid.uuid4())
        if self.cache.check_duplicate_and_add(temp_event_id, normalized_evidence):
            with self.metrics_lock:
                self._metrics["duplicates_removed"] += 1
                self._metrics["events_dropped"] += 1
            return False

        # 4. Map severity to EventPriority
        sev_str = str(normalized_evidence.severity).upper()
        prio_str = self.priority_mapping.get(sev_str, "NORMAL")
        try:
            priority = EventPriority[prio_str]
        except KeyError:
            priority = EventPriority.NORMAL

        # 5. Wrap in EvidenceEvent
        event = EvidenceEvent.wrap(normalized_evidence.to_dict(), priority=priority)

        # 6. Enqueue
        success = self.queue.enqueue(event)
        if not success:
            logger.error(f"Event Queue Overflow! Dropped event {event.event_id}")
            with self.metrics_lock:
                self._metrics["events_dropped"] += 1
            return False

        # Update metrics
        with self.metrics_lock:
            self._metrics["events_received"] += 1
            current_sz = self.queue.size()
            if current_sz > self._metrics["peak_queue_size"]:
                self._metrics["peak_queue_size"] = current_sz

        return True

    def pull(self) -> Optional[EvidenceEvent]:
        """Manually pulls the highest priority event from the queue."""
        return self.queue.dequeue()

    def broadcast(self, event: EvidenceEvent) -> None:
        """Broadcasts an event to matching subscribers."""
        event.status = EventStatus.PROCESSING
        
        with self.subscribers_lock:
            targets = [sub for sub in self.subscribers if sub.matches(event)]

        for sub in targets:
            try:
                sub.receive(event)
            except Exception as e:
                logger.error(f"Subscriber {sub.name} failed to process event {event.event_id}: {e}")

        event.status = EventStatus.PROCESSED

        # Calculate latency from event generation to broadcast completion
        try:
            wrapped_time = datetime.datetime.fromisoformat(event.timestamp.replace('Z', '+00:00'))
            now = datetime.datetime.now(datetime.timezone.utc)
            latency_ms = (now - wrapped_time).total_seconds() * 1000.0
        except Exception:
            latency_ms = 0.0

        with self.metrics_lock:
            self._metrics["events_published"] += 1
            count = self._metrics["events_published"]
            prev_avg = self._metrics["average_latency"]
            self._metrics["average_latency"] = ((prev_avg * (count - 1)) + latency_ms) / count

    def register(self, subscriber: Subscriber) -> None:
        """Registers a subscriber to receive events."""
        with self.subscribers_lock:
            if subscriber not in self.subscribers:
                self.subscribers.append(subscriber)
                subscriber.is_subscribed = True
                logger.info(f"Registered subscriber: {subscriber.name}")

    def unregister(self, subscriber: Subscriber) -> None:
        """Unregisters a subscriber."""
        with self.subscribers_lock:
            if subscriber in self.subscribers:
                self.subscribers.remove(subscriber)
                subscriber.is_subscribed = False
                logger.info(f"Unregistered subscriber: {subscriber.name}")

    def health(self) -> Dict[str, Any]:
        """Provides detailed health diagnostics of the streaming system."""
        health_status = "Healthy"
        diagnostics = []

        # Check queue
        q_sz = self.queue.size()
        max_q = self.config.get("queue_size", 10000)
        if q_sz >= max_q * 0.9:
            health_status = "Degraded"
            diagnostics.append(f"Queue warning: size is at {q_sz}/{max_q}")

        # Check subscribers health
        with self.subscribers_lock:
            for sub in self.subscribers:
                try:
                    status = sub.health()
                    if status != "Healthy" and "Interface" not in status:
                        health_status = "Degraded"
                        diagnostics.append(f"Subscriber {sub.name} is degraded: {status}")
                except Exception as e:
                    health_status = "Degraded"
                    diagnostics.append(f"Subscriber {sub.name} health check threw error: {e}")

        return {
            "status": health_status,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "diagnostics": diagnostics,
            "queue_utilization": f"{q_sz}/{max_q}",
            "subscriber_count": len(self.subscribers)
        }

    def metrics(self) -> Dict[str, Any]:
        """Returns runtime performance metrics."""
        with self.metrics_lock:
            m = self._metrics.copy()
            m["current_queue_size"] = self.queue.size()
            m["subscriber_count"] = len(self.subscribers)
            return m

    def _dispatcher_loop(self) -> None:
        """Active background thread retrieving and broadcasting events."""
        while not self._stop_event.is_set():
            try:
                event = self.queue.dequeue()
                if event is None:
                    self._stop_event.wait(0.01)
                    continue
                self.broadcast(event)
            except Exception as e:
                logger.error(f"Error in dispatcher loop: {e}")

    def shutdown(self) -> None:
        """Triggers clean shutdown of dispatcher and exports final metrics."""
        self._stop_event.set()
        if self._dispatcher_thread.is_alive():
            self._dispatcher_thread.join(timeout=2.0)

        # Export metrics to processed/metrics/event_bus_metrics.json
        m = self.metrics()
        metrics_dir = pathlib.Path("processed/metrics")
        metrics_dir.mkdir(parents=True, exist_ok=True)
        metrics_file = metrics_dir / "event_bus_metrics.json"
        
        try:
            with open(metrics_file, "w", encoding="utf-8") as f:
                json.dump(m, f, indent=2)
            logger.info(f"Saved event bus metrics to {metrics_file}")
        except Exception as e:
            logger.error(f"Failed to save metrics to {metrics_file}: {e}")
