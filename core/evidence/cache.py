import hashlib
import json
import logging
import threading
import time
from typing import Dict
from core.evidence.base_evidence import BaseEvidence

logger = logging.getLogger(__name__)

class EvidenceCache:
    """A thread-safe cache used to detect duplicate events by tracking recent

    event IDs and computed SHA-256 evidence payload hashes with a configured TTL.
    """

    def __init__(self, max_size: int = 10000, ttl_seconds: int = 600):
        self.max_size = max_size
        self.ttl = ttl_seconds
        self.event_ids: Dict[str, float] = {}  # event_id -> entry_time
        self.evidence_hashes: Dict[str, float] = {}  # hash -> entry_time
        self.lock = threading.Lock()

    def _compute_hash(self, evidence: BaseEvidence) -> str:
        """Computes a SHA-256 hash of the evidence's core contents for deduplication."""
        # Standardize dynamic variables to avoid false positive hash mismatch
        core_data = {
            "detector": str(evidence.detector).upper(),
            "entity": str(evidence.entity).strip(),
            "entity_type": str(evidence.entity_type).upper(),
            "window_start": str(evidence.window_start),
            "window_end": str(evidence.window_end),
            "risk_score": round(float(evidence.risk_score), 6),
            "confidence": round(float(evidence.confidence), 6),
            "severity": str(evidence.severity).upper(),
            "top_reasons": sorted(evidence.top_reasons) if evidence.top_reasons else [],
            "metadata": {k: v for k, v in sorted(evidence.metadata.items())} if evidence.metadata else {}
        }
        serialized = json.dumps(core_data, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def prune_expired(self) -> None:
        """Removes expired entries from the cache based on TTL."""
        now = time.time()
        with self.lock:
            expired_ids = [eid for eid, t in self.event_ids.items() if now - t > self.ttl]
            for eid in expired_ids:
                del self.event_ids[eid]

            expired_hashes = [h for h, t in self.evidence_hashes.items() if now - t > self.ttl]
            for h in expired_hashes:
                del self.evidence_hashes[h]

    def check_duplicate_and_add(self, event_id: str, evidence: BaseEvidence) -> bool:
        """Checks if the event ID or evidence hash is already cached.

        Returns True if a duplicate is found (and discards), otherwise caches it
        and returns False. Enforces max_size limit.
        """
        self.prune_expired()
        h = self._compute_hash(evidence)
        now = time.time()

        with self.lock:
            if event_id in self.event_ids:
                logger.warning(f"Duplicate event ID detected: {event_id}")
                return True
            if h in self.evidence_hashes:
                logger.warning(f"Duplicate evidence payload detected. Hash: {h} for event {event_id}")
                return True

            # Evict oldest entry if size limit reached
            if len(self.event_ids) >= self.max_size:
                oldest_id = min(self.event_ids, key=self.event_ids.get)
                del self.event_ids[oldest_id]
            if len(self.evidence_hashes) >= self.max_size:
                oldest_hash = min(self.evidence_hashes, key=self.evidence_hashes.get)
                del self.evidence_hashes[oldest_hash]

            # Cache the new records
            self.event_ids[event_id] = now
            self.evidence_hashes[h] = now
            return False

    def clear(self) -> None:
        """Clears all cached records."""
        with self.lock:
            self.event_ids.clear()
            self.evidence_hashes.clear()
