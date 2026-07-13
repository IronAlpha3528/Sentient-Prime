"""
Sentinel — Baseline Store

SQLite-backed rolling statistics store that tracks per-entity, per-metric
baselines using Welford's online algorithm for numerically stable running
mean and variance computation.

Used by detection agents to determine when an entity's behavior deviates
significantly from its own historical norm.

Usage:
    from ingestion.baseline_store import BaselineStore

    store = BaselineStore("baselines.db")
    store.update("host:web01", "file_write_rate", 12.5)
    store.update("host:web01", "file_write_rate", 14.0)
    store.update("host:web01", "file_write_rate", 11.8)

    z = store.deviation("host:web01", "file_write_rate", 85.0)
    # z ≈ 56.7 → extreme deviation → flag!
"""

import math
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class BaselineStats:
    """Current baseline statistics for an entity-metric pair."""

    entity_id: str
    metric: str
    mean: float
    std: float
    count: int

    @property
    def is_established(self) -> bool:
        """A baseline is considered established with at least 10 observations."""
        return self.count >= 10


class BaselineStore:
    """
    SQLite-backed store for rolling per-entity, per-metric baselines.

    Uses Welford's online algorithm to maintain running mean and variance
    without needing to store individual data points. This is both
    memory-efficient and numerically stable.

    Thread-safe: uses a lock around database operations.
    """

    # Minimum observations before a deviation check is meaningful
    MIN_OBSERVATIONS = 3

    def __init__(self, db_path: str = "baselines.db"):
        """
        Initialize the BaselineStore.

        Args:
            db_path: Path to the SQLite database file.
                     Use ":memory:" for in-memory testing.
        """
        self.db_path = db_path
        self._lock = threading.Lock()
        self._is_memory = db_path == ":memory:"
        self._persistent_conn: Optional[sqlite3.Connection] = None

        # Create parent directory if needed (unless in-memory)
        if not self._is_memory:
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)

        # For :memory: mode, keep a single persistent connection
        # (each sqlite3.connect(":memory:") creates a separate database)
        if self._is_memory:
            self._persistent_conn = sqlite3.connect(":memory:")

        self._init_db()

    def _init_db(self):
        """Create the baselines table if it doesn't exist."""
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS baselines (
                        entity_id   TEXT    NOT NULL,
                        metric      TEXT    NOT NULL,
                        count       INTEGER NOT NULL DEFAULT 0,
                        mean        REAL    NOT NULL DEFAULT 0.0,
                        m2          REAL    NOT NULL DEFAULT 0.0,
                        last_value  REAL,
                        updated_at  TEXT,
                        PRIMARY KEY (entity_id, metric)
                    )
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_baselines_entity
                    ON baselines (entity_id)
                """)
                conn.commit()
            finally:
                self._release(conn)

    def _connect(self) -> sqlite3.Connection:
        """
        Get a database connection.

        For :memory: mode, returns the single persistent connection.
        For file-backed mode, creates a new connection per operation.
        """
        if self._is_memory and self._persistent_conn is not None:
            return self._persistent_conn

        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")  # better concurrent read performance
        return conn

    def _release(self, conn: sqlite3.Connection):
        """
        Release a connection. Only closes file-backed connections;
        the persistent in-memory connection stays open.
        """
        if not self._is_memory:
            conn.close()

    def update(self, entity_id: str, metric: str, value: float) -> BaselineStats:
        """
        Update the rolling baseline for an entity-metric pair with a new
        observation, using Welford's online algorithm.

        Args:
            entity_id: Identifier for the entity (e.g., "host:web01", "user:alice")
            metric: The metric name (e.g., "file_write_rate", "login_count")
            value: The observed value

        Returns:
            Updated BaselineStats for this entity-metric pair.
        """
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT count, mean, m2 FROM baselines WHERE entity_id = ? AND metric = ?",
                    (entity_id, metric),
                ).fetchone()

                if row is None:
                    # First observation for this entity-metric pair
                    count, mean, m2 = 1, value, 0.0
                    conn.execute(
                        """INSERT INTO baselines (entity_id, metric, count, mean, m2,
                           last_value, updated_at)
                           VALUES (?, ?, ?, ?, ?, ?, datetime('now'))""",
                        (entity_id, metric, count, mean, m2, value),
                    )
                else:
                    # Welford's online algorithm update
                    old_count, old_mean, old_m2 = row
                    count = old_count + 1
                    delta = value - old_mean
                    mean = old_mean + delta / count
                    delta2 = value - mean
                    m2 = old_m2 + delta * delta2

                    conn.execute(
                        """UPDATE baselines
                           SET count = ?, mean = ?, m2 = ?, last_value = ?,
                               updated_at = datetime('now')
                           WHERE entity_id = ? AND metric = ?""",
                        (count, mean, m2, value, entity_id, metric),
                    )

                conn.commit()

                # Compute std from m2
                variance = m2 / count if count > 1 else 0.0
                std = math.sqrt(variance)

                return BaselineStats(
                    entity_id=entity_id,
                    metric=metric,
                    mean=mean,
                    std=std,
                    count=count,
                )
            finally:
                self._release(conn)

    def deviation(self, entity_id: str, metric: str, value: float) -> Optional[float]:
        """
        Compute how many standard deviations a value is from the baseline
        (z-score) for a given entity-metric pair.

        Args:
            entity_id: Identifier for the entity
            metric: The metric name
            value: The value to check against the baseline

        Returns:
            The z-score (number of standard deviations from mean),
            or None if the baseline has too few observations.
            Returns 0.0 if std is 0 and value equals mean.
            Returns float('inf') if std is 0 and value differs from mean.
        """
        stats = self.get_baseline(entity_id, metric)

        if stats is None or stats.count < self.MIN_OBSERVATIONS:
            return None

        if stats.std == 0.0:
            return 0.0 if value == stats.mean else float("inf")

        return abs(value - stats.mean) / stats.std

    def get_baseline(self, entity_id: str, metric: str) -> Optional[BaselineStats]:
        """
        Retrieve the current baseline statistics for an entity-metric pair.

        Args:
            entity_id: Identifier for the entity
            metric: The metric name

        Returns:
            BaselineStats if a baseline exists, None otherwise.
        """
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT count, mean, m2 FROM baselines WHERE entity_id = ? AND metric = ?",
                    (entity_id, metric),
                ).fetchone()

                if row is None:
                    return None

                count, mean, m2 = row
                variance = m2 / count if count > 1 else 0.0
                std = math.sqrt(variance)

                return BaselineStats(
                    entity_id=entity_id,
                    metric=metric,
                    mean=mean,
                    std=std,
                    count=count,
                )
            finally:
                self._release(conn)

    def get_all_baselines(self, entity_id: str) -> list[BaselineStats]:
        """
        Retrieve all baseline statistics for a given entity.

        Args:
            entity_id: Identifier for the entity

        Returns:
            List of BaselineStats for all metrics tracked for this entity.
        """
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT metric, count, mean, m2 FROM baselines WHERE entity_id = ?",
                    (entity_id,),
                ).fetchall()

                results = []
                for metric, count, mean, m2 in rows:
                    variance = m2 / count if count > 1 else 0.0
                    std = math.sqrt(variance)
                    results.append(
                        BaselineStats(
                            entity_id=entity_id,
                            metric=metric,
                            mean=mean,
                            std=std,
                            count=count,
                        )
                    )
                return results
            finally:
                self._release(conn)

    def reset(self, entity_id: str, metric: Optional[str] = None):
        """
        Reset baseline(s) for an entity.

        Args:
            entity_id: Identifier for the entity
            metric: If provided, reset only this metric. Otherwise reset all.
        """
        with self._lock:
            conn = self._connect()
            try:
                if metric:
                    conn.execute(
                        "DELETE FROM baselines WHERE entity_id = ? AND metric = ?",
                        (entity_id, metric),
                    )
                else:
                    conn.execute(
                        "DELETE FROM baselines WHERE entity_id = ?",
                        (entity_id,),
                    )
                conn.commit()
            finally:
                self._release(conn)

    def entity_count(self) -> int:
        """Return the number of distinct entities with baselines."""
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT COUNT(DISTINCT entity_id) FROM baselines"
                ).fetchone()
                return row[0] if row else 0
            finally:
                self._release(conn)

    def metric_count(self, entity_id: str) -> int:
        """Return the number of metrics tracked for an entity."""
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT COUNT(*) FROM baselines WHERE entity_id = ?",
                    (entity_id,),
                ).fetchone()
                return row[0] if row else 0
            finally:
                self._release(conn)
