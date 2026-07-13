"""
Tests for the Sentinel BaselineStore.

Covers:
- Basic update/retrieval
- Welford's algorithm correctness (mean, std)
- Deviation (z-score) calculation
- Edge cases (no data, single observation, zero std)
- Multi-entity / multi-metric isolation
- Reset functionality
- Established baseline threshold
"""

import math

import pytest

from sentinel_prime.core.ingestion.baseline_store import BaselineStore, BaselineStats


@pytest.fixture
def store():
    """Create an in-memory BaselineStore for testing."""
    return BaselineStore(":memory:")


# ── Basic update & retrieval ──────────────────────────────────────────────


class TestUpdate:
    def test_first_observation(self, store):
        """First update should set mean=value, std=0, count=1."""
        stats = store.update("host:web01", "file_write_rate", 10.0)
        assert stats.entity_id == "host:web01"
        assert stats.metric == "file_write_rate"
        assert stats.mean == 10.0
        assert stats.std == 0.0
        assert stats.count == 1

    def test_two_observations(self, store):
        """Two observations should produce correct mean and std."""
        store.update("host:web01", "file_write_rate", 10.0)
        stats = store.update("host:web01", "file_write_rate", 20.0)
        assert stats.mean == 15.0
        assert stats.count == 2
        # std of [10, 20] population = 5.0
        assert math.isclose(stats.std, 5.0, rel_tol=1e-9)

    def test_multiple_observations_accuracy(self, store):
        """Verify Welford's algorithm against known values."""
        values = [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]
        for v in values:
            stats = store.update("entity1", "metric1", v)

        # Known: mean = 5.0, population variance = 4.0, population std = 2.0
        assert math.isclose(stats.mean, 5.0, rel_tol=1e-9)
        assert math.isclose(stats.std, 2.0, rel_tol=1e-9)
        assert stats.count == 8

    def test_identical_values(self, store):
        """All identical values should produce std=0."""
        for _ in range(10):
            stats = store.update("host:static", "cpu", 50.0)
        assert stats.mean == 50.0
        assert stats.std == 0.0
        assert stats.count == 10


# ── Get baseline ──────────────────────────────────────────────────────────


class TestGetBaseline:
    def test_nonexistent_entity(self, store):
        """Getting a baseline for a nonexistent entity returns None."""
        assert store.get_baseline("nonexistent", "metric") is None

    def test_retrieval_matches_update(self, store):
        """get_baseline should return the same stats as the last update."""
        store.update("host:db01", "query_rate", 100.0)
        store.update("host:db01", "query_rate", 200.0)

        stats = store.get_baseline("host:db01", "query_rate")
        assert stats is not None
        assert stats.mean == 150.0
        assert stats.count == 2

    def test_get_all_baselines(self, store):
        """get_all_baselines should return all metrics for an entity."""
        store.update("host:web01", "cpu", 50.0)
        store.update("host:web01", "memory", 70.0)
        store.update("host:web01", "disk_io", 30.0)

        baselines = store.get_all_baselines("host:web01")
        assert len(baselines) == 3
        metrics = {b.metric for b in baselines}
        assert metrics == {"cpu", "memory", "disk_io"}


# ── Deviation (z-score) ──────────────────────────────────────────────────


class TestDeviation:
    def test_insufficient_data(self, store):
        """Deviation should return None with fewer than MIN_OBSERVATIONS."""
        store.update("host:new", "metric", 10.0)
        store.update("host:new", "metric", 20.0)
        # Only 2 observations — below MIN_OBSERVATIONS (3)
        assert store.deviation("host:new", "metric", 100.0) is None

    def test_nonexistent_entity(self, store):
        """Deviation for nonexistent entity should return None."""
        assert store.deviation("ghost", "metric", 42.0) is None

    def test_zero_std_same_value(self, store):
        """Zero std + value == mean should return 0.0."""
        for _ in range(5):
            store.update("host:stable", "metric", 10.0)
        assert store.deviation("host:stable", "metric", 10.0) == 0.0

    def test_zero_std_different_value(self, store):
        """Zero std + value != mean should return infinity."""
        for _ in range(5):
            store.update("host:stable", "metric", 10.0)
        assert store.deviation("host:stable", "metric", 15.0) == float("inf")

    def test_normal_deviation(self, store):
        """Z-score should be correctly computed."""
        # Build a baseline: mean=10, population_std=2
        values = [8.0, 10.0, 12.0, 8.0, 10.0, 12.0, 8.0, 10.0, 12.0, 10.0]
        for v in values:
            store.update("host:web01", "rate", v)

        stats = store.get_baseline("host:web01", "rate")
        assert stats is not None

        # Value exactly at mean → z = 0
        z = store.deviation("host:web01", "rate", stats.mean)
        assert math.isclose(z, 0.0, abs_tol=1e-9)

        # Value 1 std away
        z = store.deviation("host:web01", "rate", stats.mean + stats.std)
        assert math.isclose(z, 1.0, rel_tol=1e-9)

        # Value 3 std away (anomalous!)
        z = store.deviation("host:web01", "rate", stats.mean + 3 * stats.std)
        assert math.isclose(z, 3.0, rel_tol=1e-9)

    def test_ransomware_burst_detection(self, store):
        """
        Simulate a ransomware scenario:
        - Normal file write rate: ~10-15 writes/minute
        - Ransomware burst: 500 writes/minute
        The z-score should be very high (>> 3).
        """
        # Build normal baseline
        normal_rates = [10, 12, 11, 14, 13, 10, 15, 12, 11, 13,
                        14, 10, 12, 11, 13, 12, 14, 10, 11, 15]
        for rate in normal_rates:
            store.update("host:victim", "file_write_rate", float(rate))

        # Check the burst
        z = store.deviation("host:victim", "file_write_rate", 500.0)
        assert z is not None
        assert z > 3.0  # Way above the anomaly threshold
        # In practice this will be ~300+ standard deviations

    def test_benign_traffic_no_flag(self, store):
        """Normal traffic should NOT trigger high z-scores."""
        normal_rates = [10, 12, 11, 14, 13, 10, 15, 12, 11, 13]
        for rate in normal_rates:
            store.update("host:normal", "file_write_rate", float(rate))

        # A normal value should have z < 3
        z = store.deviation("host:normal", "file_write_rate", 14.0)
        assert z is not None
        assert z < 3.0


# ── Multi-entity isolation ────────────────────────────────────────────────


class TestIsolation:
    def test_entities_are_isolated(self, store):
        """Different entities should have independent baselines."""
        store.update("host:web01", "cpu", 50.0)
        store.update("host:web02", "cpu", 90.0)

        stats1 = store.get_baseline("host:web01", "cpu")
        stats2 = store.get_baseline("host:web02", "cpu")

        assert stats1.mean == 50.0
        assert stats2.mean == 90.0

    def test_metrics_are_isolated(self, store):
        """Different metrics for the same entity should be independent."""
        store.update("host:web01", "cpu", 50.0)
        store.update("host:web01", "memory", 80.0)

        cpu = store.get_baseline("host:web01", "cpu")
        mem = store.get_baseline("host:web01", "memory")

        assert cpu.mean == 50.0
        assert mem.mean == 80.0


# ── Reset ─────────────────────────────────────────────────────────────────


class TestReset:
    def test_reset_single_metric(self, store):
        """Resetting a single metric should not affect others."""
        store.update("host:web01", "cpu", 50.0)
        store.update("host:web01", "memory", 80.0)

        store.reset("host:web01", "cpu")

        assert store.get_baseline("host:web01", "cpu") is None
        assert store.get_baseline("host:web01", "memory") is not None

    def test_reset_all_metrics(self, store):
        """Resetting an entity without metric should clear all."""
        store.update("host:web01", "cpu", 50.0)
        store.update("host:web01", "memory", 80.0)
        store.update("host:web01", "disk", 30.0)

        store.reset("host:web01")

        assert store.get_all_baselines("host:web01") == []


# ── Metadata ──────────────────────────────────────────────────────────────


class TestMetadata:
    def test_entity_count(self, store):
        store.update("entity1", "m", 1.0)
        store.update("entity2", "m", 2.0)
        store.update("entity3", "m", 3.0)
        assert store.entity_count() == 3

    def test_metric_count(self, store):
        store.update("host:x", "cpu", 1.0)
        store.update("host:x", "mem", 2.0)
        store.update("host:x", "disk", 3.0)
        assert store.metric_count("host:x") == 3

    def test_is_established(self, store):
        """Baseline is 'established' after 10+ observations."""
        for i in range(9):
            stats = store.update("host:x", "m", float(i))
        assert not stats.is_established

        stats = store.update("host:x", "m", 9.0)
        assert stats.is_established
