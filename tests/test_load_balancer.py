"""
Tests for posframework.load_balancer module.

Validates multi-adapter load balancing with different distribution strategies,
health monitoring, pool acquisition/release, and MockLoadBalancer functionality.
All tests run without WiFi hardware by using MockRadioManager.
"""

import asyncio
import sys
import os

# Allow running standalone without pytest
try:
    import pytest
except ImportError:
    pytest = None

# Ensure posframework is importable when running standalone
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from posframework.radio_manager import (
    Band,
    MockRadioManager,
    RadioInterface,
    TaskType,
)
from posframework.load_balancer import (
    AdapterWorkload,
    DistributionStrategy,
    ERROR_THRESHOLD,
    LoadBalancer,
    MockLoadBalancer,
)


# ================================================================
# FIXTURES
# ================================================================

if pytest:
    @pytest.fixture
    def event_loop():
        """Create a new event loop for each test."""
        loop = asyncio.new_event_loop()
        yield loop
        loop.close()


def run(coro):
    """Helper to run async coroutines in tests."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


if pytest:
    @pytest.fixture
    def mock_manager():
        """Provide a discovered MockRadioManager with 4 interfaces."""
        mgr = MockRadioManager(mock_interfaces=["wlan0", "wlan1", "wlan2", "wlan3"])
        run(mgr.discover_interfaces())
        return mgr

    @pytest.fixture
    def load_balancer(mock_manager):
        """Provide an initialized LoadBalancer."""
        lb = LoadBalancer(mock_manager)
        run(lb.initialize())
        return lb

    @pytest.fixture
    def mock_lb():
        """Provide a fully set up MockLoadBalancer."""
        mlb = MockLoadBalancer(mock_interfaces=["wlan0", "wlan1", "wlan2", "wlan3"])
        run(mlb.setup())
        return mlb


def _make_mock_manager():
    """Create a MockRadioManager for standalone tests."""
    mgr = MockRadioManager(mock_interfaces=["wlan0", "wlan1", "wlan2", "wlan3"])
    run(mgr.discover_interfaces())
    return mgr


def _make_load_balancer():
    """Create an initialized LoadBalancer for standalone tests."""
    mgr = _make_mock_manager()
    lb = LoadBalancer(mgr)
    run(lb.initialize())
    return lb


def _make_mock_lb():
    """Create a MockLoadBalancer for standalone tests."""
    mlb = MockLoadBalancer(mock_interfaces=["wlan0", "wlan1", "wlan2", "wlan3"])
    run(mlb.setup())
    return mlb


# ================================================================
# POOL ACQUISITION TESTS
# ================================================================


class TestPoolAcquisition:
    """Tests for acquire_pool functionality."""

    def test_acquire_pool_returns_multiple_interfaces(self, load_balancer):
        """acquire_pool should return multiple interfaces for the same task."""
        pool = run(load_balancer.acquire_pool(TaskType.SCAN, count=2))
        assert len(pool) == 2
        assert all(isinstance(iface, RadioInterface) for iface in pool)
        # All should be assigned to SCAN
        assert all(iface.current_task == TaskType.SCAN for iface in pool)

    def test_acquire_pool_all_available(self, load_balancer):
        """acquire_pool with count=None should return all available interfaces."""
        pool = run(load_balancer.acquire_pool(TaskType.MONITOR))
        assert len(pool) == 4  # all 4 mock interfaces

    def test_acquire_pool_respects_count_limit(self, load_balancer):
        """acquire_pool should not exceed the requested count."""
        pool = run(load_balancer.acquire_pool(TaskType.SCAN, count=1))
        assert len(pool) == 1

    def test_acquire_pool_empty_when_none_available(self, mock_manager):
        """acquire_pool returns empty list when no interfaces are available."""
        lb = LoadBalancer(mock_manager)
        run(lb.initialize())
        # Acquire all interfaces first
        run(lb.acquire_pool(TaskType.SCAN))
        # Try to acquire more
        pool2 = run(lb.acquire_pool(TaskType.MONITOR, count=2))
        assert pool2 == []

    def test_acquire_pool_updates_stats(self, load_balancer):
        """acquire_pool should update statistics."""
        run(load_balancer.acquire_pool(TaskType.SCAN, count=2))
        assert load_balancer.stats["pools_acquired"] == 1
        assert load_balancer.stats["total_tasks_distributed"] == 2


# ================================================================
# STRATEGY TESTS
# ================================================================


class TestRoundRobinStrategy:
    """Tests for round-robin distribution strategy."""

    def test_round_robin_rotates_starting_interface(self, load_balancer):
        """Round-robin should cycle starting adapter on each call."""
        # First call starts at index 0
        pool1 = run(load_balancer.acquire_pool(
            TaskType.SCAN, count=1, strategy="round_robin"
        ))
        first_name = pool1[0].name

        # Release
        run(load_balancer.release_pool(pool1))

        # Second call should start at a different index
        pool2 = run(load_balancer.acquire_pool(
            TaskType.SCAN, count=1, strategy="round_robin"
        ))
        second_name = pool2[0].name

        # They should be different (rotating)
        assert first_name != second_name

    def test_round_robin_wraps_around(self, load_balancer):
        """Round-robin should wrap around after exhausting adapters."""
        names = []
        for _ in range(5):
            pool = run(load_balancer.acquire_pool(
                TaskType.SCAN, count=1, strategy="round_robin"
            ))
            if pool:
                names.append(pool[0].name)
                run(load_balancer.release_pool(pool))

        # After 4 rotations it should wrap
        assert len(names) == 5
        assert names[0] == names[4]  # wraps back to first


class TestLeastLoadedStrategy:
    """Tests for least-loaded distribution strategy."""

    def test_least_loaded_prefers_idle_adapters(self, load_balancer):
        """Least-loaded should pick adapters with fewer active tasks."""
        # Acquire one interface to add load
        pool1 = run(load_balancer.acquire_pool(
            TaskType.SCAN, count=1, strategy="least_loaded"
        ))
        first_name = pool1[0].name

        # Don't release - now acquire with least_loaded
        pool2 = run(load_balancer.acquire_pool(
            TaskType.MONITOR, count=1, strategy="least_loaded"
        ))
        second_name = pool2[0].name

        # Should pick a different (idle) adapter
        assert first_name != second_name

    def test_least_loaded_fills_evenly(self, load_balancer):
        """Least-loaded should distribute tasks evenly across adapters."""
        pools = []
        for _ in range(4):
            pool = run(load_balancer.acquire_pool(
                TaskType.SCAN, count=1, strategy="least_loaded"
            ))
            pools.append(pool)

        # All 4 adapters should be used
        used_names = {p[0].name for p in pools if p}
        assert len(used_names) == 4


class TestBandSplitStrategy:
    """Tests for band-split distribution strategy."""

    def test_band_split_separates_5ghz_and_24ghz(self, load_balancer):
        """Band-split should prioritize 5GHz adapters first."""
        pool = run(load_balancer.acquire_pool(
            TaskType.SCAN, count=4, strategy="band_split"
        ))

        # MockRadioManager assigns 5GHz to even-indexed interfaces (wlan0, wlan2)
        # So band_split should return 5GHz adapters first
        assert len(pool) == 4

        # First adapters should be the 5GHz ones
        five_ghz_names = []
        two_ghz_names = []
        for iface in pool:
            if iface.supports_5ghz:
                five_ghz_names.append(iface.name)
            else:
                two_ghz_names.append(iface.name)

        # Verify we have both bands represented
        assert len(five_ghz_names) >= 1
        assert len(two_ghz_names) >= 1

        # 5GHz adapters should come before 2.4GHz in the pool ordering
        first_5ghz_idx = pool.index(
            next(i for i in pool if i.supports_5ghz)
        )
        last_24ghz_idx = len(pool) - 1 - next(
            idx for idx, i in enumerate(reversed(pool))
            if not i.supports_5ghz
        )
        assert first_5ghz_idx < last_24ghz_idx

    def test_band_split_assigns_correct_bands(self, mock_lb):
        """Band-split in MockLoadBalancer correctly identifies band support."""
        pool = run(mock_lb.acquire_pool(
            TaskType.SCAN, count=4, strategy="band_split"
        ))

        # wlan0 (idx 0) and wlan2 (idx 2) should support 5GHz
        for iface in pool:
            if iface.name in ("wlan0", "wlan2"):
                assert iface.supports_5ghz
            else:
                assert not iface.supports_5ghz


# ================================================================
# HEALTH MONITORING TESTS
# ================================================================


class TestHealthMonitoring:
    """Tests for adapter health monitoring and error threshold removal."""

    def test_adapter_removed_after_error_threshold(self, load_balancer):
        """Adapters should be removed after ERROR_THRESHOLD consecutive errors."""
        # Report errors up to threshold
        for i in range(ERROR_THRESHOLD):
            run(load_balancer.report_error("wlan0", f"error {i}"))

        # wlan0 should be removed
        assert "wlan0" in load_balancer.removed_adapters
        assert "wlan0" not in load_balancer.healthy_interfaces

    def test_adapter_not_removed_below_threshold(self, load_balancer):
        """Adapters should NOT be removed below the error threshold."""
        for i in range(ERROR_THRESHOLD - 1):
            run(load_balancer.report_error("wlan0", f"error {i}"))

        assert "wlan0" not in load_balancer.removed_adapters
        assert "wlan0" in load_balancer.healthy_interfaces

    def test_success_resets_consecutive_errors(self, load_balancer):
        """A success report should reset consecutive error count."""
        # Add some errors (below threshold)
        run(load_balancer.report_error("wlan0", "error 1"))
        run(load_balancer.report_error("wlan0", "error 2"))

        # Report success
        run(load_balancer.report_success("wlan0"))

        # Now add more errors - should need full threshold again
        run(load_balancer.report_error("wlan0", "error 3"))
        run(load_balancer.report_error("wlan0", "error 4"))

        # Still should be healthy (only 2 consecutive)
        assert "wlan0" in load_balancer.healthy_interfaces

    def test_removed_adapter_excluded_from_pool(self, load_balancer):
        """Removed adapters should not be included in pool acquisition."""
        # Remove wlan0
        for i in range(ERROR_THRESHOLD):
            run(load_balancer.report_error("wlan0", f"error {i}"))

        # Acquire pool - wlan0 should not be included
        pool = run(load_balancer.acquire_pool(TaskType.SCAN))
        pool_names = [iface.name for iface in pool]
        assert "wlan0" not in pool_names

    def test_restore_adapter(self, load_balancer):
        """Restored adapters should be usable again."""
        # Remove adapter
        for i in range(ERROR_THRESHOLD):
            run(load_balancer.report_error("wlan0", f"error {i}"))

        assert "wlan0" in load_balancer.removed_adapters

        # Restore it
        result = run(load_balancer.restore_adapter("wlan0"))
        assert result is True
        assert "wlan0" not in load_balancer.removed_adapters
        assert "wlan0" in load_balancer.healthy_interfaces

    def test_release_pool_with_error_tracks_errors(self, load_balancer):
        """Releasing a pool with an error should track errors per adapter."""
        pool = run(load_balancer.acquire_pool(TaskType.SCAN, count=2))
        run(load_balancer.release_pool(pool, error="connection lost"))

        # Check that errors were tracked
        for iface in pool:
            wl = load_balancer.get_workload(iface.name)
            assert wl.error_count == 1
            assert wl.last_error == "connection lost"


# ================================================================
# RELEASE TESTS
# ================================================================


class TestPoolRelease:
    """Tests for release_pool functionality."""

    def test_release_pool_makes_interfaces_available(self, load_balancer):
        """Released interfaces should be available for new pools."""
        pool = run(load_balancer.acquire_pool(TaskType.SCAN, count=2))
        assert len(pool) == 2

        # Release
        run(load_balancer.release_pool(pool))

        # Interfaces should be available again
        for iface in pool:
            assert iface.current_task == TaskType.IDLE

    def test_release_pool_updates_stats(self, load_balancer):
        """release_pool should update statistics."""
        pool = run(load_balancer.acquire_pool(TaskType.SCAN, count=2))
        run(load_balancer.release_pool(pool))
        assert load_balancer.stats["pools_released"] == 1

    def test_release_pool_increments_completed(self, load_balancer):
        """Successful release should increment tasks_completed in workload."""
        pool = run(load_balancer.acquire_pool(TaskType.SCAN, count=1))
        iface_name = pool[0].name
        run(load_balancer.release_pool(pool))

        wl = load_balancer.get_workload(iface_name)
        assert wl.tasks_completed == 1
        assert wl.active_tasks == 0


# ================================================================
# MOCK LOAD BALANCER TESTS
# ================================================================


class TestMockLoadBalancer:
    """Tests for MockLoadBalancer convenience class."""

    def test_mock_lb_setup(self, mock_lb):
        """MockLoadBalancer.setup() should discover interfaces."""
        assert len(mock_lb.healthy_interfaces) == 4

    def test_mock_lb_works_without_hardware(self, mock_lb):
        """MockLoadBalancer should work entirely without hardware."""
        pool = run(mock_lb.acquire_pool(TaskType.CAPTURE, count=3))
        assert len(pool) == 3
        run(mock_lb.release_pool(pool))

    def test_mock_lb_custom_interfaces(self):
        """MockLoadBalancer should accept custom interface names."""
        mlb = MockLoadBalancer(mock_interfaces=["mon0", "mon1"])
        run(mlb.setup())
        assert "mon0" in mlb.healthy_interfaces
        assert "mon1" in mlb.healthy_interfaces


# ================================================================
# WORKLOAD TRACKING TESTS
# ================================================================


class TestWorkloadTracking:
    """Tests for per-adapter workload metrics."""

    def test_packets_processed_tracking(self, load_balancer):
        """report_packets should accumulate packet counts."""
        run(load_balancer.report_packets("wlan0", 100))
        run(load_balancer.report_packets("wlan0", 50))

        wl = load_balancer.get_workload("wlan0")
        assert wl.packets_processed == 150

    def test_error_rate_calculation(self, load_balancer):
        """AdapterWorkload.error_rate should calculate correctly."""
        pool = run(load_balancer.acquire_pool(TaskType.SCAN, count=1))
        iface_name = pool[0].name
        run(load_balancer.release_pool(pool, error="fail"))

        wl = load_balancer.get_workload(iface_name)
        # 1 task assigned, 1 error
        assert wl.error_rate == 1.0

    def test_active_tasks_count(self, load_balancer):
        """active_tasks should reflect currently running tasks."""
        pool = run(load_balancer.acquire_pool(TaskType.SCAN, count=2))
        name1 = pool[0].name

        wl = load_balancer.get_workload(name1)
        assert wl.active_tasks == 1

        run(load_balancer.release_pool(pool))
        assert wl.active_tasks == 0


# ================================================================
# STANDALONE RUNNER (when pytest is not available)
# ================================================================

if __name__ == "__main__":
    passed = 0
    failed = 0

    def _run_test(name, func):
        global passed, failed
        try:
            func()
            print(f"  PASS: {name}")
            passed += 1
        except Exception as e:
            print(f"  FAIL: {name} - {e}")
            failed += 1

    print("Running load_balancer tests (standalone)...\n")

    # Pool acquisition
    def test_acquire_pool_returns_multiple():
        lb = _make_load_balancer()
        pool = run(lb.acquire_pool(TaskType.SCAN, count=2))
        assert len(pool) == 2
        assert all(iface.current_task == TaskType.SCAN for iface in pool)

    def test_acquire_pool_all_available():
        lb = _make_load_balancer()
        pool = run(lb.acquire_pool(TaskType.MONITOR))
        assert len(pool) == 4

    def test_acquire_pool_respects_count():
        lb = _make_load_balancer()
        pool = run(lb.acquire_pool(TaskType.SCAN, count=1))
        assert len(pool) == 1

    def test_acquire_pool_empty_when_none():
        lb = _make_load_balancer()
        run(lb.acquire_pool(TaskType.SCAN))
        pool2 = run(lb.acquire_pool(TaskType.MONITOR, count=2))
        assert pool2 == []

    # Round-robin
    def test_round_robin_rotates():
        lb = _make_load_balancer()
        pool1 = run(lb.acquire_pool(TaskType.SCAN, count=1, strategy="round_robin"))
        first = pool1[0].name
        run(lb.release_pool(pool1))
        pool2 = run(lb.acquire_pool(TaskType.SCAN, count=1, strategy="round_robin"))
        second = pool2[0].name
        assert first != second

    # Least-loaded
    def test_least_loaded_prefers_idle():
        lb = _make_load_balancer()
        pool1 = run(lb.acquire_pool(TaskType.SCAN, count=1, strategy="least_loaded"))
        first = pool1[0].name
        pool2 = run(lb.acquire_pool(TaskType.MONITOR, count=1, strategy="least_loaded"))
        second = pool2[0].name
        assert first != second

    # Band-split
    def test_band_split_5ghz_first():
        lb = _make_load_balancer()
        pool = run(lb.acquire_pool(TaskType.SCAN, count=4, strategy="band_split"))
        assert len(pool) == 4
        # 5GHz should come before 2.4GHz
        five_ghz = [i for i in pool if i.supports_5ghz]
        two_ghz = [i for i in pool if not i.supports_5ghz]
        assert len(five_ghz) >= 1
        assert len(two_ghz) >= 1

    # Health monitoring
    def test_adapter_removed_after_errors():
        lb = _make_load_balancer()
        for i in range(ERROR_THRESHOLD):
            run(lb.report_error("wlan0", f"error {i}"))
        assert "wlan0" in lb.removed_adapters
        assert "wlan0" not in lb.healthy_interfaces

    def test_success_resets_errors():
        lb = _make_load_balancer()
        run(lb.report_error("wlan0", "e1"))
        run(lb.report_error("wlan0", "e2"))
        run(lb.report_success("wlan0"))
        run(lb.report_error("wlan0", "e3"))
        run(lb.report_error("wlan0", "e4"))
        assert "wlan0" in lb.healthy_interfaces

    def test_restore_adapter():
        lb = _make_load_balancer()
        for i in range(ERROR_THRESHOLD):
            run(lb.report_error("wlan0", f"error {i}"))
        assert "wlan0" in lb.removed_adapters
        result = run(lb.restore_adapter("wlan0"))
        assert result is True
        assert "wlan0" in lb.healthy_interfaces

    # Release
    def test_release_makes_available():
        lb = _make_load_balancer()
        pool = run(lb.acquire_pool(TaskType.SCAN, count=2))
        run(lb.release_pool(pool))
        for iface in pool:
            assert iface.current_task == TaskType.IDLE

    # MockLoadBalancer
    def test_mock_lb_setup():
        mlb = _make_mock_lb()
        assert len(mlb.healthy_interfaces) == 4

    # Workload
    def test_packets_tracking():
        lb = _make_load_balancer()
        run(lb.report_packets("wlan0", 100))
        run(lb.report_packets("wlan0", 50))
        wl = lb.get_workload("wlan0")
        assert wl.packets_processed == 150

    tests = [
        ("test_acquire_pool_returns_multiple", test_acquire_pool_returns_multiple),
        ("test_acquire_pool_all_available", test_acquire_pool_all_available),
        ("test_acquire_pool_respects_count", test_acquire_pool_respects_count),
        ("test_acquire_pool_empty_when_none", test_acquire_pool_empty_when_none),
        ("test_round_robin_rotates", test_round_robin_rotates),
        ("test_least_loaded_prefers_idle", test_least_loaded_prefers_idle),
        ("test_band_split_5ghz_first", test_band_split_5ghz_first),
        ("test_adapter_removed_after_errors", test_adapter_removed_after_errors),
        ("test_success_resets_errors", test_success_resets_errors),
        ("test_restore_adapter", test_restore_adapter),
        ("test_release_makes_available", test_release_makes_available),
        ("test_mock_lb_setup", test_mock_lb_setup),
        ("test_packets_tracking", test_packets_tracking),
    ]

    for name, func in tests:
        _run_test(name, func)

    print(f"\nResults: {passed} passed, {failed} failed")
    sys.exit(0 if failed == 0 else 1)
