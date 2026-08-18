"""
Load Balancer - Multi-Adapter Task Distribution.

Extends RadioManager to distribute the same task type across multiple
WiFi adapters simultaneously using configurable strategies.

Strategies:
- ROUND_ROBIN: Cycle through adapters sequentially
- LEAST_LOADED: Pick the adapter with fewest active tasks
- BAND_SPLIT: Dedicate 2.4GHz and 5GHz adapters to separate channel ranges

Features:
- Acquire pools of interfaces for parallel attacks/scanning
- Per-interface workload tracking (tasks assigned, packets processed, error rate)
- Health monitoring: adapters with 3+ consecutive errors are removed from pool
- Graceful degradation when adapters fail
- MockLoadBalancer for testing without hardware

Usage:
    from posframework.load_balancer import LoadBalancer
    from posframework.radio_manager import MockRadioManager, TaskType

    manager = MockRadioManager()
    await manager.discover_interfaces()

    lb = LoadBalancer(manager)
    pool = await lb.acquire_pool(TaskType.SCAN, count=2, strategy='round_robin')
    try:
        # Use interfaces in pool for parallel work
        ...
    finally:
        await lb.release_pool(pool)
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional

from .radio_manager import (
    Band,
    RadioInterface,
    RadioManager,
    MockRadioManager,
    TaskType,
)

logger = logging.getLogger(__name__)


class DistributionStrategy(Enum):
    """Strategies for distributing tasks across adapters."""

    ROUND_ROBIN = "round_robin"
    LEAST_LOADED = "least_loaded"
    BAND_SPLIT = "band_split"


@dataclass
class AdapterWorkload:
    """Tracks workload metrics for a single adapter."""

    interface_name: str
    tasks_assigned: int = 0
    tasks_completed: int = 0
    packets_processed: int = 0
    error_count: int = 0
    consecutive_errors: int = 0
    last_error: Optional[str] = None
    last_assigned: float = 0.0
    is_healthy: bool = True

    @property
    def error_rate(self) -> float:
        """Calculate error rate as a fraction of total tasks."""
        total = self.tasks_assigned
        if total == 0:
            return 0.0
        return self.error_count / total

    @property
    def active_tasks(self) -> int:
        """Number of currently active (uncompleted) tasks."""
        return max(0, self.tasks_assigned - self.tasks_completed)


# Threshold for consecutive errors before removing adapter from pool
ERROR_THRESHOLD = 3


class LoadBalancer:
    """
    Multi-adapter load balancer wrapping RadioManager.

    Distributes tasks across multiple WiFi adapters using configurable
    strategies for parallel attacks and scanning.
    """

    def __init__(self, radio_manager: RadioManager) -> None:
        """
        Initialize LoadBalancer with a RadioManager instance.

        Args:
            radio_manager: The RadioManager that manages the physical interfaces.
        """
        self._radio_manager = radio_manager
        self._lock = asyncio.Lock()
        self._workloads: Dict[str, AdapterWorkload] = {}
        self._round_robin_index: int = 0
        self._removed_adapters: List[str] = []
        self._stats = {
            "pools_acquired": 0,
            "pools_released": 0,
            "adapters_removed": 0,
            "total_tasks_distributed": 0,
        }

    @property
    def radio_manager(self) -> RadioManager:
        """Access the underlying RadioManager."""
        return self._radio_manager

    @property
    def workloads(self) -> Dict[str, AdapterWorkload]:
        """Get per-adapter workload data."""
        return dict(self._workloads)

    @property
    def healthy_interfaces(self) -> List[str]:
        """Get list of healthy interface names."""
        return [
            name for name, wl in self._workloads.items()
            if wl.is_healthy
        ]

    @property
    def removed_adapters(self) -> List[str]:
        """Get list of adapters removed due to errors."""
        return list(self._removed_adapters)

    @property
    def stats(self) -> dict:
        """Get load balancer statistics."""
        return dict(self._stats)

    async def initialize(self) -> None:
        """
        Initialize workload tracking for all discovered interfaces.

        Should be called after RadioManager.discover_interfaces().
        """
        async with self._lock:
            self._workloads.clear()
            self._removed_adapters.clear()
            self._round_robin_index = 0

            for iface in self._radio_manager.interfaces:
                self._workloads[iface.name] = AdapterWorkload(
                    interface_name=iface.name
                )

            logger.info(
                "LoadBalancer initialized with %d adapters: %s",
                len(self._workloads),
                ", ".join(self._workloads.keys()),
            )

    async def acquire_pool(
        self,
        task: TaskType,
        count: Optional[int] = None,
        strategy: str = "round_robin",
        prefer_5ghz: bool = False,
        require_injection: bool = False,
    ) -> List[RadioInterface]:
        """
        Acquire multiple interfaces for the same task type.

        Args:
            task: Type of task to perform on all interfaces.
            count: Number of interfaces to acquire (None = all available).
            strategy: Distribution strategy ('round_robin', 'least_loaded', 'band_split').
            prefer_5ghz: Prefer interfaces with 5GHz support.
            require_injection: Require packet injection support.

        Returns:
            List of acquired RadioInterface objects.
        """
        async with self._lock:
            strat = self._parse_strategy(strategy)
            available = self._get_healthy_available()

            if not available:
                logger.warning(
                    "No healthy interfaces available for pool acquisition"
                )
                return []

            # Filter by requirements
            candidates = self._filter_candidates(
                available, prefer_5ghz, require_injection
            )

            if not candidates:
                logger.warning(
                    "No candidates matching requirements for task %s", task.name
                )
                return []

            # Determine how many to acquire
            target_count = count if count is not None else len(candidates)
            target_count = min(target_count, len(candidates))

            if target_count <= 0:
                return []

            # Order candidates by strategy
            ordered = self._order_by_strategy(candidates, strat)

            # Acquire the interfaces
            acquired: List[RadioInterface] = []
            for iface in ordered[:target_count]:
                result = await self._acquire_single(iface, task)
                if result is not None:
                    acquired.append(result)

            self._stats["pools_acquired"] += 1
            self._stats["total_tasks_distributed"] += len(acquired)

            logger.info(
                "Acquired pool of %d interfaces for task %s (strategy: %s)",
                len(acquired), task.name, strategy,
            )

            return acquired

    async def release_pool(
        self,
        interfaces: List[RadioInterface],
        error: Optional[str] = None,
    ) -> None:
        """
        Release all interfaces in a pool back to the manager.

        Args:
            interfaces: List of interfaces to release.
            error: Optional error message if the pool task failed.
        """
        async with self._lock:
            for iface in interfaces:
                await self._release_single(iface, error)

            self._stats["pools_released"] += 1

            logger.info(
                "Released pool of %d interfaces%s",
                len(interfaces),
                f" (error: {error})" if error else "",
            )

    async def report_error(self, interface_name: str, error: str) -> None:
        """
        Report an error for a specific adapter.

        If consecutive errors reach the threshold, the adapter is removed
        from the healthy pool.

        Args:
            interface_name: Name of the interface that errored.
            error: Description of the error.
        """
        async with self._lock:
            workload = self._workloads.get(interface_name)
            if workload is None:
                return

            workload.error_count += 1
            workload.consecutive_errors += 1
            workload.last_error = error

            if workload.consecutive_errors >= ERROR_THRESHOLD:
                workload.is_healthy = False
                if interface_name not in self._removed_adapters:
                    self._removed_adapters.append(interface_name)
                    self._stats["adapters_removed"] += 1
                    logger.warning(
                        "Adapter %s removed from pool after %d consecutive errors: %s",
                        interface_name,
                        workload.consecutive_errors,
                        error,
                    )

    async def report_success(self, interface_name: str) -> None:
        """
        Report a successful operation for an adapter, resetting consecutive errors.

        Args:
            interface_name: Name of the interface that succeeded.
        """
        async with self._lock:
            workload = self._workloads.get(interface_name)
            if workload is None:
                return
            workload.consecutive_errors = 0

    async def report_packets(self, interface_name: str, count: int) -> None:
        """
        Report packets processed by an adapter.

        Args:
            interface_name: Name of the interface.
            count: Number of packets processed.
        """
        async with self._lock:
            workload = self._workloads.get(interface_name)
            if workload is not None:
                workload.packets_processed += count

    async def restore_adapter(self, interface_name: str) -> bool:
        """
        Restore a previously removed adapter to the healthy pool.

        Args:
            interface_name: Name of the interface to restore.

        Returns:
            True if restored, False if not found.
        """
        async with self._lock:
            workload = self._workloads.get(interface_name)
            if workload is None:
                return False

            workload.is_healthy = True
            workload.consecutive_errors = 0
            if interface_name in self._removed_adapters:
                self._removed_adapters.remove(interface_name)

            logger.info("Adapter %s restored to healthy pool", interface_name)
            return True

    def get_workload(self, interface_name: str) -> Optional[AdapterWorkload]:
        """Get workload metrics for a specific adapter."""
        return self._workloads.get(interface_name)

    # ================================================================
    # PRIVATE HELPERS
    # ================================================================

    def _parse_strategy(self, strategy: str) -> DistributionStrategy:
        """Parse strategy string to enum."""
        strategy_map = {
            "round_robin": DistributionStrategy.ROUND_ROBIN,
            "least_loaded": DistributionStrategy.LEAST_LOADED,
            "band_split": DistributionStrategy.BAND_SPLIT,
        }
        return strategy_map.get(strategy.lower(), DistributionStrategy.ROUND_ROBIN)

    def _get_healthy_available(self) -> List[RadioInterface]:
        """Get healthy and available interfaces."""
        available = self._radio_manager.available_interfaces
        healthy_names = {
            name for name, wl in self._workloads.items()
            if wl.is_healthy
        }
        return [iface for iface in available if iface.name in healthy_names]

    def _filter_candidates(
        self,
        interfaces: List[RadioInterface],
        prefer_5ghz: bool,
        require_injection: bool,
    ) -> List[RadioInterface]:
        """Filter interfaces by requirements."""
        candidates = interfaces

        if require_injection:
            candidates = [
                iface for iface in candidates
                if iface.supports_injection
            ]

        return candidates

    def _order_by_strategy(
        self,
        candidates: List[RadioInterface],
        strategy: DistributionStrategy,
    ) -> List[RadioInterface]:
        """Order candidates based on the distribution strategy."""
        if strategy == DistributionStrategy.ROUND_ROBIN:
            return self._order_round_robin(candidates)
        elif strategy == DistributionStrategy.LEAST_LOADED:
            return self._order_least_loaded(candidates)
        elif strategy == DistributionStrategy.BAND_SPLIT:
            return self._order_band_split(candidates)
        return candidates

    def _order_round_robin(
        self, candidates: List[RadioInterface]
    ) -> List[RadioInterface]:
        """Order by round-robin: rotate starting position each call."""
        if not candidates:
            return []

        n = len(candidates)
        start = self._round_robin_index % n
        self._round_robin_index += 1

        ordered = candidates[start:] + candidates[:start]
        return ordered

    def _order_least_loaded(
        self, candidates: List[RadioInterface]
    ) -> List[RadioInterface]:
        """Order by workload: least active tasks first."""
        def load_key(iface: RadioInterface) -> int:
            wl = self._workloads.get(iface.name)
            if wl is None:
                return 0
            return wl.active_tasks

        return sorted(candidates, key=load_key)

    def _order_band_split(
        self, candidates: List[RadioInterface]
    ) -> List[RadioInterface]:
        """
        Order by band: 5GHz adapters first, then 2.4GHz.

        In BAND_SPLIT mode the intent is to assign 5GHz-capable adapters
        to high-frequency channels and 2.4GHz-only adapters to low-frequency
        channels, enabling parallel coverage of both bands.
        """
        band_5ghz: List[RadioInterface] = []
        band_24ghz: List[RadioInterface] = []

        for iface in candidates:
            if iface.supports_5ghz:
                band_5ghz.append(iface)
            else:
                band_24ghz.append(iface)

        # Return 5GHz first then 2.4GHz
        return band_5ghz + band_24ghz

    async def _acquire_single(
        self, iface: RadioInterface, task: TaskType
    ) -> Optional[RadioInterface]:
        """Acquire a single interface and update workload tracking."""
        # Directly assign the task (we already hold the lock and verified availability)
        iface.current_task = task
        from datetime import datetime, timezone
        iface.assigned_at = datetime.now(timezone.utc)

        workload = self._workloads.get(iface.name)
        if workload:
            workload.tasks_assigned += 1
            workload.last_assigned = time.time()

        return iface

    async def _release_single(
        self, iface: RadioInterface, error: Optional[str] = None
    ) -> None:
        """Release a single interface and update workload tracking."""
        workload = self._workloads.get(iface.name)

        if error and workload:
            workload.error_count += 1
            workload.consecutive_errors += 1
            workload.last_error = error

            if workload.consecutive_errors >= ERROR_THRESHOLD:
                workload.is_healthy = False
                if iface.name not in self._removed_adapters:
                    self._removed_adapters.append(iface.name)
                    self._stats["adapters_removed"] += 1
                    logger.warning(
                        "Adapter %s removed from pool after %d consecutive errors",
                        iface.name,
                        workload.consecutive_errors,
                    )
        elif workload:
            workload.tasks_completed += 1
            workload.consecutive_errors = 0

        iface.current_task = TaskType.IDLE
        iface.assigned_at = None


class MockLoadBalancer(LoadBalancer):
    """
    Mock LoadBalancer for testing without hardware.

    Uses MockRadioManager internally for interface simulation.
    """

    def __init__(
        self,
        mock_interfaces: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize MockLoadBalancer with simulated interfaces.

        Args:
            mock_interfaces: List of interface names to simulate.
        """
        mock_manager = MockRadioManager(mock_interfaces=mock_interfaces)
        super().__init__(mock_manager)
        self._mock_manager = mock_manager

    async def setup(self) -> None:
        """Discover mock interfaces and initialize workload tracking."""
        await self._mock_manager.discover_interfaces()
        await self.initialize()

    @property
    def mock_manager(self) -> MockRadioManager:
        """Access the underlying mock radio manager."""
        return self._mock_manager
