"""
POSFramework Event Bus - Async Pub/Sub Event System.

Provides decoupled communication between components via events.

Features:
- Async event processing via queue-based dispatch loop
- Type-safe events with dataclasses
- Priority-based handlers
- Event history for debugging
- Graceful error handling
- Sync emit for non-async callers (emit_sync)

Usage:
    bus = EventBus()

    @bus.on(EventType.AP_DISCOVERED)
    async def handle_ap(event: Event):
        print(f"New AP: {event.data}")

    await bus.emit(EventType.AP_DISCOVERED, data=ap_info)
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

logger = logging.getLogger(__name__)

# Type alias for async handler functions
AsyncHandler = Callable[["Event"], Coroutine[Any, Any, None]]


class EventType(Enum):
    """All event types in the POSFramework system."""

    # Lifecycle
    SYSTEM_STARTING = auto()
    SYSTEM_READY = auto()
    SYSTEM_STOPPING = auto()
    SYSTEM_ERROR = auto()

    # WiFi Scanning / Recon
    SCAN_STARTED = auto()
    SCAN_COMPLETED = auto()
    AP_DISCOVERED = auto()
    AP_UPDATED = auto()
    AP_LOST = auto()
    CLIENT_DISCOVERED = auto()
    PROBE_CAPTURED = auto()

    # Handshake / Capture
    HANDSHAKE_STARTED = auto()
    HANDSHAKE_CAPTURED = auto()
    HANDSHAKE_FAILED = auto()
    PMKID_CAPTURED = auto()

    # Attacks
    ATTACK_STARTED = auto()
    ATTACK_COMPLETED = auto()
    ATTACK_FAILED = auto()
    DEAUTH_SENT = auto()
    ROGUE_AP_STARTED = auto()
    ROGUE_AP_STOPPED = auto()

    # Credential Capture
    CREDENTIAL_CAPTURED = auto()
    CREDENTIAL_VERIFIED = auto()

    # Cracking
    CRACK_STARTED = auto()
    CRACK_PROGRESS = auto()
    CRACK_SUCCESS = auto()
    CRACK_FAILED = auto()

    # Hardware
    ADAPTER_CONNECTED = auto()
    ADAPTER_DISCONNECTED = auto()

    # Plugin
    PLUGIN_LOADED = auto()
    PLUGIN_ERROR = auto()
    PLUGIN_UNLOADED = auto()

    # Metrics / Storage
    METRICS_UPDATE = auto()
    STORAGE_LOW = auto()


@dataclass
class Event:
    """Immutable event with metadata."""

    type: EventType
    data: Any = None
    timestamp: float = field(default_factory=time.time)
    source: str = "system"
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])


@dataclass
class HandlerInfo:
    """Handler registration info."""

    handler: AsyncHandler
    priority: int = 100  # Lower = higher priority
    once: bool = False  # Remove after first call


class EventBus:
    """
    Async event bus with pub/sub pattern.

    Concurrency model: this bus runs on a SINGLE asyncio event loop. subscribe,
    unsubscribe, emit and dispatch are safe with respect to each other on that loop.
    From another OS thread, use emit_sync which marshals the event onto the loop
    via call_soon_threadsafe.

    Supports:
    - Multiple handlers per event
    - Priority ordering
    - One-time handlers
    - Event history
    - Error isolation (a failing handler does not stop others)
    """

    def __init__(self, max_history: int = 1000) -> None:
        self._handlers: dict[EventType, list[HandlerInfo]] = {}
        self._queue: asyncio.Queue[Event] = asyncio.Queue()
        self._running = False
        self._task: asyncio.Task[None] | None = None
        self._history: list[Event] = []
        self._max_history = max_history
        self._stats: dict[str, int] = {
            "events_published": 0,
            "events_processed": 0,
            "handler_errors": 0,
        }

    def subscribe(
        self,
        event_type: EventType,
        handler: AsyncHandler,
        priority: int = 100,
        once: bool = False,
    ) -> None:
        """
        Subscribe to an event type.

        Args:
            event_type: Event to listen for
            handler: Async handler function
            priority: Lower = called first (default 100)
            once: Remove handler after first call
        """
        if event_type not in self._handlers:
            self._handlers[event_type] = []

        info = HandlerInfo(handler=handler, priority=priority, once=once)
        self._handlers[event_type].append(info)
        # Sort by priority
        self._handlers[event_type].sort(key=lambda h: h.priority)

        logger.debug(
            "Subscribed to %s: %s (priority=%d)",
            event_type.name,
            handler.__name__,
            priority,
        )

    def unsubscribe(self, event_type: EventType, handler: AsyncHandler) -> bool:
        """Remove a handler. Returns True if found and removed."""
        if event_type not in self._handlers:
            return False

        for i, info in enumerate(self._handlers[event_type]):
            if info.handler == handler:
                del self._handlers[event_type][i]
                return True
        return False

    def on(
        self, event_type: EventType, priority: int = 100, once: bool = False
    ) -> Callable[[AsyncHandler], AsyncHandler]:
        """
        Decorator for subscribing to events.

        Usage:
            @bus.on(EventType.AP_DISCOVERED)
            async def handle_ap(event: Event):
                print(event.data)
        """
        def decorator(handler: AsyncHandler) -> AsyncHandler:
            self.subscribe(event_type, handler, priority, once)
            return handler
        return decorator

    async def emit(
        self,
        event_type: EventType,
        data: Any = None,
        source: str = "system",
    ) -> Event:
        """
        Emit an event asynchronously.

        Returns the created Event object.
        """
        event = Event(type=event_type, data=data, source=source)
        await self._queue.put(event)
        self._stats["events_published"] += 1
        return event

    def emit_sync(
        self,
        event_type: EventType,
        data: Any = None,
        source: str = "system",
    ) -> Event:
        """
        Emit event from sync context (schedules on loop).

        Use this from synchronous code (e.g., the orchestrator). If no
        event loop is running, the event is queued directly.
        """
        event = Event(type=event_type, data=data, source=source)
        try:
            loop = asyncio.get_running_loop()
            loop.call_soon_threadsafe(self._queue.put_nowait, event)
        except RuntimeError:
            # No running loop - queue directly
            self._queue.put_nowait(event)
        self._stats["events_published"] += 1
        return event

    async def start(self) -> None:
        """Start the event processing loop."""
        if self._running:
            return

        self._running = True
        self._task = asyncio.create_task(self._process_loop())
        logger.info("Event bus started")

    async def stop(self, timeout: float = 5.0) -> None:
        """Stop the event bus gracefully."""
        self._running = False

        if self._task:
            # Wait for queue to drain
            try:
                await asyncio.wait_for(self._queue.join(), timeout=timeout)
            except (TimeoutError, asyncio.TimeoutError):
                logger.warning("Event queue drain timeout, forcing stop")

            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

        logger.info("Event bus stopped")

    async def _process_loop(self) -> None:
        """Main event processing loop."""
        while self._running:
            try:
                event = await asyncio.wait_for(
                    self._queue.get(),
                    timeout=1.0,
                )
            except (TimeoutError, asyncio.TimeoutError):
                continue

            try:
                await self._dispatch(event)
            finally:
                self._queue.task_done()

    async def _dispatch(self, event: Event) -> None:
        """Dispatch event to all subscribed handlers."""
        # Add to history
        self._history.append(event)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history:]

        # Iterate a snapshot so handlers can modify subscriptions during dispatch
        handlers = list(self._handlers.get(event.type, []))
        if not handlers:
            logger.debug("No handlers for %s", event.type.name)
            return

        to_remove: list[HandlerInfo] = []

        for info in handlers:
            try:
                await info.handler(event)
                self._stats["events_processed"] += 1

                if info.once:
                    to_remove.append(info)

            except Exception as e:
                logger.error(
                    "Handler error for %s: %s - %s",
                    event.type.name,
                    info.handler.__name__,
                    e,
                )
                self._stats["handler_errors"] += 1

        # Remove one-time handlers
        current = self._handlers.get(event.type, [])
        for info in to_remove:
            if info in current:
                current.remove(info)

    def get_history(
        self,
        event_type: EventType | None = None,
        limit: int = 100,
    ) -> list[Event]:
        """Get recent events, optionally filtered by type."""
        events = self._history
        if event_type:
            events = [e for e in events if e.type == event_type]
        return events[-limit:]

    def get_stats(self) -> dict[str, int]:
        """Get event bus statistics."""
        return {
            **self._stats,
            "queue_size": self._queue.qsize(),
            "handler_count": sum(len(h) for h in self._handlers.values()),
            "history_size": len(self._history),
        }

    def clear_history(self) -> None:
        """Clear event history."""
        self._history.clear()


# Global event bus instance
_bus: EventBus | None = None


def get_event_bus() -> EventBus:
    """Get or create global event bus singleton."""
    global _bus
    if _bus is None:
        _bus = EventBus()
    return _bus


async def emit(event_type: EventType, data: Any = None, source: str = "system") -> Event:
    """Convenience function to emit on global bus."""
    return await get_event_bus().emit(event_type, data, source)


def on(
    event_type: EventType, priority: int = 100, once: bool = False
) -> Callable[[AsyncHandler], AsyncHandler]:
    """Convenience decorator for global bus."""
    return get_event_bus().on(event_type, priority, once)
