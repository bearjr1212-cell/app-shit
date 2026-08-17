"""
AutoPwn Engine - Autonomous Attack State Machine.

The main orchestrator for autonomous attack operations, ported from
MoMo's architecture and adapted to use posframework's EventBus,
ReconEngine, DeauthEngine, and HandshakeCapture.

Features:
- Full state machine: IDLE -> SCANNING -> ANALYZING -> ATTACKING -> CRACKING
- Session persistence and resumption
- Event-driven via EventBus (pub/sub)
- Configurable attack modes (PASSIVE/BALANCED/AGGRESSIVE)
- Battery and session duration safety checks
- Callback registration for all lifecycle events
- Wraps synchronous scapy operations with asyncio.to_thread()

Usage:
    engine = AutoPwnEngine(config=AutoPwnConfig(mode=AutoPwnMode.BALANCED))
    engine.on_state_change(my_state_handler)
    await engine.start()
    ...
    await engine.stop()
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Callable, Coroutine, Dict, List, Optional

from .attack_chain import (
    AttackChain,
    AttackChainConfig,
    AttackResult,
    AttackType,
)
from .event_bus import EventType, get_event_bus
from .session_manager import (
    Session,
    SessionManager,
    SessionState,
)
from .target_scorer import (
    Target,
    TargetAnalyzer,
    TargetAnalyzerConfig,
    TargetStatus,
    TargetType,
)

logger = logging.getLogger(__name__)


class AutoPwnMode(Enum):
    """AutoPwn operation modes."""

    PASSIVE = auto()      # Only scan and analyze, no attacks
    BALANCED = auto()     # Careful attacks, longer cooldowns
    AGGRESSIVE = auto()   # Full-speed attacks


class AutoPwnState(Enum):
    """Engine state machine states."""

    IDLE = auto()
    SCANNING = auto()
    ANALYZING = auto()
    ATTACKING = auto()
    CRACKING = auto()
    PAUSED = auto()
    STOPPING = auto()


@dataclass
class AutoPwnConfig:
    """AutoPwn engine configuration."""

    # Mode
    mode: AutoPwnMode = AutoPwnMode.AGGRESSIVE

    # Scanning
    scan_interval: float = 30.0
    scan_channels: List[int] = field(default_factory=lambda: [1, 6, 11])
    scan_5ghz: bool = True

    # Targeting
    target_config: TargetAnalyzerConfig = field(
        default_factory=TargetAnalyzerConfig
    )
    max_concurrent_attacks: int = 1

    # Attacks
    attack_config: AttackChainConfig = field(
        default_factory=AttackChainConfig
    )
    enable_pmkid: bool = True
    enable_deauth: bool = True
    enable_eviltwin: bool = False

    # Cracking
    enable_local_crack: bool = True
    enable_cloud_crack: bool = False
    crack_timeout: int = 300

    # Safety
    whitelist_ssids: List[str] = field(default_factory=list)
    blacklist_ssids: List[str] = field(default_factory=list)
    whitelist_bssids: List[str] = field(default_factory=list)
    blacklist_bssids: List[str] = field(default_factory=list)
    max_session_duration: int = 0  # 0 = unlimited
    stop_on_low_battery: int = 20

    # Session
    session_dir: str = "logs/autopwn"
    auto_save_interval: float = 30.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "mode": self.mode.name,
            "scan_interval": self.scan_interval,
            "max_concurrent_attacks": self.max_concurrent_attacks,
            "enable_pmkid": self.enable_pmkid,
            "enable_deauth": self.enable_deauth,
            "enable_eviltwin": self.enable_eviltwin,
            "enable_local_crack": self.enable_local_crack,
            "enable_cloud_crack": self.enable_cloud_crack,
        }


class AutoPwnEngine:
    """
    Autonomous attack engine with full state machine.

    Orchestrates the complete auto-pwn workflow:
    1. Scan for targets (via ReconEngine wrapped in asyncio.to_thread)
    2. Analyze and prioritize (via TargetAnalyzer)
    3. Execute attack chains (via AttackChain)
    4. Crack captured hashes
    5. Report results via EventBus

    The engine emits events on the posframework EventBus at each
    state transition and significant operation.
    """

    def __init__(
        self,
        config: Optional[AutoPwnConfig] = None,
        wifi_scanner: Any = None,
        ble_scanner: Any = None,
        capture_manager: Any = None,
        eviltwin_manager: Any = None,
        cracker: Any = None,
    ) -> None:
        self.config = config or AutoPwnConfig()

        # External components (posframework engines)
        self._wifi_scanner = wifi_scanner
        self._ble_scanner = ble_scanner
        self._capture_manager = capture_manager
        self._eviltwin_manager = eviltwin_manager
        self._cracker = cracker

        # Internal components
        self._target_analyzer = TargetAnalyzer(self.config.target_config)
        self._attack_chain = AttackChain(
            config=self.config.attack_config,
            capture_manager=capture_manager,
            eviltwin_manager=eviltwin_manager,
        )
        self._session_manager = SessionManager(
            session_dir=self.config.session_dir,
            auto_save_interval=self.config.auto_save_interval,
        )

        # EventBus integration
        self._event_bus = get_event_bus()

        # State
        self._state = AutoPwnState.IDLE
        self._running = False
        self._paused = False

        # Tasks
        self._main_loop_task: Optional[asyncio.Task] = None
        self._attack_tasks: List[asyncio.Task] = []

        # Callbacks
        self._on_state_change: List[
            Callable[[AutoPwnState], Coroutine[Any, Any, None]]
        ] = []
        self._on_target_found: List[
            Callable[[Target], Coroutine[Any, Any, None]]
        ] = []
        self._on_attack_complete: List[
            Callable[[AttackResult], Coroutine[Any, Any, None]]
        ] = []
        self._on_capture: List[
            Callable[[Target, str], Coroutine[Any, Any, None]]
        ] = []
        self._on_crack: List[
            Callable[[str, str], Coroutine[Any, Any, None]]
        ] = []

        # Stats
        self._start_time: Optional[datetime] = None

        # Register attack chain callbacks
        self._attack_chain.on_attack_complete(self._handle_attack_complete)

    # ═══════════════════════════════════════════════════════════════════════════
    # Lifecycle
    # ═══════════════════════════════════════════════════════════════════════════

    async def start(self, resume_session_id: Optional[str] = None) -> None:
        """Start the AutoPwn engine."""
        if self._running:
            logger.warning("Engine already running")
            return

        logger.info(
            "Starting AutoPwn engine in %s mode", self.config.mode.name
        )

        self._running = True
        self._paused = False
        self._start_time = datetime.now()

        # Start session manager
        await self._session_manager.start()

        # Create or resume session
        if resume_session_id:
            session = await self._session_manager.resume_session(
                resume_session_id
            )
            if not session:
                session = await self._session_manager.create_session(
                    config=self.config.to_dict(),
                )
        else:
            session = await self._session_manager.create_session(
                config=self.config.to_dict(),
            )

        session.started_at = datetime.now()
        session.state = SessionState.RUNNING

        # Start main loop
        self._main_loop_task = asyncio.create_task(self._main_loop())

        await self._set_state(AutoPwnState.SCANNING)

        # Emit event on bus
        self._event_bus.emit_sync(
            EventType.SYSTEM_STARTING,
            data={
                "mode": self.config.mode.name,
                "session_id": session.id,
            },
            source="autopwn_engine",
        )

        logger.info("AutoPwn engine started, session: %s", session.id)

    async def stop(self) -> None:
        """Stop the AutoPwn engine."""
        if not self._running:
            return

        logger.info("Stopping AutoPwn engine...")
        await self._set_state(AutoPwnState.STOPPING)

        self._running = False

        # Cancel attack tasks
        for task in self._attack_tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        # Cancel main loop
        if self._main_loop_task:
            self._main_loop_task.cancel()
            try:
                await self._main_loop_task
            except asyncio.CancelledError:
                pass

        # End session
        await self._session_manager.end_session()
        await self._session_manager.stop()

        await self._set_state(AutoPwnState.IDLE)

        # Emit event
        self._event_bus.emit_sync(
            EventType.SYSTEM_STOPPING,
            data={"reason": "engine_stop"},
            source="autopwn_engine",
        )

        logger.info("AutoPwn engine stopped")

    async def pause(self) -> None:
        """Pause the engine."""
        if not self._running or self._paused:
            return

        self._paused = True
        await self._session_manager.pause_session()
        await self._set_state(AutoPwnState.PAUSED)
        logger.info("AutoPwn engine paused")

    async def resume(self) -> None:
        """Resume from pause."""
        if not self._paused:
            return

        self._paused = False

        if self._session_manager.current_session:
            self._session_manager.current_session.state = SessionState.RUNNING

        await self._set_state(AutoPwnState.SCANNING)
        logger.info("AutoPwn engine resumed")

    # ═══════════════════════════════════════════════════════════════════════════
    # Main Loop
    # ═══════════════════════════════════════════════════════════════════════════

    async def _main_loop(self) -> None:
        """Main operation loop cycling through phases."""
        while self._running:
            try:
                if self._paused:
                    await asyncio.sleep(1.0)
                    continue

                # Check session duration limit
                if self._should_stop_session():
                    logger.info("Session duration limit reached")
                    await self.stop()
                    break

                # Check battery
                if await self._should_stop_battery():
                    logger.warning("Low battery, stopping")
                    await self.stop()
                    break

                # Scan phase
                await self._set_state(AutoPwnState.SCANNING)
                await self._scan_phase()

                # Analyze phase
                await self._set_state(AutoPwnState.ANALYZING)
                await self._analyze_phase()

                # Attack phase (skip in PASSIVE mode)
                if self.config.mode != AutoPwnMode.PASSIVE:
                    await self._set_state(AutoPwnState.ATTACKING)
                    await self._attack_phase()

                    # Crack phase
                    if self.config.enable_local_crack:
                        await self._set_state(AutoPwnState.CRACKING)
                        await self._crack_phase()

                # Wait before next cycle
                await asyncio.sleep(self.config.scan_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Main loop error: %s", e)
                await asyncio.sleep(5.0)

    async def _scan_phase(self) -> None:
        """Scan for targets using the wifi_scanner via asyncio.to_thread."""
        logger.debug("Starting scan phase")

        if self._wifi_scanner:
            try:
                # Wrap synchronous scanner in thread
                if asyncio.iscoroutinefunction(
                    getattr(self._wifi_scanner, "scan", None)
                ):
                    results = await self._wifi_scanner.scan(
                        channels=self.config.scan_channels,
                    )
                else:
                    results = await asyncio.to_thread(
                        self._wifi_scanner.scan,
                        channels=self.config.scan_channels,
                    )

                new_targets = await self._target_analyzer.process_scan_results(
                    results,
                    target_type=TargetType.WIFI_AP,
                )

                # Notify new targets
                for target in new_targets:
                    await self._notify_target_found(target)

                    session = self._session_manager.current_session
                    if session:
                        session.add_target(target)

                # Emit scan completed event
                self._event_bus.emit_sync(
                    EventType.SCAN_COMPLETED,
                    data={
                        "new_targets": len(new_targets),
                        "total_targets": len(self._target_analyzer.targets),
                    },
                    source="autopwn_engine",
                )

            except Exception as e:
                logger.error("WiFi scan error: %s", e)

    async def _analyze_phase(self) -> None:
        """Analyze and prioritize targets."""
        logger.debug("Starting analyze phase")

        targets = await self._target_analyzer.get_next_targets(
            count=self.config.max_concurrent_attacks,
        )

        logger.debug("Selected %d targets for attack", len(targets))

    async def _attack_phase(self) -> None:
        """Execute attacks on selected targets."""
        targets = await self._target_analyzer.get_next_targets(
            count=self.config.max_concurrent_attacks,
        )

        if not targets:
            logger.debug("No targets available for attack")
            return

        for target in targets:
            if not self._running or self._paused:
                break

            await self._target_analyzer.mark_attacking(target.id)

            logger.info(
                "Attacking target: %s (%s)", target.ssid, target.bssid
            )

            # Emit attack started event
            self._event_bus.emit_sync(
                EventType.ATTACK_STARTED,
                data={
                    "target_id": target.id,
                    "ssid": target.ssid,
                    "bssid": target.bssid,
                },
                source="autopwn_engine",
            )

            # Execute attack chain
            await self._attack_chain.execute(target)

            # Process results
            success_result = self._attack_chain.get_successful_result()

            if success_result and success_result.success:
                await self._handle_capture(target, success_result)
            else:
                await self._target_analyzer.mark_failed(
                    target.id,
                    "chain",
                    "All attacks failed",
                )

    async def _crack_phase(self) -> None:
        """Crack captured hashes."""
        if not self._cracker:
            return

        targets_to_crack = [
            t for t in self._target_analyzer.targets
            if (t.handshake_captured or t.pmkid_captured)
            and not t.password
            and t.status == TargetStatus.CAPTURED
        ]

        for target in targets_to_crack:
            if not self._running or self._paused:
                break

            logger.info("Cracking: %s", target.ssid)

            # Emit crack started event
            self._event_bus.emit_sync(
                EventType.CRACK_STARTED,
                data={"target_id": target.id, "ssid": target.ssid},
                source="autopwn_engine",
            )

            try:
                # Wrap cracker in thread if synchronous
                if asyncio.iscoroutinefunction(
                    getattr(self._cracker, "crack", None)
                ):
                    result = await asyncio.wait_for(
                        self._cracker.crack(target.bssid),
                        timeout=self.config.crack_timeout,
                    )
                else:
                    result = await asyncio.wait_for(
                        asyncio.to_thread(
                            self._cracker.crack, target.bssid
                        ),
                        timeout=self.config.crack_timeout,
                    )

                if result and result.get("password"):
                    password = result["password"]
                    await self._target_analyzer.mark_cracked(
                        target.id, password
                    )

                    await self._notify_crack(target.ssid, password)

                    session = self._session_manager.current_session
                    if session:
                        session.record_crack(target.ssid, password)

                    # Emit crack success event
                    self._event_bus.emit_sync(
                        EventType.CRACK_SUCCESS,
                        data={
                            "target_id": target.id,
                            "ssid": target.ssid,
                        },
                        source="autopwn_engine",
                    )

            except (TimeoutError, asyncio.TimeoutError):
                logger.debug("Crack timeout for %s", target.ssid)
            except Exception as e:
                logger.error("Crack error: %s", e)

    # ═══════════════════════════════════════════════════════════════════════════
    # Event Handlers
    # ═══════════════════════════════════════════════════════════════════════════

    async def _handle_attack_complete(self, result: AttackResult) -> None:
        """Handle attack completion."""
        session = self._session_manager.current_session
        if session:
            session.record_attack(result.success)

        # Emit event
        self._event_bus.emit_sync(
            EventType.ATTACK_COMPLETED,
            data={
                "target_id": result.target_id,
                "attack_type": result.attack_type.name,
                "success": result.success,
            },
            source="autopwn_engine",
        )

        for callback in self._on_attack_complete:
            try:
                await callback(result)
            except Exception as e:
                logger.error("Attack complete callback error: %s", e)

    async def _handle_capture(
        self,
        target: Target,
        result: AttackResult,
    ) -> None:
        """Handle successful capture."""
        capture_type = "handshake"
        if result.attack_type == AttackType.PMKID:
            capture_type = "pmkid"
        elif result.attack_type == AttackType.EVIL_TWIN:
            capture_type = "credential"

        await self._target_analyzer.mark_captured(target.id, capture_type)

        session = self._session_manager.current_session
        if session and result.capture_file:
            session.record_capture(
                target.id,
                capture_type,
                result.capture_file,
            )

        await self._notify_capture(target, capture_type)

        # Emit capture event
        event_type = EventType.HANDSHAKE_CAPTURED
        if capture_type == "pmkid":
            event_type = EventType.PMKID_CAPTURED
        elif capture_type == "credential":
            event_type = EventType.CREDENTIAL_CAPTURED

        self._event_bus.emit_sync(
            event_type,
            data={
                "target_id": target.id,
                "ssid": target.ssid,
                "capture_type": capture_type,
                "file": result.capture_file,
            },
            source="autopwn_engine",
        )

        logger.info("Captured %s for %s", capture_type, target.ssid)

    # ═══════════════════════════════════════════════════════════════════════════
    # Callbacks
    # ═══════════════════════════════════════════════════════════════════════════

    def on_state_change(
        self,
        callback: Callable[[AutoPwnState], Coroutine[Any, Any, None]],
    ) -> None:
        """Register state change callback."""
        self._on_state_change.append(callback)

    def on_target_found(
        self,
        callback: Callable[[Target], Coroutine[Any, Any, None]],
    ) -> None:
        """Register target found callback."""
        self._on_target_found.append(callback)

    def on_attack_complete(
        self,
        callback: Callable[[AttackResult], Coroutine[Any, Any, None]],
    ) -> None:
        """Register attack complete callback."""
        self._on_attack_complete.append(callback)

    def on_capture(
        self,
        callback: Callable[[Target, str], Coroutine[Any, Any, None]],
    ) -> None:
        """Register capture callback."""
        self._on_capture.append(callback)

    def on_crack(
        self,
        callback: Callable[[str, str], Coroutine[Any, Any, None]],
    ) -> None:
        """Register crack callback."""
        self._on_crack.append(callback)

    async def _set_state(self, state: AutoPwnState) -> None:
        """Set engine state, notify callbacks, and emit event."""
        if state == self._state:
            return

        self._state = state
        logger.debug("State: %s", state.name)

        for callback in self._on_state_change:
            try:
                await callback(state)
            except Exception as e:
                logger.error("State change callback error: %s", e)

    async def _notify_target_found(self, target: Target) -> None:
        """Notify target found."""
        for callback in self._on_target_found:
            try:
                await callback(target)
            except Exception as e:
                logger.error("Target found callback error: %s", e)

    async def _notify_capture(self, target: Target, capture_type: str) -> None:
        """Notify capture."""
        for callback in self._on_capture:
            try:
                await callback(target, capture_type)
            except Exception as e:
                logger.error("Capture callback error: %s", e)

    async def _notify_crack(self, ssid: str, password: str) -> None:
        """Notify crack."""
        for callback in self._on_crack:
            try:
                await callback(ssid, password)
            except Exception as e:
                logger.error("Crack callback error: %s", e)

    # ═══════════════════════════════════════════════════════════════════════════
    # Helpers
    # ═══════════════════════════════════════════════════════════════════════════

    def _should_stop_session(self) -> bool:
        """Check if session should stop due to duration."""
        if self.config.max_session_duration <= 0:
            return False
        if not self._start_time:
            return False
        elapsed = (datetime.now() - self._start_time).total_seconds()
        return elapsed >= self.config.max_session_duration

    async def _should_stop_battery(self) -> bool:
        """Check if should stop due to low battery."""
        if self.config.stop_on_low_battery <= 0:
            return False
        try:
            with open("/sys/class/power_supply/BAT0/capacity") as f:
                level = int(f.read().strip())
                return level <= self.config.stop_on_low_battery
        except Exception:
            return False

    # ═══════════════════════════════════════════════════════════════════════════
    # Properties
    # ═══════════════════════════════════════════════════════════════════════════

    @property
    def state(self) -> AutoPwnState:
        """Get current state."""
        return self._state

    @property
    def is_running(self) -> bool:
        """Check if engine is running."""
        return self._running

    @property
    def is_paused(self) -> bool:
        """Check if engine is paused."""
        return self._paused

    @property
    def session(self) -> Optional[Session]:
        """Get current session."""
        return self._session_manager.current_session

    @property
    def targets(self) -> List[Target]:
        """Get all targets."""
        return self._target_analyzer.targets

    @property
    def stats(self) -> Dict[str, Any]:
        """Get engine statistics."""
        session = self._session_manager.current_session
        target_stats = self._target_analyzer.stats

        return {
            "state": self._state.name,
            "mode": self.config.mode.name,
            "running": self._running,
            "paused": self._paused,
            "session_id": session.id if session else None,
            "uptime_seconds": (
                (datetime.now() - self._start_time).total_seconds()
                if self._start_time
                else 0
            ),
            "targets": target_stats,
            "session_stats": (
                session.stats.to_dict() if session else {}
            ),
        }
