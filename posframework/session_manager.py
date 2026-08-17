"""
AutoPwn Session Management.

Provides session persistence and resume capability for autonomous operations.

Features:
- JSON-based session persistence to logs/autopwn/
- Session creation, save, resume, pause, and end lifecycle
- Auto-save loop for crash recovery
- Session history and cleanup of old sessions
- Full serialization/deserialization of session state

Usage:
    manager = SessionManager(session_dir="logs/autopwn")
    await manager.start()
    session = await manager.create_session(config=config_dict)
    ...
    await manager.end_session()
    await manager.stop()
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class SessionState(Enum):
    """Session state."""

    NEW = auto()
    RUNNING = auto()
    PAUSED = auto()
    COMPLETED = auto()
    ABORTED = auto()


@dataclass
class SessionStats:
    """Session statistics."""

    targets_discovered: int = 0
    targets_attacked: int = 0
    targets_captured: int = 0
    targets_cracked: int = 0
    targets_failed: int = 0

    attacks_total: int = 0
    attacks_successful: int = 0
    attacks_failed: int = 0

    handshakes_captured: int = 0
    pmkids_captured: int = 0
    credentials_captured: int = 0
    passwords_cracked: int = 0

    def to_dict(self) -> Dict[str, int]:
        """Convert to dictionary."""
        return {
            "targets_discovered": self.targets_discovered,
            "targets_attacked": self.targets_attacked,
            "targets_captured": self.targets_captured,
            "targets_cracked": self.targets_cracked,
            "targets_failed": self.targets_failed,
            "attacks_total": self.attacks_total,
            "attacks_successful": self.attacks_successful,
            "attacks_failed": self.attacks_failed,
            "handshakes_captured": self.handshakes_captured,
            "pmkids_captured": self.pmkids_captured,
            "credentials_captured": self.credentials_captured,
            "passwords_cracked": self.passwords_cracked,
        }


@dataclass
class Session:
    """
    Represents an AutoPwn session.

    Tracks all targets, attacks, and results for a single
    auto-pwn run. Can be persisted and resumed.
    """

    # Identity
    id: str = ""
    name: str = ""

    # Timing
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    last_activity: datetime = field(default_factory=datetime.now)

    # State
    state: SessionState = SessionState.NEW

    # Configuration snapshot
    config: Dict[str, Any] = field(default_factory=dict)

    # Targets
    targets: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # Results
    stats: SessionStats = field(default_factory=SessionStats)

    # Capture files
    capture_files: List[str] = field(default_factory=list)
    cracked_passwords: Dict[str, str] = field(default_factory=dict)

    # Log
    events: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.id:
            self.id = datetime.now().strftime("%Y%m%d_%H%M%S")
        if not self.name:
            self.name = f"session_{self.id}"

    def add_event(
        self,
        event_type: str,
        message: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Add an event to the session log."""
        self.events.append({
            "timestamp": datetime.now().isoformat(),
            "type": event_type,
            "message": message,
            "data": data or {},
        })
        self.last_activity = datetime.now()

        # Keep last 1000 events
        if len(self.events) > 1000:
            self.events = self.events[-1000:]

    def add_target(self, target: Any) -> None:
        """Add or update a target (accepts any object with to_dict and id)."""
        target_dict = target.to_dict() if hasattr(target, "to_dict") else {}
        target_id = getattr(target, "id", str(target))
        ssid = getattr(target, "ssid", "unknown")
        self.targets[target_id] = target_dict
        self.stats.targets_discovered = len(self.targets)
        self.add_event("target_added", f"New target: {ssid}")

    def record_capture(
        self,
        target_id: str,
        capture_type: str,
        file_path: str,
    ) -> None:
        """Record a successful capture."""
        if file_path not in self.capture_files:
            self.capture_files.append(file_path)

        if capture_type == "handshake":
            self.stats.handshakes_captured += 1
        elif capture_type == "pmkid":
            self.stats.pmkids_captured += 1
        elif capture_type == "credential":
            self.stats.credentials_captured += 1

        self.stats.targets_captured += 1
        self.add_event(
            "capture",
            f"Captured {capture_type} for {target_id}",
            {"file": file_path},
        )

    def record_crack(self, ssid: str, password: str) -> None:
        """Record a cracked password."""
        self.cracked_passwords[ssid] = password
        self.stats.passwords_cracked += 1
        self.stats.targets_cracked += 1
        self.add_event(
            "crack",
            f"Cracked: {ssid}",
            {"password": password[:3] + "***"},
        )

    def record_attack(self, success: bool) -> None:
        """Record attack result."""
        self.stats.attacks_total += 1
        if success:
            self.stats.attacks_successful += 1
        else:
            self.stats.attacks_failed += 1

    @property
    def duration_seconds(self) -> float:
        """Get session duration in seconds."""
        if not self.started_at:
            return 0.0
        end = self.ended_at or datetime.now()
        return (end - self.started_at).total_seconds()

    @property
    def is_active(self) -> bool:
        """Check if session is active."""
        return self.state in (SessionState.RUNNING, SessionState.PAUSED)

    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary for serialization."""
        return {
            "id": self.id,
            "name": self.name,
            "created_at": self.created_at.isoformat(),
            "started_at": (
                self.started_at.isoformat() if self.started_at else None
            ),
            "ended_at": (
                self.ended_at.isoformat() if self.ended_at else None
            ),
            "last_activity": self.last_activity.isoformat(),
            "state": self.state.name,
            "config": self.config,
            "targets": self.targets,
            "stats": self.stats.to_dict(),
            "capture_files": self.capture_files,
            "cracked_passwords": self.cracked_passwords,
            "events": self.events[-100:],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Session":
        """Create session from dictionary."""
        session = cls(
            id=data.get("id", ""),
            name=data.get("name", ""),
        )

        if data.get("created_at"):
            session.created_at = datetime.fromisoformat(data["created_at"])
        if data.get("started_at"):
            session.started_at = datetime.fromisoformat(data["started_at"])
        if data.get("ended_at"):
            session.ended_at = datetime.fromisoformat(data["ended_at"])
        if data.get("last_activity"):
            session.last_activity = datetime.fromisoformat(data["last_activity"])

        session.state = SessionState[data.get("state", "NEW")]
        session.config = data.get("config", {})
        session.targets = data.get("targets", {})
        session.capture_files = data.get("capture_files", [])
        session.cracked_passwords = data.get("cracked_passwords", {})
        session.events = data.get("events", [])

        stats_data = data.get("stats", {})
        session.stats = SessionStats(**stats_data)

        return session


class SessionManager:
    """
    Manages AutoPwn sessions.

    Handles session creation, persistence, and resumption.
    Persists to JSON files in logs/autopwn/ directory.
    """

    def __init__(
        self,
        session_dir: str = "logs/autopwn",
        max_sessions: int = 10,
        auto_save_interval: float = 30.0,
    ) -> None:
        self.session_dir = Path(session_dir)
        self.max_sessions = max_sessions
        self.auto_save_interval = auto_save_interval

        self._current_session: Optional[Session] = None
        self._sessions: Dict[str, Session] = {}
        self._save_task: Optional[asyncio.Task] = None
        self._running = False

    async def start(self) -> None:
        """Start the session manager."""
        self._running = True

        # Ensure directory exists
        self.session_dir.mkdir(parents=True, exist_ok=True)

        # Load existing sessions
        await self._load_sessions()

        # Start auto-save task
        self._save_task = asyncio.create_task(self._auto_save_loop())

        logger.info(
            "Session manager started, %d sessions loaded",
            len(self._sessions),
        )

    async def stop(self) -> None:
        """Stop the session manager."""
        self._running = False

        if self._save_task:
            self._save_task.cancel()
            try:
                await self._save_task
            except asyncio.CancelledError:
                pass

        if self._current_session:
            await self.save_session(self._current_session)

        logger.info("Session manager stopped")

    async def _auto_save_loop(self) -> None:
        """Periodically save current session."""
        while self._running:
            try:
                await asyncio.sleep(self.auto_save_interval)

                if self._current_session and self._current_session.is_active:
                    await self.save_session(self._current_session)
                    logger.debug(
                        "Auto-saved session %s", self._current_session.id
                    )

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Auto-save error: %s", e)

    async def _load_sessions(self) -> None:
        """Load sessions from disk."""
        try:
            for file in self.session_dir.glob("session_*.json"):
                try:
                    data = json.loads(file.read_text())
                    session = Session.from_dict(data)
                    self._sessions[session.id] = session
                except Exception as e:
                    logger.warning("Failed to load session %s: %s", file, e)
        except Exception as e:
            logger.error("Failed to load sessions: %s", e)

    async def save_session(self, session: Session) -> None:
        """Save session to disk."""
        try:
            self.session_dir.mkdir(parents=True, exist_ok=True)
            file_path = self.session_dir / f"session_{session.id}.json"
            data = session.to_dict()

            # Write atomically
            temp_path = file_path.with_suffix(".tmp")
            temp_path.write_text(json.dumps(data, indent=2, default=str))
            temp_path.replace(file_path)

            logger.debug("Saved session %s", session.id)

        except Exception as e:
            logger.error("Failed to save session: %s", e)

    async def create_session(
        self,
        name: str = "",
        config: Optional[Dict[str, Any]] = None,
    ) -> Session:
        """Create a new session."""
        session = Session(name=name, config=config or {})
        self._sessions[session.id] = session
        self._current_session = session

        session.add_event("created", "Session created")

        await self._cleanup_old_sessions()

        logger.info("Created session %s", session.id)
        return session

    async def _cleanup_old_sessions(self) -> None:
        """Remove old sessions if over limit."""
        if len(self._sessions) <= self.max_sessions:
            return

        sorted_sessions = sorted(
            self._sessions.values(),
            key=lambda s: s.created_at,
        )

        for session in sorted_sessions:
            if len(self._sessions) <= self.max_sessions:
                break

            if (
                not session.is_active
                and self._current_session
                and session.id != self._current_session.id
            ):
                await self.delete_session(session.id)

    async def delete_session(self, session_id: str) -> bool:
        """Delete a session."""
        if session_id not in self._sessions:
            return False

        try:
            file_path = self.session_dir / f"session_{session_id}.json"
            if file_path.exists():
                file_path.unlink()

            del self._sessions[session_id]

            logger.info("Deleted session %s", session_id)
            return True

        except Exception as e:
            logger.error("Failed to delete session: %s", e)
            return False

    async def resume_session(self, session_id: str) -> Optional[Session]:
        """Resume a paused session."""
        session = self._sessions.get(session_id)
        if not session:
            return None

        if session.state not in (SessionState.PAUSED, SessionState.NEW):
            logger.warning(
                "Cannot resume session in state %s", session.state
            )
            return None

        session.state = SessionState.RUNNING
        session.add_event("resumed", "Session resumed")
        self._current_session = session

        logger.info("Resumed session %s", session_id)
        return session

    async def pause_session(self) -> None:
        """Pause the current session."""
        if self._current_session:
            self._current_session.state = SessionState.PAUSED
            self._current_session.add_event("paused", "Session paused")
            await self.save_session(self._current_session)
            logger.info("Paused session %s", self._current_session.id)

    async def end_session(self, aborted: bool = False) -> None:
        """End the current session."""
        if self._current_session:
            self._current_session.state = (
                SessionState.ABORTED if aborted else SessionState.COMPLETED
            )
            self._current_session.ended_at = datetime.now()
            self._current_session.add_event(
                "ended",
                "Session aborted" if aborted else "Session completed",
            )
            await self.save_session(self._current_session)

            logger.info(
                "Ended session %s (%s)",
                self._current_session.id,
                "aborted" if aborted else "completed",
            )

    def get_session(self, session_id: str) -> Optional[Session]:
        """Get a session by ID."""
        return self._sessions.get(session_id)

    @property
    def current_session(self) -> Optional[Session]:
        """Get current active session."""
        return self._current_session

    @property
    def sessions(self) -> List[Session]:
        """Get all sessions."""
        return list(self._sessions.values())

    @property
    def active_sessions(self) -> List[Session]:
        """Get active sessions."""
        return [s for s in self._sessions.values() if s.is_active]

    def get_recent_sessions(self, count: int = 5) -> List[Session]:
        """Get most recent sessions."""
        sorted_sessions = sorted(
            self._sessions.values(),
            key=lambda s: s.created_at,
            reverse=True,
        )
        return sorted_sessions[:count]
