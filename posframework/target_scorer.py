"""
Target Scorer and Analyzer
───────────────────────────
Two complementary systems for target prioritization:

1. TargetScorer (legacy): Scores targets from DB based on POS vendor match,
   signal, clients, security type, isolation. Used by ReconAttackFlow.

2. TargetAnalyzer (AutoPwn): Async target analysis with priority queue,
   cooldown, attack tracking. Used by AutoPwnEngine for autonomous operations.

Both can coexist - TargetScorer is synchronous/DB-driven while TargetAnalyzer
is async with in-memory state and designed for the state machine loop.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Dict, List, Optional

from .config import log

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# AutoPwn Target Types (from MoMo architecture)
# ═══════════════════════════════════════════════════════════════════════════════


class TargetType(Enum):
    """Types of targets."""

    WIFI_AP = auto()
    WIFI_CLIENT = auto()
    BLE_DEVICE = auto()
    PROBE_REQUEST = auto()


class TargetStatus(Enum):
    """Target processing status."""

    DISCOVERED = auto()
    ANALYZING = auto()
    QUEUED = auto()
    ATTACKING = auto()
    CAPTURED = auto()
    CRACKED = auto()
    FAILED = auto()
    SKIPPED = auto()
    COOLDOWN = auto()


class TargetPriority(Enum):
    """Target priority levels."""

    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    SKIP = 5


@dataclass
class Target:
    """Represents a potential attack target for the AutoPwn engine."""

    # Identity
    id: str
    target_type: TargetType

    # WiFi AP specific
    ssid: Optional[str] = None
    bssid: Optional[str] = None
    channel: Optional[int] = None
    frequency: Optional[int] = None

    # Security
    encryption: Optional[str] = None
    wpa_version: Optional[int] = None
    pmkid_vulnerable: Optional[bool] = None
    downgrade_possible: Optional[bool] = None

    # Signal
    signal_dbm: int = -100
    last_seen: datetime = field(default_factory=datetime.now)

    # Clients (for APs)
    client_count: int = 0
    active_clients: List[str] = field(default_factory=list)

    # Status
    status: TargetStatus = TargetStatus.DISCOVERED
    priority: TargetPriority = TargetPriority.MEDIUM

    # Attack history
    attack_attempts: int = 0
    last_attack: Optional[datetime] = None
    successful_attacks: List[str] = field(default_factory=list)
    failed_attacks: List[str] = field(default_factory=list)

    # Results
    handshake_captured: bool = False
    pmkid_captured: bool = False
    credential_captured: bool = False
    password: Optional[str] = None

    # Metadata
    first_seen: datetime = field(default_factory=datetime.now)
    vendor: Optional[str] = None
    notes: List[str] = field(default_factory=list)

    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Target):
            return self.id == other.id
        return False

    @property
    def is_wpa2(self) -> bool:
        """Check if target uses WPA2."""
        return self.wpa_version == 2 or (
            self.encryption is not None and "WPA2" in self.encryption.upper()
        )

    @property
    def is_wpa3(self) -> bool:
        """Check if target uses WPA3."""
        return self.wpa_version == 3 or (
            self.encryption is not None and "WPA3" in self.encryption.upper()
        )

    @property
    def is_open(self) -> bool:
        """Check if target is open (no encryption)."""
        return self.encryption is None or self.encryption.upper() == "OPEN"

    @property
    def has_active_clients(self) -> bool:
        """Check if AP has active clients."""
        return len(self.active_clients) > 0

    @property
    def is_attackable(self) -> bool:
        """Check if target can be attacked."""
        return self.status not in (
            TargetStatus.CAPTURED,
            TargetStatus.CRACKED,
            TargetStatus.SKIPPED,
            TargetStatus.COOLDOWN,
        )

    def add_note(self, note: str) -> None:
        """Add a note to the target."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.notes.append(f"[{timestamp}] {note}")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "target_type": self.target_type.name,
            "ssid": self.ssid,
            "bssid": self.bssid,
            "channel": self.channel,
            "encryption": self.encryption,
            "signal_dbm": self.signal_dbm,
            "status": self.status.name,
            "priority": self.priority.name,
            "client_count": self.client_count,
            "attack_attempts": self.attack_attempts,
            "handshake_captured": self.handshake_captured,
            "pmkid_captured": self.pmkid_captured,
            "password": self.password,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
        }

    @classmethod
    def from_wifi_scan(cls, scan_result: Dict[str, Any]) -> "Target":
        """Create target from WiFi scan result dict."""
        bssid = scan_result.get("bssid", "")
        clients = scan_result.get("clients", [])
        return cls(
            id=bssid,
            target_type=TargetType.WIFI_AP,
            ssid=scan_result.get("ssid"),
            bssid=bssid,
            channel=scan_result.get("channel"),
            frequency=scan_result.get("frequency"),
            encryption=scan_result.get("encryption"),
            signal_dbm=scan_result.get("signal_dbm", -100),
            vendor=scan_result.get("vendor"),
            active_clients=clients,
            client_count=scan_result.get("client_count", len(clients)),
        )


@dataclass
class TargetAnalyzerConfig:
    """Configuration for target analysis."""

    # Signal thresholds
    min_signal_dbm: int = -80
    strong_signal_dbm: int = -60

    # Targeting preferences
    prefer_wpa2: bool = True
    prefer_with_clients: bool = True
    prefer_pmkid_vulnerable: bool = True

    # Limits
    max_concurrent_targets: int = 3
    cooldown_seconds: int = 300
    max_attack_attempts: int = 3

    # Filtering
    ssid_whitelist: List[str] = field(default_factory=list)
    ssid_blacklist: List[str] = field(default_factory=list)
    bssid_whitelist: List[str] = field(default_factory=list)
    bssid_blacklist: List[str] = field(default_factory=list)


class TargetAnalyzer:
    """
    Analyzes and prioritizes attack targets for the AutoPwn engine.

    Responsibilities:
    - Receive scan results from WiFi/BLE scanners
    - Classify and score targets
    - Maintain target database in memory
    - Provide prioritized target queue
    """

    def __init__(self, config: Optional[TargetAnalyzerConfig] = None) -> None:
        self.config = config or TargetAnalyzerConfig()
        self._targets: Dict[str, Target] = {}
        self._priority_queue: List[Target] = []
        self._lock: Optional[asyncio.Lock] = None  # Lazily created to avoid event loop binding issues

    @property
    def _async_lock(self) -> asyncio.Lock:
        """Lazily create the asyncio.Lock on first access (avoids pre-loop creation issues)."""
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    async def process_scan_results(
        self,
        results: List[Dict[str, Any]],
        target_type: TargetType = TargetType.WIFI_AP,
    ) -> List[Target]:
        """Process scan results and update target database."""
        async with self._async_lock:
            new_targets: List[Target] = []

            for result in results:
                if target_type == TargetType.WIFI_AP:
                    target = Target.from_wifi_scan(result)
                else:
                    continue

                # Check if target should be skipped
                if self._should_skip(target):
                    target.status = TargetStatus.SKIPPED
                    target.priority = TargetPriority.SKIP

                # Update or add target
                if target.id in self._targets:
                    self._update_target(self._targets[target.id], target)
                else:
                    self._analyze_target(target)
                    self._targets[target.id] = target
                    new_targets.append(target)
                    logger.debug(
                        "New target: %s (%s)", target.ssid, target.bssid
                    )

            # Rebuild priority queue
            self._rebuild_queue()

            return new_targets

    def _should_skip(self, target: Target) -> bool:
        """Check if target should be skipped based on filters."""
        if target.signal_dbm < self.config.min_signal_dbm:
            return True

        if self.config.ssid_whitelist:
            if target.ssid not in self.config.ssid_whitelist:
                return True

        if target.ssid in self.config.ssid_blacklist:
            return True

        if self.config.bssid_whitelist:
            if target.bssid not in self.config.bssid_whitelist:
                return True

        if target.bssid in self.config.bssid_blacklist:
            return True

        return False

    def _analyze_target(self, target: Target) -> None:
        """Analyze target and assign priority."""
        score = 50  # Base score

        # Signal strength bonus
        if target.signal_dbm >= self.config.strong_signal_dbm:
            score += 20
        elif target.signal_dbm >= -70:
            score += 10

        # WPA2 vs WPA3
        if target.is_wpa2 and self.config.prefer_wpa2:
            score += 15
        elif target.is_wpa3:
            score -= 10
            if target.downgrade_possible:
                score += 5

        # Open network
        if target.is_open:
            score += 5

        # Active clients
        if target.has_active_clients and self.config.prefer_with_clients:
            score += 20
            score += min(target.client_count * 2, 10)

        # PMKID vulnerability
        if target.pmkid_vulnerable and self.config.prefer_pmkid_vulnerable:
            score += 25

        # Assign priority based on score
        if score >= 80:
            target.priority = TargetPriority.CRITICAL
        elif score >= 60:
            target.priority = TargetPriority.HIGH
        elif score >= 40:
            target.priority = TargetPriority.MEDIUM
        else:
            target.priority = TargetPriority.LOW

        target.add_note(f"Priority score: {score}")

    def _update_target(self, existing: Target, new: Target) -> None:
        """Update existing target with new scan data."""
        existing.signal_dbm = new.signal_dbm
        existing.last_seen = datetime.now()
        existing.channel = new.channel or existing.channel

        if new.active_clients:
            for client in new.active_clients:
                if client not in existing.active_clients:
                    existing.active_clients.append(client)
            existing.client_count = len(existing.active_clients)

    def _rebuild_queue(self) -> None:
        """Rebuild the priority queue."""
        attackable = [
            t for t in self._targets.values()
            if t.is_attackable and t.priority != TargetPriority.SKIP
        ]

        self._priority_queue = sorted(
            attackable,
            key=lambda t: (t.priority.value, -t.signal_dbm),
        )

    async def get_next_targets(self, count: int = 1) -> List[Target]:
        """Get next targets to attack."""
        async with self._async_lock:
            targets: List[Target] = []
            now = datetime.now()

            for target in self._priority_queue:
                if len(targets) >= count:
                    break

                # Check cooldown
                if target.status == TargetStatus.COOLDOWN:
                    if target.last_attack:
                        elapsed = (now - target.last_attack).total_seconds()
                        if elapsed < self.config.cooldown_seconds:
                            continue
                        target.status = TargetStatus.QUEUED

                # Check attack attempts
                if target.attack_attempts >= self.config.max_attack_attempts:
                    target.status = TargetStatus.FAILED
                    continue

                # Skip if already attacking
                if target.status == TargetStatus.ATTACKING:
                    continue

                targets.append(target)

            return targets

    async def mark_attacking(self, target_id: str) -> None:
        """Mark target as currently being attacked."""
        async with self._async_lock:
            if target_id in self._targets:
                target = self._targets[target_id]
                target.status = TargetStatus.ATTACKING
                target.attack_attempts += 1
                target.last_attack = datetime.now()

    async def mark_captured(
        self,
        target_id: str,
        capture_type: str = "handshake",
    ) -> None:
        """Mark target as captured."""
        async with self._async_lock:
            if target_id in self._targets:
                target = self._targets[target_id]
                target.status = TargetStatus.CAPTURED

                if capture_type == "handshake":
                    target.handshake_captured = True
                elif capture_type == "pmkid":
                    target.pmkid_captured = True
                elif capture_type == "credential":
                    target.credential_captured = True

                target.add_note(f"Captured: {capture_type}")
                self._rebuild_queue()

    async def mark_cracked(
        self,
        target_id: str,
        password: str,
    ) -> None:
        """Mark target as cracked."""
        async with self._async_lock:
            if target_id in self._targets:
                target = self._targets[target_id]
                target.status = TargetStatus.CRACKED
                target.password = password
                target.add_note(f"Cracked! Password: {password[:3]}***")
                self._rebuild_queue()

    async def mark_failed(
        self,
        target_id: str,
        attack_type: str,
        reason: str = "",
    ) -> None:
        """Mark attack as failed."""
        async with self._async_lock:
            if target_id in self._targets:
                target = self._targets[target_id]
                target.failed_attacks.append(attack_type)

                if target.attack_attempts >= self.config.max_attack_attempts:
                    target.status = TargetStatus.FAILED
                else:
                    target.status = TargetStatus.COOLDOWN

                target.add_note(f"Attack failed: {attack_type} - {reason}")
                self._rebuild_queue()

    async def add_client(self, ap_bssid: str, client_mac: str) -> None:
        """Add a client to an AP target."""
        async with self._async_lock:
            if ap_bssid in self._targets:
                target = self._targets[ap_bssid]
                if client_mac not in target.active_clients:
                    target.active_clients.append(client_mac)
                    target.client_count = len(target.active_clients)
                    target.add_note(f"New client: {client_mac}")
                    self._analyze_target(target)
                    self._rebuild_queue()

    def get_target(self, target_id: str) -> Optional[Target]:
        """Get target by ID."""
        return self._targets.get(target_id)

    @property
    def targets(self) -> List[Target]:
        """Get all targets."""
        return list(self._targets.values())

    @property
    def stats(self) -> Dict[str, int]:
        """Get target statistics."""
        stats: Dict[str, int] = {
            "total": len(self._targets),
            "discovered": 0,
            "attacking": 0,
            "captured": 0,
            "cracked": 0,
            "failed": 0,
            "skipped": 0,
        }

        for target in self._targets.values():
            if target.status == TargetStatus.DISCOVERED:
                stats["discovered"] += 1
            elif target.status == TargetStatus.ATTACKING:
                stats["attacking"] += 1
            elif target.status == TargetStatus.CAPTURED:
                stats["captured"] += 1
            elif target.status == TargetStatus.CRACKED:
                stats["cracked"] += 1
            elif target.status == TargetStatus.FAILED:
                stats["failed"] += 1
            elif target.status == TargetStatus.SKIPPED:
                stats["skipped"] += 1

        return stats


# ═══════════════════════════════════════════════════════════════════════════════
# Legacy TargetScorer (original POSFramework scoring)
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class ScoredTarget:
    """Represents a scored target with all relevant metadata."""
    bssid: str
    ssid: str
    channel: int
    vendor: str
    security: str
    rssi: int
    score: float
    client_count: int
    is_pos: bool
    clients: List[Dict[str, Any]] = field(default_factory=list)
    recommended_strategy: str = ""

    def __repr__(self):
        pos_tag = " [POS]" if self.is_pos else ""
        return (
            f"ScoredTarget({self.ssid}{pos_tag} "
            f"score={self.score:.1f} "
            f"rssi={self.rssi} "
            f"clients={self.client_count} "
            f"security={self.security})"
        )


class TargetScorer:
    """
    Scores and ranks discovered targets for attack prioritization.

    Scoring criteria:
      - POS vendor match:      +50 points
      - Signal strength:       0 to +30 (scaled from RSSI)
      - Client count:          +5 per client (max +25)
      - Security weakness:     Open +40, WPA-PSK +20, WPA2-PSK +15, WPA-Enterprise +5
      - Isolation penalty:     -20 if isolation detected
      - Client proximity:      +10 if clients have strong RSSI (> -60)
    """

    # Scoring weights
    POS_VENDOR_BONUS = 50
    MAX_SIGNAL_SCORE = 30
    CLIENT_SCORE_PER = 5
    CLIENT_SCORE_MAX = 25
    CLIENT_PROXIMITY_BONUS = 10
    ISOLATION_PENALTY = -20

    # Security type scores (weaker = easier = higher score)
    SECURITY_SCORES = {
        "OPEN": 40,
        "WEP": 35,
        "WPA-PSK": 20,
        "WPA2-PSK": 15,
        "WPA2": 15,
        "WPA": 20,
        "WPA3": 5,
        "WPA2-Enterprise": 5,
        "WPA-Enterprise": 5,
        "ENTERPRISE": 5,
    }

    # Strategy recommendations based on security type
    STRATEGY_MAP = {
        "OPEN": "rogue_ap_mitm",
        "WEP": "wep_crack",
        "WPA-PSK": "handshake_capture",
        "WPA2-PSK": "handshake_capture",
        "WPA2": "handshake_capture",
        "WPA": "handshake_capture",
        "WPA3": "sae_downgrade",
        "WPA2-Enterprise": "karma_credential",
        "WPA-Enterprise": "karma_credential",
        "ENTERPRISE": "karma_credential",
    }

    def __init__(self, db=None, isolation_bssids: Optional[set] = None):
        """
        Initialize the TargetScorer.

        Args:
            db: POSDatabase instance to query for AP/client data.
            isolation_bssids: Set of BSSIDs known to have client isolation enabled.
        """
        self.db = db
        self._isolation_bssids = isolation_bssids or set()

    def set_database(self, db):
        """Set or update the database reference."""
        self.db = db

    def add_isolation_bssid(self, bssid: str):
        """Mark a BSSID as having client isolation detected."""
        self._isolation_bssids.add(bssid.lower())

    def _score_signal(self, rssi: int) -> float:
        """
        Score signal strength. Higher RSSI (closer to 0) = better score.
        Scale: -30 dBm (excellent) -> 30 points, -90 dBm (weak) -> 0 points.
        """
        if rssi is None:
            return 0
        # Clamp RSSI to expected range
        rssi = max(-90, min(-30, rssi))
        # Linear scale from 0 (at -90) to MAX_SIGNAL_SCORE (at -30)
        return self.MAX_SIGNAL_SCORE * (rssi + 90) / 60.0

    def _score_security(self, security: str) -> float:
        """Score based on security type. Weaker security = higher score."""
        if not security:
            return self.SECURITY_SCORES.get("OPEN", 40)

        security_upper = security.upper().strip()
        # Try exact match first
        if security_upper in self.SECURITY_SCORES:
            return self.SECURITY_SCORES[security_upper]

        # Partial matching for compound security strings
        for key, score in self.SECURITY_SCORES.items():
            if key in security_upper:
                return score

        # Default to moderate score for unknown types
        return 10

    def _get_strategy(self, security: str) -> str:
        """Determine recommended attack strategy based on security type."""
        if not security:
            return self.STRATEGY_MAP.get("OPEN", "rogue_ap_mitm")

        security_upper = security.upper().strip()
        if security_upper in self.STRATEGY_MAP:
            return self.STRATEGY_MAP[security_upper]

        for key, strategy in self.STRATEGY_MAP.items():
            if key in security_upper:
                return strategy

        return "generic_attack"

    def score_target(self, bssid: str, ssid: str, channel: int,
                     vendor: str, security: str, rssi: int,
                     is_pos: bool = False,
                     clients: Optional[List[Dict[str, Any]]] = None) -> ScoredTarget:
        """
        Score a single target based on all criteria.

        Args:
            bssid: Target BSSID.
            ssid: Target SSID.
            channel: Operating channel.
            vendor: Vendor string.
            security: Security type string.
            rssi: Signal strength in dBm.
            is_pos: Whether this is a POS target.
            clients: List of dicts with 'mac' and 'rssi' keys.

        Returns:
            ScoredTarget with computed score and metadata.
        """
        score = 0.0
        client_list = clients or []
        client_count = len(client_list)

        # POS vendor bonus
        if is_pos:
            score += self.POS_VENDOR_BONUS

        # Signal strength score
        score += self._score_signal(rssi)

        # Client count score
        client_score = min(client_count * self.CLIENT_SCORE_PER, self.CLIENT_SCORE_MAX)
        score += client_score

        # Security weakness score
        score += self._score_security(security)

        # Isolation penalty
        if bssid.lower() in self._isolation_bssids:
            score += self.ISOLATION_PENALTY

        # Client proximity bonus (if any client has strong signal)
        if client_list:
            strong_clients = [c for c in client_list
                             if c.get("rssi") and c["rssi"] > -60]
            if strong_clients:
                score += self.CLIENT_PROXIMITY_BONUS

        # Determine recommended strategy
        strategy = self._get_strategy(security)
        if is_pos:
            strategy = "pos_full_chain"

        return ScoredTarget(
            bssid=bssid,
            ssid=ssid or "(hidden)",
            channel=channel or 0,
            vendor=vendor or "Unknown",
            security=security or "OPEN",
            rssi=rssi or -100,
            score=score,
            client_count=client_count,
            is_pos=is_pos,
            clients=client_list,
            recommended_strategy=strategy,
        )

    def score_all_targets(self) -> List[ScoredTarget]:
        """
        Query the database and score all discovered access points.

        Returns:
            List of ScoredTarget objects sorted by score (highest first).
        """
        if not self.db:
            log.warning("TargetScorer: No database set, cannot score targets")
            return []

        scored = []

        # Get all APs from database
        try:
            self.db.cursor.execute(
                'SELECT bssid, ssid, channel, vendor, security, rssi, '
                'is_pos_vendor, is_pos_ssid FROM access_points'
            )
            aps = self.db.cursor.fetchall()
        except Exception as e:
            log.error(f"TargetScorer: Failed to query APs: {e}")
            return []

        for ap in aps:
            bssid, ssid, channel, vendor, security, rssi, is_pos_vendor, is_pos_ssid = ap
            is_pos = bool(is_pos_vendor or is_pos_ssid)

            # Get clients for this AP
            client_data = self.db.get_clients_for_bssid(bssid)
            clients = [{"mac": mac, "rssi": client_rssi}
                      for mac, client_rssi in client_data]

            target = self.score_target(
                bssid=bssid,
                ssid=ssid,
                channel=channel,
                vendor=vendor,
                security=security,
                rssi=rssi,
                is_pos=is_pos,
                clients=clients,
            )
            scored.append(target)

        # Sort by score descending
        scored.sort(key=lambda t: t.score, reverse=True)

        if scored:
            log.info(f"TargetScorer: Scored {len(scored)} targets. "
                     f"Top: {scored[0].ssid} (score={scored[0].score:.1f})")

        return scored

    def get_top_targets(self, max_targets: int = 5) -> List[ScoredTarget]:
        """
        Get the top N targets sorted by score.

        Args:
            max_targets: Maximum number of targets to return.

        Returns:
            List of top scored targets.
        """
        all_targets = self.score_all_targets()
        return all_targets[:max_targets]

    def score_single_from_db(self, bssid: str) -> Optional[ScoredTarget]:
        """
        Score a single target by BSSID from the database.

        Args:
            bssid: BSSID to look up and score.

        Returns:
            ScoredTarget or None if not found.
        """
        if not self.db:
            return None

        try:
            self.db.cursor.execute(
                'SELECT bssid, ssid, channel, vendor, security, rssi, '
                'is_pos_vendor, is_pos_ssid FROM access_points WHERE bssid = ?',
                (bssid,)
            )
            row = self.db.cursor.fetchone()
        except Exception as e:
            log.error(f"TargetScorer: Failed to query AP {bssid}: {e}")
            return None

        if not row:
            return None

        bssid, ssid, channel, vendor, security, rssi, is_pos_vendor, is_pos_ssid = row
        is_pos = bool(is_pos_vendor or is_pos_ssid)

        client_data = self.db.get_clients_for_bssid(bssid)
        clients = [{"mac": mac, "rssi": client_rssi}
                  for mac, client_rssi in client_data]

        return self.score_target(
            bssid=bssid,
            ssid=ssid,
            channel=channel,
            vendor=vendor,
            security=security,
            rssi=rssi,
            is_pos=is_pos,
            clients=clients,
        )
