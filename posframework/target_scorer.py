"""
Target Scorer
─────────────
Scores and ranks discovered targets based on multiple criteria:
  - POS vendor match (highest priority)
  - Signal strength (RSSI)
  - Number of associated clients
  - Security type (weaker = higher score)
  - Isolation detected (penalty)
  - Client RSSI proximity

Used by ReconAttackFlow to determine which targets to attack first.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any

from .config import log


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
