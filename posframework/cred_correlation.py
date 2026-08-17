"""
Credential Correlation Engine
------------------------------
Links credentials across protocols to identify same-identity usage:
  - Match by username (exact and normalized)
  - Match by password hash or plaintext
  - Match by source IP
  - Match by timing proximity

Groups credentials into identity objects representing a single user
across multiple services, with confidence scoring.
"""

import time
import hashlib
import threading
from collections import defaultdict

from .config import log


class CredentialCorrelationEngine:
    """
    Correlate credentials across protocols to identify single identities.

    Receives credentials from multiple capture sources and groups them
    into identities based on username, password, IP, and timing similarity.
    """

    def __init__(self, time_window=300, min_confidence=0.3):
        self._credentials = []
        self._identities = []
        self._lock = threading.Lock()

        # Correlation parameters
        self.time_window = time_window  # seconds for timing correlation
        self.min_confidence = min_confidence  # minimum score to link

        # Indexes for fast lookup
        self._by_username = defaultdict(list)
        self._by_password_hash = defaultdict(list)
        self._by_source_ip = defaultdict(list)
        self._next_identity_id = 1
        self._correlated = False

    def add_credential(self, cred_dict):
        """
        Add a credential to the correlation pool.

        Args:
            cred_dict: Dictionary with keys:
                - username (str): Login username/email
                - password (str): Plaintext password or hash
                - protocol (str): Capture protocol (http, smtp, imap, etc.)
                - source_ip (str): Client IP address
                - timestamp (float): Capture time (epoch)
                - host (str): Target host/service
                - Additional metadata fields
        """
        with self._lock:
            # Assign internal ID
            cred_dict = dict(cred_dict)
            cred_dict["_id"] = len(self._credentials)
            cred_dict.setdefault("timestamp", time.time())

            self._credentials.append(cred_dict)

            # Update indexes
            username = cred_dict.get("username", "").lower().strip()
            if username:
                self._by_username[username].append(cred_dict["_id"])

            # Hash password for comparison (avoid storing plaintext index)
            password = cred_dict.get("password", "")
            if password:
                pw_hash = hashlib.sha256(password.encode()).hexdigest()[:16]
                self._by_password_hash[pw_hash].append(cred_dict["_id"])

            source_ip = cred_dict.get("source_ip", "")
            if source_ip:
                self._by_source_ip[source_ip].append(cred_dict["_id"])

            self._correlated = False  # Mark as needing re-correlation

    def correlate(self):
        """
        Run correlation algorithm to group credentials into identities.

        Uses a union-find approach to merge credentials that share
        common attributes above the confidence threshold.

        Returns:
            List of identity objects
        """
        with self._lock:
            if not self._credentials:
                return []

            n = len(self._credentials)
            # Union-Find
            parent = list(range(n))

            def find(x):
                while parent[x] != x:
                    parent[x] = parent[parent[x]]
                    x = parent[x]
                return x

            def union(x, y):
                px, py = find(x), find(y)
                if px != py:
                    parent[px] = py

            # Correlate by username
            for username, ids in self._by_username.items():
                if len(ids) > 1:
                    for i in range(1, len(ids)):
                        score = self._compute_username_score(
                            self._credentials[ids[0]],
                            self._credentials[ids[i]]
                        )
                        if score >= self.min_confidence:
                            union(ids[0], ids[i])

            # Correlate by password hash
            for pw_hash, ids in self._by_password_hash.items():
                if len(ids) > 1:
                    for i in range(1, len(ids)):
                        score = self._compute_password_score(
                            self._credentials[ids[0]],
                            self._credentials[ids[i]]
                        )
                        if score >= self.min_confidence:
                            union(ids[0], ids[i])

            # Correlate by source IP + timing
            for source_ip, ids in self._by_source_ip.items():
                if len(ids) > 1:
                    for i in range(len(ids)):
                        for j in range(i + 1, len(ids)):
                            score = self._compute_timing_score(
                                self._credentials[ids[i]],
                                self._credentials[ids[j]]
                            )
                            if score >= self.min_confidence:
                                union(ids[i], ids[j])

            # Build identity groups
            groups = defaultdict(list)
            for i in range(n):
                groups[find(i)].append(i)

            # Build identity objects
            self._identities = []
            for group_root, member_ids in groups.items():
                if len(member_ids) < 1:
                    continue

                members = [self._credentials[i] for i in member_ids]
                identity = self._build_identity(members)
                self._identities.append(identity)

            self._correlated = True
            log.info(f"Correlation complete: {n} credentials -> "
                     f"{len(self._identities)} identities")

            return list(self._identities)

    def _compute_username_score(self, cred_a, cred_b):
        """Compute correlation score based on username match."""
        username_a = cred_a.get("username", "").lower().strip()
        username_b = cred_b.get("username", "").lower().strip()

        if not username_a or not username_b:
            return 0.0

        # Exact match
        if username_a == username_b:
            # Different protocols boost confidence
            if cred_a.get("protocol") != cred_b.get("protocol"):
                return 0.90
            return 0.80

        # Partial match (e.g., user@domain.com vs user)
        if username_a.split("@")[0] == username_b.split("@")[0]:
            return 0.70

        return 0.0

    def _compute_password_score(self, cred_a, cred_b):
        """Compute correlation score based on password match."""
        pw_a = cred_a.get("password", "")
        pw_b = cred_b.get("password", "")

        if not pw_a or not pw_b:
            return 0.0

        # Exact password match across different services
        if pw_a == pw_b:
            if cred_a.get("protocol") != cred_b.get("protocol"):
                return 0.85
            if cred_a.get("host") != cred_b.get("host"):
                return 0.80
            return 0.60  # Same service, same password (might be same login)

        return 0.0

    def _compute_timing_score(self, cred_a, cred_b):
        """Compute correlation score based on timing proximity from same IP."""
        ts_a = cred_a.get("timestamp", 0)
        ts_b = cred_b.get("timestamp", 0)
        ip_a = cred_a.get("source_ip", "")
        ip_b = cred_b.get("source_ip", "")

        if not ip_a or ip_a != ip_b:
            return 0.0

        time_diff = abs(ts_a - ts_b)
        if time_diff <= 60:  # Within 1 minute
            return 0.50
        elif time_diff <= self.time_window:
            # Linear decay
            score = 0.50 * (1.0 - time_diff / self.time_window)
            return max(score, 0.0)

        return 0.0

    def _build_identity(self, members):
        """Build an identity object from a group of correlated credentials."""
        identity_id = self._next_identity_id
        self._next_identity_id += 1

        # Extract common attributes
        usernames = set()
        passwords = set()
        protocols = set()
        source_ips = set()
        hosts = set()

        for cred in members:
            u = cred.get("username", "")
            if u:
                usernames.add(u)
            p = cred.get("password", "")
            if p:
                passwords.add(p)
            proto = cred.get("protocol", "")
            if proto:
                protocols.add(proto)
            ip = cred.get("source_ip", "")
            if ip:
                source_ips.add(ip)
            h = cred.get("host", "")
            if h:
                hosts.add(h)

        # Compute overall confidence based on number of correlating factors
        confidence = min(1.0, 0.3 + 0.15 * len(members) + 0.1 * len(protocols))

        return {
            "identity_id": identity_id,
            "primary_username": sorted(usernames)[0] if usernames else "",
            "usernames": sorted(usernames),
            "passwords": sorted(passwords),
            "protocols": sorted(protocols),
            "source_ips": sorted(source_ips),
            "target_hosts": sorted(hosts),
            "credential_count": len(members),
            "confidence": round(confidence, 2),
            "credentials": members,
            "first_seen": min(c.get("timestamp", 0) for c in members),
            "last_seen": max(c.get("timestamp", 0) for c in members),
        }

    def get_identities(self):
        """
        Get all correlated identities. Runs correlation if needed.

        Returns:
            List of identity dictionaries
        """
        if not self._correlated:
            self.correlate()
        with self._lock:
            return list(self._identities)

    def get_stats(self):
        """Return correlation engine statistics."""
        with self._lock:
            multi_protocol = sum(
                1 for i in self._identities
                if len(i.get("protocols", [])) > 1
            )
            return {
                "total_credentials": len(self._credentials),
                "total_identities": len(self._identities),
                "multi_protocol_identities": multi_protocol,
                "unique_usernames": len(self._by_username),
                "unique_source_ips": len(self._by_source_ip),
                "correlated": self._correlated,
            }
