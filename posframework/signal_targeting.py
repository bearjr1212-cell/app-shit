"""
Signal Strength Targeting
─────────────────────────
Only target clients within close range (strong RSSI) for deauth attacks.
This increases attack effectiveness - clients near the AP are more likely
to connect to our evil twin.

RSSI threshold: Clients with RSSI > -70 dBm are considered "close range"
"""

from collections import defaultdict

from .config import log


class SignalTargeting:
    """
    Filter deauth targets based on signal strength.
    - Strong signal (-40 to -70 dBm): High priority (close range)
    - Medium signal (-70 to -85 dBm): Medium priority
    - Weak signal (< -85 dBm): Low priority (maybe skip)
    """

    def __init__(self, rssi_threshold=-70):
        self.rssi_threshold = rssi_threshold
        self._client_rssis = defaultdict(list)  # client_mac -> list of RSSI samples
        self._cached_avg = {}  # client_mac -> running average RSSI
        self._priority_queue = []  # Sorted list of (rssi, client_mac, bssid)

    def add_sample(self, client_mac, bssid, rssi):
        """Record an RSSI sample for a client and update running average."""
        samples = self._client_rssis[client_mac]
        n = len(samples) + 1
        if client_mac in self._cached_avg:
            old_avg = self._cached_avg[client_mac]
            self._cached_avg[client_mac] = (old_avg * (n - 1) + rssi) / n
        else:
            self._cached_avg[client_mac] = rssi
        samples.append(rssi)

    def get_avg_rssi(self, client_mac):
        """Get average RSSI for a client (O(1) cached lookup)."""
        return self._cached_avg.get(client_mac, -100)

    def get_priority(self, client_mac):
        """
        Return priority tier for a client:
        1 = HIGH (close range, strong signal)
        2 = MEDIUM (medium range)
        3 = LOW (weak signal, may skip)
        """
        avg = self.get_avg_rssi(client_mac)
        if avg >= self.rssi_threshold:
            return 1
        elif avg >= -85:
            return 2
        else:
            return 3

    def should_deauth(self, client_mac):
        """Return True if client should be targeted for deauth."""
        avg = self.get_avg_rssi(client_mac)
        return avg > self.rssi_threshold

    def should_deauth_with_rssi(self, client_mac, rssi):
        """Return True if client should be targeted using provided RSSI value."""
        return rssi > self.rssi_threshold

    def get_closest_clients(self, bssid, db, limit=10):
        """
        Get the N closest clients for a given AP from the database.
        Returns list of (client_mac, avg_rssi) tuples.
        """
        # Get clients from DB for this BSSID (now returns list of (mac, rssi) tuples)
        clients = db.get_clients_for_bssid(bssid)
        if not clients:
            return []

        # Calculate average RSSI for each
        client_rssis = []
        for item in clients:
            # Handle both tuple (mac, rssi) and plain mac formats
            if isinstance(item, tuple):
                mac, db_rssi = item
            else:
                mac = item
                db_rssi = -100
            avg = self.get_avg_rssi(mac)
            # Use the better of stored avg or DB value
            if avg == -100 and db_rssi is not None:
                avg = db_rssi
            client_rssis.append((mac, avg))

        # Sort by RSSI (strongest first) and limit
        client_rssis.sort(key=lambda x: x[1], reverse=True)
        return client_rssis[:limit]

    def filter_targets(self, targets, rssi_limit=-80):
        """
        Filter a dict of {bssid: set(clients)} to only include
        clients with RSSI above the threshold.
        """
        filtered = {}
        for bssid, clients in targets.items():
            close_clients = set()
            for client in clients:
                avg = self.get_avg_rssi(client)
                if avg > rssi_limit:
                    close_clients.add(client)
            if close_clients:
                filtered[bssid] = close_clients
        return filtered

    def get_stats(self):
        total_clients = len(self._client_rssis)
        high_priority = sum(1 for mac in self._client_rssis if self.get_priority(mac) == 1)
        medium_priority = sum(1 for mac in self._client_rssis if self.get_priority(mac) == 2)
        low_priority = sum(1 for mac in self._client_rssis if self.get_priority(mac) == 3)
        return {
            "total_clients": total_clients,
            "high_priority": high_priority,
            "medium_priority": medium_priority,
            "low_priority": low_priority,
        }
