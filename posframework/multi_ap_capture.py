"""
Multi-AP Parallel Handshake Capture
────────────────────────────────────
Manage multiple HandshakeSniffer instances concurrently,
targeting multiple access points with priority-based scheduling.

Uses a priority queue (heapq) to manage target ordering,
spawning individual HandshakeSniffer threads per target AP.
"""

import time
import heapq
import threading

from .config import log
from .handshake import HandshakeSniffer


class MultiAPCapture:
    """
    Multi-AP parallel handshake capture manager.

    Manages multiple HandshakeSniffer instances concurrently,
    one per target BSSID. Priority queue determines target order
    when max concurrent captures is limited.

    Usage:
        multi = MultiAPCapture("wlan0mon", max_concurrent=4)
        multi.add_target("AA:BB:CC:DD:EE:FF", priority=1)
        multi.add_target("11:22:33:44:55:66", priority=2)
        multi.start()
        # ... wait for handshakes ...
        multi.stop()
    """

    def __init__(self, interface, output_dir="handshakes", max_concurrent=4,
                 callback=None):
        """
        Initialize Multi-AP capture.

        Args:
            interface: Wireless interface in monitor mode
            output_dir: Directory for PCAP output files
            max_concurrent: Maximum number of concurrent sniffers
            callback: Optional callable(bssid, client_mac, filename)
                      invoked when any AP's handshake completes
        """
        self.interface = interface
        self.output_dir = output_dir
        self.max_concurrent = max_concurrent
        self.callback = callback
        self.running = False
        self._lock = threading.Lock()
        self._priority_queue = []  # heapq of (priority, timestamp, bssid)
        self._targets = {}  # bssid -> {priority, status, sniffer, completed_files}
        self._active_sniffers = {}  # bssid -> HandshakeSniffer
        self._scheduler_thread = None
        self._counter = 0  # tie-breaker for heapq

    def add_target(self, bssid, priority=5):
        """
        Add a target AP to the capture queue.

        Args:
            bssid: Target AP BSSID
            priority: Priority value (lower = higher priority)
        """
        bssid = bssid.lower()
        with self._lock:
            if bssid in self._targets:
                log.warning(f"MultiAPCapture: target {bssid} already exists")
                return

            self._counter += 1
            heapq.heappush(self._priority_queue, (priority, self._counter, bssid))
            self._targets[bssid] = {
                "priority": priority,
                "status": "queued",
                "sniffer": None,
                "completed_files": [],
                "added_at": time.time()
            }
            log.info(f"MultiAPCapture: added target {bssid} (priority={priority})")

        # If already running, try to schedule immediately
        if self.running:
            self._schedule_sniffers()

    def remove_target(self, bssid):
        """
        Remove a target AP from capture.

        Args:
            bssid: Target AP BSSID to remove
        """
        bssid = bssid.lower()
        with self._lock:
            if bssid not in self._targets:
                return

            # Stop active sniffer if running
            if bssid in self._active_sniffers:
                sniffer = self._active_sniffers[bssid]
                sniffer.stop()
                del self._active_sniffers[bssid]

            self._targets[bssid]["status"] = "removed"
            del self._targets[bssid]
            log.info(f"MultiAPCapture: removed target {bssid}")

    def start(self):
        """Start the multi-AP capture scheduler."""
        if self.running:
            log.warning("MultiAPCapture is already running")
            return

        self.running = True
        self._scheduler_thread = threading.Thread(
            target=self._scheduler_loop,
            daemon=True
        )
        self._scheduler_thread.start()
        log.info(f"MultiAPCapture started on {self.interface} "
                 f"(max_concurrent={self.max_concurrent})")

    def _scheduler_loop(self):
        """Background scheduler that manages sniffer lifecycle."""
        while self.running:
            self._schedule_sniffers()
            time.sleep(2.0)

    def _schedule_sniffers(self):
        """Schedule pending targets up to max_concurrent limit."""
        with self._lock:
            active_count = len(self._active_sniffers)
            available_slots = self.max_concurrent - active_count

            if available_slots <= 0:
                return

            # Get next targets from priority queue
            targets_to_start = []
            temp_queue = []

            while self._priority_queue and len(targets_to_start) < available_slots:
                item = heapq.heappop(self._priority_queue)
                priority, counter, bssid = item

                if bssid not in self._targets:
                    continue  # Target was removed

                if self._targets[bssid]["status"] == "queued":
                    targets_to_start.append(bssid)
                elif self._targets[bssid]["status"] in ("active", "completed"):
                    continue  # Already running or done
                else:
                    temp_queue.append(item)

            # Put back items that weren't started
            for item in temp_queue:
                heapq.heappush(self._priority_queue, item)

        # Start sniffers outside of lock
        for bssid in targets_to_start:
            self._start_sniffer(bssid)

    def _start_sniffer(self, bssid):
        """Start a HandshakeSniffer for a specific BSSID."""
        def on_handshake(client_mac, target_bssid, filename):
            self._on_handshake_complete(client_mac, target_bssid, filename)

        sniffer = HandshakeSniffer(
            interface=self.interface,
            target_bssid=bssid,
            output_dir=self.output_dir,
            callback=on_handshake
        )
        sniffer.start()

        with self._lock:
            self._active_sniffers[bssid] = sniffer
            if bssid in self._targets:
                self._targets[bssid]["status"] = "active"
                self._targets[bssid]["sniffer"] = sniffer

        log.info(f"MultiAPCapture: started sniffer for {bssid}")

    def _on_handshake_complete(self, client_mac, bssid, filename):
        """Callback when a handshake is captured for any target."""
        bssid = bssid.lower()
        with self._lock:
            if bssid in self._targets:
                self._targets[bssid]["status"] = "completed"
                self._targets[bssid]["completed_files"].append(filename)

            # Stop the sniffer for this AP
            if bssid in self._active_sniffers:
                self._active_sniffers[bssid].stop()
                del self._active_sniffers[bssid]

        log.critical(f"MultiAPCapture: handshake complete for {bssid} -> {filename}")

        # Invoke user callback
        if self.callback:
            try:
                self.callback(bssid, client_mac, filename)
            except Exception as e:
                log.error(f"MultiAPCapture callback error: {e}")

        # Schedule next targets
        if self.running:
            self._schedule_sniffers()

    def stop(self):
        """Stop all active sniffers and the scheduler."""
        self.running = False

        # Stop all active sniffers
        with self._lock:
            for bssid, sniffer in list(self._active_sniffers.items()):
                sniffer.stop()
                if bssid in self._targets:
                    self._targets[bssid]["status"] = "stopped"
            self._active_sniffers.clear()

        # Wait for scheduler thread
        if self._scheduler_thread:
            self._scheduler_thread.join(timeout=10)
            self._scheduler_thread = None

        log.info("MultiAPCapture stopped")

    def get_target_status(self, bssid):
        """Get status for a specific target."""
        bssid = bssid.lower()
        with self._lock:
            if bssid not in self._targets:
                return None
            target = self._targets[bssid]
            return {
                "bssid": bssid,
                "priority": target["priority"],
                "status": target["status"],
                "completed_files": list(target["completed_files"]),
                "added_at": target["added_at"]
            }

    def get_stats(self):
        """Return overall capture statistics."""
        with self._lock:
            statuses = {}
            for target in self._targets.values():
                status = target["status"]
                statuses[status] = statuses.get(status, 0) + 1

            return {
                "running": self.running,
                "interface": self.interface,
                "total_targets": len(self._targets),
                "active_sniffers": len(self._active_sniffers),
                "max_concurrent": self.max_concurrent,
                "status_breakdown": statuses,
                "completed_files": [
                    f for t in self._targets.values()
                    for f in t["completed_files"]
                ]
            }
