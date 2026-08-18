"""
SQLite Database Layer
─────────────────────
WAL mode, batched commits, indexed tables for APs, clients, deauth events,
EAPOL handshake frames, and harvested credentials.

Supports context manager protocol for safe usage:
    with POSDatabase() as db:
        db.update_ap(...)
    # Automatically flushed and closed
"""

import json
import os
import re
import sqlite3
import time
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from .config import DB_NAME, COMMIT_INTERVAL, log
from .intel import is_pos_ssid

# MAC address validation pattern
_MAC_RE = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')


class POSDatabase:
    # Write batching: buffer writes and flush every COMMIT_INTERVAL seconds
    # or when buffer exceeds BATCH_FLUSH_SIZE items
    BATCH_FLUSH_SIZE = 50

    def __init__(self, db_path=None):
        self._db_path = db_path or DB_NAME
        try:
            self.conn = sqlite3.connect(self._db_path, check_same_thread=False)
        except sqlite3.Error as e:
            log.error(f"Database connection failed ({self._db_path}): {e}")
            raise
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA cache_size=-8000")
        self.conn.execute("PRAGMA temp_store=MEMORY")
        self.cursor = self.conn.cursor()
        self._lock = threading.Lock()
        self._closed = False
        self._setup_tables()
        self._last_commit = time.monotonic()
        self._write_buffer = []

    # ─── Context Manager Protocol ─────────────────────────────────────────────

    def __enter__(self):
        """Support `with POSDatabase() as db:` usage pattern."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Flush and close on context exit."""
        self.close()
        return False  # Don't suppress exceptions

    def __del__(self):
        """Fallback: flush and close on garbage collection if not already closed."""
        if not self._closed:
            try:
                self.close()
            except Exception:
                pass

    # ─── Query Helpers ─────────────────────────────────────────────────────────

    def _query_as_dicts(self, sql: str, params: tuple = ()) -> List[Dict[str, Any]]:
        """Execute a SELECT query and return results as a list of dicts.

        Eliminates repeated boilerplate of:
            columns = [desc[0] for desc in self.cursor.description]
            return [dict(zip(columns, row)) for row in self.cursor.fetchall()]

        Args:
            sql: SQL SELECT query string.
            params: Optional query parameters tuple.

        Returns:
            List of dictionaries, one per row, with column names as keys.
        """
        with self._lock:
            self.cursor.execute(sql, params)
            columns = [desc[0] for desc in self.cursor.description]
            return [dict(zip(columns, row)) for row in self.cursor.fetchall()]

    def _setup_tables(self):
        with self._lock:
            self.cursor.execute('''CREATE TABLE IF NOT EXISTS access_points (
                bssid TEXT PRIMARY KEY, ssid TEXT, vendor TEXT,
                channel INTEGER, security TEXT, rssi INTEGER,
                first_seen TEXT, last_seen TEXT, beacon_count INTEGER DEFAULT 1,
                is_pos_vendor INTEGER DEFAULT 0, is_pos_ssid INTEGER DEFAULT 0,
                is_hidden INTEGER DEFAULT 0)''')
            self.cursor.execute('''CREATE TABLE IF NOT EXISTS clients (
                mac TEXT PRIMARY KEY, vendor TEXT, associated_bssid TEXT,
                probed_ssids TEXT, rssi INTEGER, first_seen TEXT,
                last_seen TEXT, frame_count INTEGER DEFAULT 1,
                is_pos_vendor INTEGER DEFAULT 0)''')
            self.cursor.execute('''CREATE TABLE IF NOT EXISTS deauth_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, src_mac TEXT,
                dst_mac TEXT, bssid TEXT, reason INTEGER, timestamp TEXT)''')
            self.cursor.execute('''CREATE TABLE IF NOT EXISTS eapol_frames (
                id INTEGER PRIMARY KEY AUTOINCREMENT, client_mac TEXT,
                bssid TEXT, frame_number INTEGER, timestamp TEXT)''')
            self.cursor.execute('''CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT, client_ip TEXT,
                client_mac TEXT, username TEXT, password TEXT,
                url TEXT, timestamp TEXT)''')
            self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_clients_bssid ON clients(associated_bssid)')
            self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_deauth_bssid ON deauth_events(bssid)')
            self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_eapol_bssid ON eapol_frames(bssid)')
            self.conn.commit()
        self._setup_printer_tables()
        self._setup_enrichment_tables()
        self._setup_vlan_tables()

    def _setup_printer_tables(self):
        """Create printer-related tables."""
        with self._lock:
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS printers (
                    ip TEXT PRIMARY KEY,
                    model TEXT,
                    manufacturer TEXT,
                    hostname TEXT,
                    serial TEXT,
                    firmware_version TEXT,
                    discovery_time REAL,
                    ssid TEXT,
                    associated_bssid TEXT,
                    default_creds INTEGER DEFAULT 0,
                    vulnerabilities TEXT
                )
            ''')
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS print_jobs (
                    job_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    printer_ip TEXT,
                    timestamp REAL,
                    source_ip TEXT,
                    document_name TEXT,
                    document_type TEXT,
                    page_count INTEGER,
                    file_size INTEGER,
                    extracted_content BLOB
                )
            ''')
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS printer_credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    printer_ip TEXT,
                    username TEXT,
                    password TEXT,
                    auth_method TEXT,
                    found_via TEXT,
                    timestamp REAL
                )
            ''')
            self.conn.commit()

    def _setup_enrichment_tables(self):
        """Create tables for credential enrichment, client profiles, and correlations."""
        with self._lock:
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS enriched_credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    password TEXT,
                    source_url TEXT,
                    target_service TEXT,
                    timestamp TEXT,
                    client_mac TEXT,
                    client_hostname TEXT,
                    confidence_score REAL DEFAULT 0.5,
                    capture_method TEXT,
                    associated_bssid TEXT
                )
            ''')
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS client_profiles (
                    mac TEXT PRIMARY KEY,
                    os_fingerprint TEXT,
                    device_type TEXT DEFAULT 'unknown',
                    probed_networks TEXT,
                    first_seen REAL,
                    last_seen REAL
                )
            ''')
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS credential_correlations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    identity_id INTEGER,
                    credential_id INTEGER,
                    correlation_score REAL
                )
            ''')
            self.cursor.execute(
                'CREATE INDEX IF NOT EXISTS idx_enriched_mac ON enriched_credentials(client_mac)')
            self.cursor.execute(
                'CREATE INDEX IF NOT EXISTS idx_correlations_identity ON credential_correlations(identity_id)')
            self.conn.commit()

    def _setup_vlan_tables(self):
        """Create VLAN, network segment, and topology tables."""
        with self._lock:
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS vlans (
                    vlan_id INTEGER PRIMARY KEY,
                    name TEXT,
                    ip_range TEXT,
                    gateway TEXT,
                    native INTEGER DEFAULT 0,
                    discovery_method TEXT,
                    switch_name TEXT,
                    switch_port TEXT,
                    first_seen TEXT,
                    last_seen TEXT
                )
            ''')
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS network_segments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    vlan_id INTEGER,
                    ip_range TEXT,
                    hosts_discovered INTEGER,
                    services TEXT,
                    acl_gaps TEXT,
                    segment_type TEXT,
                    first_seen TEXT
                )
            ''')
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS vlan_topology (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    src_vlan INTEGER,
                    dst_vlan INTEGER,
                    route_type TEXT,
                    gateway_ip TEXT,
                    bidirectional INTEGER DEFAULT 0,
                    discovered_at TEXT
                )
            ''')
            self.cursor.execute(
                'CREATE INDEX IF NOT EXISTS idx_segments_vlan ON network_segments(vlan_id)')
            self.cursor.execute(
                'CREATE INDEX IF NOT EXISTS idx_topology_src ON vlan_topology(src_vlan)')
            self.conn.commit()

    def _maybe_commit(self):
        """Flush buffered writes when interval elapsed or buffer is full.

        Uses a single lock (_lock) to guard both buffer access and
        commit timing, preventing the deadlock that occurred when
        _buffer_lock and _lock were acquired in different orders.
        """
        now = time.monotonic()
        with self._lock:
            elapsed = now - self._last_commit >= COMMIT_INTERVAL
            if elapsed or len(self._write_buffer) >= self.BATCH_FLUSH_SIZE:
                self._flush_buffer_locked()
                self.conn.commit()
                self._last_commit = now

    def _buffer_write(self, sql, params):
        """Add a write operation to the buffer and flush if needed."""
        with self._lock:
            self._write_buffer.append((sql, params))
            if len(self._write_buffer) >= self.BATCH_FLUSH_SIZE:
                self._flush_buffer_locked()
                self.conn.commit()
                self._last_commit = time.monotonic()

    def _flush_buffer_locked(self):
        """Execute all buffered write operations. Caller must hold _lock."""
        if not self._write_buffer:
            return
        for sql, params in self._write_buffer:
            try:
                self.cursor.execute(sql, params)
            except sqlite3.Error as e:
                log.debug(f"Buffered write error: {e}")
        self._write_buffer.clear()

    def _flush_buffer(self):
        """Execute all buffered write operations (acquires _lock)."""
        with self._lock:
            self._flush_buffer_locked()

    def update_ap(self, bssid, ssid, vendor, channel, security, rssi, is_pos, is_hidden):
        now = datetime.now().isoformat(timespec='seconds')
        pos_ssid = 1 if is_pos_ssid(ssid) else 0
        with self._lock:
            self.cursor.execute('''
                INSERT INTO access_points
                    (bssid, ssid, vendor, channel, security, rssi, first_seen, last_seen,
                     beacon_count, is_pos_vendor, is_pos_ssid, is_hidden)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
                ON CONFLICT(bssid) DO UPDATE SET
                    ssid = CASE WHEN excluded.ssid != '' THEN excluded.ssid ELSE access_points.ssid END,
                    vendor = COALESCE(excluded.vendor, access_points.vendor),
                    rssi = excluded.rssi,
                    channel = COALESCE(excluded.channel, access_points.channel),
                    security = COALESCE(excluded.security, access_points.security),
                    last_seen = excluded.last_seen,
                    beacon_count = access_points.beacon_count + 1,
                    is_hidden = CASE WHEN excluded.ssid != '' THEN 0 ELSE access_points.is_hidden END,
                    is_pos_ssid = MAX(access_points.is_pos_ssid, excluded.is_pos_ssid)
            ''', (bssid, ssid, vendor, channel, security, rssi, now, now,
                  1 if is_pos else 0, pos_ssid, 1 if is_hidden else 0))
        self._maybe_commit()

    def update_client(self, mac, vendor, rssi, is_pos, associated_bssid=None, probed_ssid=None):
        now = datetime.now().isoformat(timespec='seconds')
        with self._lock:
            self.cursor.execute('''
                INSERT INTO clients
                    (mac, vendor, rssi, associated_bssid, probed_ssids, first_seen, last_seen,
                     frame_count, is_pos_vendor)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
                ON CONFLICT(mac) DO UPDATE SET
                    rssi = excluded.rssi, last_seen = excluded.last_seen,
                    frame_count = clients.frame_count + 1,
                    associated_bssid = COALESCE(excluded.associated_bssid, clients.associated_bssid),
                    probed_ssids = CASE
                        WHEN excluded.probed_ssids IS NOT NULL AND excluded.probed_ssids != ''
                             AND INSTR(COALESCE(clients.probed_ssids, ''), excluded.probed_ssids) = 0
                        THEN CASE WHEN clients.probed_ssids IS NULL OR clients.probed_ssids = ''
                            THEN excluded.probed_ssids
                            ELSE clients.probed_ssids || ',' || excluded.probed_ssids END
                        ELSE clients.probed_ssids END
            ''', (mac, vendor, rssi, associated_bssid, probed_ssid, now, now, 1 if is_pos else 0))
        self._maybe_commit()

    def log_deauth(self, src_mac, dst_mac, bssid, reason):
        now = datetime.now().isoformat(timespec='seconds')
        with self._lock:
            self.cursor.execute(
                'INSERT INTO deauth_events (src_mac, dst_mac, bssid, reason, timestamp) VALUES (?,?,?,?,?)',
                (src_mac, dst_mac, bssid, reason, now))
        self._maybe_commit()

    def log_eapol(self, client_mac, bssid, frame_number):
        now = datetime.now().isoformat(timespec='seconds')
        with self._lock:
            self.cursor.execute(
                'INSERT INTO eapol_frames (client_mac, bssid, frame_number, timestamp) VALUES (?,?,?,?)',
                (client_mac, bssid, frame_number, now))
        self._maybe_commit()

    def log_credential(self, client_ip, client_mac, username, password, url):
        now = datetime.now().isoformat(timespec='seconds')
        with self._lock:
            self.cursor.execute(
                'INSERT INTO credentials (client_ip, client_mac, username, password, url, timestamp) VALUES (?,?,?,?,?,?)',
                (client_ip, client_mac or "", username, password, url, now))
            self.conn.commit()
        log.critical(f"CREDENTIAL CAPTURED: user='{username}' from {client_ip}")
        log.debug("  Password: ****")  # Fixed-length mask to avoid leaking password length

    # ─── Printer helper methods ─────────────────────────────────────────────────

    def log_printer(self, ip, model, manufacturer, hostname, serial, firmware, ssid, bssid, default_creds, vulns):
        """Insert or update a discovered printer."""
        with self._lock:
            self.cursor.execute('''
                INSERT INTO printers
                    (ip, model, manufacturer, hostname, serial, firmware_version,
                     discovery_time, ssid, associated_bssid, default_creds, vulnerabilities)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    model = COALESCE(excluded.model, printers.model),
                    manufacturer = COALESCE(excluded.manufacturer, printers.manufacturer),
                    hostname = COALESCE(excluded.hostname, printers.hostname),
                    serial = COALESCE(excluded.serial, printers.serial),
                    firmware_version = COALESCE(excluded.firmware_version, printers.firmware_version),
                    ssid = COALESCE(excluded.ssid, printers.ssid),
                    associated_bssid = COALESCE(excluded.associated_bssid, printers.associated_bssid),
                    default_creds = excluded.default_creds,
                    vulnerabilities = COALESCE(excluded.vulnerabilities, printers.vulnerabilities)
            ''', (ip, model, manufacturer, hostname, serial, firmware,
                  time.time(), ssid, bssid, 1 if default_creds else 0, vulns))
        self._maybe_commit()

    def log_print_job(self, printer_ip, source_ip, doc_name, doc_type, page_count, file_size, content):
        """Log an intercepted print job."""
        with self._lock:
            self.cursor.execute('''
                INSERT INTO print_jobs
                    (printer_ip, timestamp, source_ip, document_name, document_type,
                     page_count, file_size, extracted_content)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (printer_ip, time.time(), source_ip, doc_name, doc_type,
                  page_count, file_size, content))
        self._maybe_commit()
        log.info(f"Print job logged: {doc_type} from {source_ip} to {printer_ip}")

    def log_printer_credential(self, printer_ip, username, password, auth_method, found_via):
        """Log a captured printer credential."""
        with self._lock:
            self.cursor.execute('''
                INSERT INTO printer_credentials
                    (printer_ip, username, password, auth_method, found_via, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (printer_ip, username, password, auth_method, found_via, time.time()))
            self.conn.commit()
        log.critical(f"PRINTER CRED CAPTURED: {auth_method} {username}@{printer_ip}")

    def get_printers(self):
        """Return all discovered printers."""
        return self._query_as_dicts('SELECT * FROM printers ORDER BY discovery_time DESC')

    def get_print_jobs(self, printer_ip=None):
        """Return intercepted print jobs, optionally filtered by printer IP."""
        if printer_ip:
            return self._query_as_dicts(
                'SELECT * FROM print_jobs WHERE printer_ip = ? ORDER BY timestamp DESC',
                (printer_ip,))
        return self._query_as_dicts('SELECT * FROM print_jobs ORDER BY timestamp DESC')

    # ─── Enrichment and profiling helper methods ────────────────────────────────

    def store_enriched_credential(self, username, password, source_url,
                                  target_service, timestamp, client_mac,
                                  client_hostname, confidence_score,
                                  capture_method, associated_bssid):
        """Store an enriched credential record."""
        with self._lock:
            self.cursor.execute('''
                INSERT INTO enriched_credentials
                    (username, password, source_url, target_service, timestamp,
                     client_mac, client_hostname, confidence_score,
                     capture_method, associated_bssid)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (username, password, source_url, target_service, timestamp,
                  client_mac, client_hostname, confidence_score,
                  capture_method, associated_bssid))
        self._maybe_commit()

    def get_enriched_credentials(self, client_mac=None):
        """Return enriched credentials, optionally filtered by client MAC."""
        if client_mac:
            return self._query_as_dicts(
                'SELECT * FROM enriched_credentials WHERE client_mac = ? ORDER BY timestamp DESC',
                (client_mac,))
        return self._query_as_dicts('SELECT * FROM enriched_credentials ORDER BY timestamp DESC')

    def store_client_profile(self, mac, os_fingerprint, device_type,
                             probed_networks, first_seen, last_seen):
        """Insert or update a client profile."""
        with self._lock:
            self.cursor.execute('''
                INSERT INTO client_profiles
                    (mac, os_fingerprint, device_type, probed_networks, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(mac) DO UPDATE SET
                    os_fingerprint = COALESCE(excluded.os_fingerprint, client_profiles.os_fingerprint),
                    device_type = excluded.device_type,
                    probed_networks = excluded.probed_networks,
                    last_seen = excluded.last_seen
            ''', (mac, os_fingerprint, device_type, probed_networks, first_seen, last_seen))
        self._maybe_commit()

    def get_client_profiles(self):
        """Return all client profiles."""
        return self._query_as_dicts('SELECT * FROM client_profiles ORDER BY last_seen DESC')

    def store_credential_correlation(self, identity_id, credential_id, correlation_score):
        """Store a credential correlation link."""
        with self._lock:
            self.cursor.execute('''
                INSERT INTO credential_correlations
                    (identity_id, credential_id, correlation_score)
                VALUES (?, ?, ?)
            ''', (identity_id, credential_id, correlation_score))
        self._maybe_commit()

    def get_credential_correlations(self, identity_id=None):
        """Return credential correlations, optionally filtered by identity."""
        if identity_id:
            return self._query_as_dicts(
                'SELECT * FROM credential_correlations WHERE identity_id = ?',
                (identity_id,))
        return self._query_as_dicts('SELECT * FROM credential_correlations')

    # ─── VLAN and network segmentation helper methods ─────────────────────────

    def log_vlan(self, vlan_id, name, ip_range, gateway, native=0,
                 discovery_method=None, switch_name=None, switch_port=None):
        """Insert or update a discovered VLAN."""
        now = datetime.now().isoformat(timespec='seconds')
        with self._lock:
            self.cursor.execute('''
                INSERT INTO vlans
                    (vlan_id, name, ip_range, gateway, native, discovery_method,
                     switch_name, switch_port, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(vlan_id) DO UPDATE SET
                    name = COALESCE(excluded.name, vlans.name),
                    ip_range = COALESCE(excluded.ip_range, vlans.ip_range),
                    gateway = COALESCE(excluded.gateway, vlans.gateway),
                    native = excluded.native,
                    discovery_method = COALESCE(excluded.discovery_method, vlans.discovery_method),
                    switch_name = COALESCE(excluded.switch_name, vlans.switch_name),
                    switch_port = COALESCE(excluded.switch_port, vlans.switch_port),
                    last_seen = excluded.last_seen
            ''', (vlan_id, name, ip_range, gateway, native, discovery_method,
                  switch_name, switch_port, now, now))
        self._maybe_commit()

    def log_segment(self, vlan_id, ip_range, hosts_discovered, services,
                    acl_gaps, segment_type):
        """Insert a network segment record."""
        now = datetime.now().isoformat(timespec='seconds')
        with self._lock:
            self.cursor.execute('''
                INSERT INTO network_segments
                    (vlan_id, ip_range, hosts_discovered, services, acl_gaps,
                     segment_type, first_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (vlan_id, ip_range, hosts_discovered, services, acl_gaps,
                  segment_type, now))
        self._maybe_commit()

    def log_vlan_route(self, src_vlan, dst_vlan, route_type, gateway_ip,
                       bidirectional=0):
        """Insert a VLAN topology route record."""
        now = datetime.now().isoformat(timespec='seconds')
        with self._lock:
            self.cursor.execute('''
                INSERT INTO vlan_topology
                    (src_vlan, dst_vlan, route_type, gateway_ip, bidirectional,
                     discovered_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (src_vlan, dst_vlan, route_type, gateway_ip, bidirectional, now))
        self._maybe_commit()

    def get_vlans(self):
        """Return all discovered VLANs."""
        return self._query_as_dicts('SELECT * FROM vlans ORDER BY vlan_id')

    def get_segments(self):
        """Return all network segments."""
        return self._query_as_dicts('SELECT * FROM network_segments ORDER BY vlan_id')

    # ─── Query methods (used by orchestrator for auto-targeting) ──────────────

    def get_clients_for_bssid(self, bssid):
        """Return all client MACs and their RSSI values associated with a given BSSID."""
        with self._lock:
            self.cursor.execute('SELECT mac, rssi FROM clients WHERE associated_bssid = ?', (bssid,))
            return [(row[0], row[1]) for row in self.cursor.fetchall()]

    def get_pos_access_points(self):
        """Return all POS-flagged APs with their SSID, channel, and BSSID."""
        with self._lock:
            self.cursor.execute(
                'SELECT bssid, ssid, channel, vendor, security, rssi FROM access_points '
                'WHERE is_pos_vendor = 1 OR is_pos_ssid = 1 ORDER BY rssi DESC')
            return self.cursor.fetchall()

    def get_strongest_ap(self):
        """Return the AP with strongest signal (best attack target)."""
        with self._lock:
            self.cursor.execute(
                'SELECT bssid, ssid, channel, vendor, rssi FROM access_points '
                'ORDER BY rssi DESC LIMIT 1')
            return self.cursor.fetchone()

    def get_strongest_pos_ap(self):
        """Return strongest POS AP (priority target for auto-attack)."""
        with self._lock:
            self.cursor.execute(
                'SELECT bssid, ssid, channel, vendor, rssi FROM access_points '
                'WHERE is_pos_vendor = 1 OR is_pos_ssid = 1 ORDER BY rssi DESC LIMIT 1')
            return self.cursor.fetchone()

    def get_all_ap_clients(self):
        """Return dict mapping BSSID -> list of client MACs."""
        with self._lock:
            self.cursor.execute('SELECT mac, associated_bssid FROM clients WHERE associated_bssid IS NOT NULL')
            result = {}
            for mac, bssid in self.cursor.fetchall():
                result.setdefault(bssid, []).append(mac)
            return result

    def get_ap_by_bssid(self, bssid):
        """Return AP row (bssid, ssid, channel, vendor, rssi) for a given BSSID."""
        with self._lock:
            self.cursor.execute(
                'SELECT bssid, ssid, channel, vendor, rssi FROM access_points WHERE bssid = ?',
                (bssid,))
            return self.cursor.fetchone()

    def get_probed_ssids(self):
        """Return a deduplicated list of all SSIDs probed by discovered clients."""
        with self._lock:
            self.cursor.execute(
                'SELECT probed_ssids FROM clients WHERE probed_ssids IS NOT NULL AND probed_ssids != ""')
            ssids = set()
            for (probed_csv,) in self.cursor.fetchall():
                for ssid in probed_csv.split(","):
                    ssid = ssid.strip()
                    if ssid:
                        ssids.add(ssid)
            return list(ssids)

    def get_stats(self) -> Dict[str, int]:
        """Return counts of all major record types in a single query batch.

        Returns:
            Dictionary with keys: access_points, pos_access_points, clients,
            pos_clients, deauth_events, eapol_frames, credentials.
        """
        with self._lock:
            self.cursor.execute('''
                SELECT
                    (SELECT COUNT(*) FROM access_points) AS access_points,
                    (SELECT COUNT(*) FROM access_points WHERE is_pos_vendor=1 OR is_pos_ssid=1) AS pos_access_points,
                    (SELECT COUNT(*) FROM clients) AS clients,
                    (SELECT COUNT(*) FROM clients WHERE is_pos_vendor=1) AS pos_clients,
                    (SELECT COUNT(*) FROM deauth_events) AS deauth_events,
                    (SELECT COUNT(*) FROM eapol_frames) AS eapol_frames,
                    (SELECT COUNT(*) FROM credentials) AS credentials
            ''')
            row = self.cursor.fetchone()
            return {
                "access_points": row[0],
                "pos_access_points": row[1],
                "clients": row[2],
                "pos_clients": row[3],
                "deauth_events": row[4],
                "eapol_frames": row[5],
                "credentials": row[6],
            }

    def export_all(self, output_path: str = "exports/database_export.json") -> str:
        """Export all database tables to a JSON file.

        Args:
            output_path: Path for the output JSON file.

        Returns:
            The output file path.
        """
        data = {
            "exported_at": datetime.now().isoformat(timespec='seconds'),
            "stats": self.get_stats(),
            "access_points": self._query_as_dicts('SELECT * FROM access_points ORDER BY rssi DESC'),
            "clients": self._query_as_dicts('SELECT * FROM clients ORDER BY last_seen DESC'),
            "credentials": self._query_as_dicts('SELECT * FROM credentials ORDER BY timestamp DESC'),
            "printers": self._query_as_dicts('SELECT * FROM printers ORDER BY discovery_time DESC'),
            "vlans": self._query_as_dicts('SELECT * FROM vlans ORDER BY vlan_id'),
            "enriched_credentials": self._query_as_dicts('SELECT * FROM enriched_credentials'),
        }

        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2, default=str)
        log.info(f"Database exported to {output_path}")
        return output_path

    def vacuum(self):
        """Compact the database and reclaim unused space.

        Should be called after large deletions or at end of session.
        WAL checkpoint is performed first to merge WAL into main DB.
        """
        self._flush_buffer()
        with self._lock:
            self.conn.commit()
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self.conn.execute("VACUUM")
        log.info("Database vacuumed and compacted")

    def flush(self):
        """Flush all buffered writes and commit to disk."""
        self._flush_buffer()
        with self._lock:
            self.conn.commit()

    def close(self):
        """Flush, commit, and close the database connection."""
        if self._closed:
            return
        self._flush_buffer()
        with self._lock:
            try:
                self.conn.commit()
                self.conn.close()
            except sqlite3.Error as e:
                log.warning(f"Database close error: {e}")
            finally:
                self._closed = True


# Alias for backward compatibility
Database = POSDatabase
