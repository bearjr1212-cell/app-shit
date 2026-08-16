"""
SQLite Database Layer
─────────────────────
WAL mode, batched commits, indexed tables for APs, clients, deauth events,
EAPOL handshake frames, and harvested credentials.
"""

import sqlite3
import time
import threading
from datetime import datetime

from .config import DB_NAME, COMMIT_INTERVAL, log
from .intel import is_pos_ssid


class POSDatabase:
    def __init__(self, db_path=None):
        self.conn = sqlite3.connect(db_path or DB_NAME, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA cache_size=-8000")
        self.conn.execute("PRAGMA temp_store=MEMORY")
        self.cursor = self.conn.cursor()
        self._setup_tables()
        self._last_commit = time.monotonic()
        self._commit_lock = threading.Lock()

    def _setup_tables(self):
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

    def _setup_printer_tables(self):
        """Create printer-related tables."""
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

    def _maybe_commit(self):
        now = time.monotonic()
        with self._commit_lock:
            if now - self._last_commit >= COMMIT_INTERVAL:
                self.conn.commit()
                self._last_commit = now

    def update_ap(self, bssid, ssid, vendor, channel, security, rssi, is_pos, is_hidden):
        now = datetime.now().isoformat(timespec='seconds')
        pos_ssid = 1 if is_pos_ssid(ssid) else 0
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
        self.cursor.execute(
            'INSERT INTO deauth_events (src_mac, dst_mac, bssid, reason, timestamp) VALUES (?,?,?,?,?)',
            (src_mac, dst_mac, bssid, reason, now))
        self._maybe_commit()

    def log_eapol(self, client_mac, bssid, frame_number):
        now = datetime.now().isoformat(timespec='seconds')
        self.cursor.execute(
            'INSERT INTO eapol_frames (client_mac, bssid, frame_number, timestamp) VALUES (?,?,?,?)',
            (client_mac, bssid, frame_number, now))
        self._maybe_commit()

    def log_credential(self, client_ip, client_mac, username, password, url):
        now = datetime.now().isoformat(timespec='seconds')
        self.cursor.execute(
            'INSERT INTO credentials (client_ip, client_mac, username, password, url, timestamp) VALUES (?,?,?,?,?,?)',
            (client_ip, client_mac or "", username, password, url, now))
        self.conn.commit()
        log.critical(f"CREDENTIAL CAPTURED: user='{username}' from {client_ip}")
        log.debug(f"  Password: {'*' * len(password)}")

    # ─── Printer helper methods ─────────────────────────────────────────────────

    def log_printer(self, ip, model, manufacturer, hostname, serial, firmware, ssid, bssid, default_creds, vulns):
        """Insert or update a discovered printer."""
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
        self.cursor.execute('''
            INSERT INTO printer_credentials
                (printer_ip, username, password, auth_method, found_via, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (printer_ip, username, password, auth_method, found_via, time.time()))
        self.conn.commit()
        log.critical(f"PRINTER CRED CAPTURED: {auth_method} {username}@{printer_ip}")

    def get_printers(self):
        """Return all discovered printers."""
        self.cursor.execute('SELECT * FROM printers ORDER BY discovery_time DESC')
        columns = [desc[0] for desc in self.cursor.description]
        return [dict(zip(columns, row)) for row in self.cursor.fetchall()]

    def get_print_jobs(self, printer_ip=None):
        """Return intercepted print jobs, optionally filtered by printer IP."""
        if printer_ip:
            self.cursor.execute(
                'SELECT * FROM print_jobs WHERE printer_ip = ? ORDER BY timestamp DESC',
                (printer_ip,))
        else:
            self.cursor.execute('SELECT * FROM print_jobs ORDER BY timestamp DESC')
        columns = [desc[0] for desc in self.cursor.description]
        return [dict(zip(columns, row)) for row in self.cursor.fetchall()]

    # ─── Query methods (used by orchestrator for auto-targeting) ──────────────

    def get_clients_for_bssid(self, bssid):
        """Return all client MACs and their RSSI values associated with a given BSSID."""
        self.cursor.execute('SELECT mac, rssi FROM clients WHERE associated_bssid = ?', (bssid,))
        return [(row[0], row[1]) for row in self.cursor.fetchall()]

    def get_pos_access_points(self):
        """Return all POS-flagged APs with their SSID, channel, and BSSID."""
        self.cursor.execute(
            'SELECT bssid, ssid, channel, vendor, security, rssi FROM access_points '
            'WHERE is_pos_vendor = 1 OR is_pos_ssid = 1 ORDER BY rssi DESC')
        return self.cursor.fetchall()

    def get_strongest_ap(self):
        """Return the AP with strongest signal (best attack target)."""
        self.cursor.execute(
            'SELECT bssid, ssid, channel, vendor, rssi FROM access_points '
            'ORDER BY rssi DESC LIMIT 1')
        return self.cursor.fetchone()

    def get_strongest_pos_ap(self):
        """Return strongest POS AP (priority target for auto-attack)."""
        self.cursor.execute(
            'SELECT bssid, ssid, channel, vendor, rssi FROM access_points '
            'WHERE is_pos_vendor = 1 OR is_pos_ssid = 1 ORDER BY rssi DESC LIMIT 1')
        return self.cursor.fetchone()

    def get_all_ap_clients(self):
        """Return dict mapping BSSID -> list of client MACs."""
        self.cursor.execute('SELECT mac, associated_bssid FROM clients WHERE associated_bssid IS NOT NULL')
        result = {}
        for mac, bssid in self.cursor.fetchall():
            result.setdefault(bssid, []).append(mac)
        return result

    def get_stats(self):
        stats = {}
        for label, query in [
            ("access_points", "SELECT COUNT(*) FROM access_points"),
            ("pos_access_points", "SELECT COUNT(*) FROM access_points WHERE is_pos_vendor=1 OR is_pos_ssid=1"),
            ("clients", "SELECT COUNT(*) FROM clients"),
            ("pos_clients", "SELECT COUNT(*) FROM clients WHERE is_pos_vendor=1"),
            ("deauth_events", "SELECT COUNT(*) FROM deauth_events"),
            ("eapol_frames", "SELECT COUNT(*) FROM eapol_frames"),
            ("credentials", "SELECT COUNT(*) FROM credentials"),
        ]:
            self.cursor.execute(query)
            stats[label] = self.cursor.fetchone()[0]
        return stats

    def flush(self):
        self.conn.commit()

    def close(self):
        self.conn.commit()
        self.conn.close()


# Alias for backward compatibility
Database = POSDatabase
