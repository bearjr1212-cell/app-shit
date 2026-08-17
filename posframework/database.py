"""
SQLite Database Layer
─────────────────────
WAL mode, batched commits, indexed tables for APs, clients, deauth events,
EAPOL handshake frames, and harvested credentials.

Thread-safe: all cursor operations are serialized via a reentrant lock.

Performance optimizations:
  - WAL mode + synchronous=NORMAL for crash-safe concurrent reads
  - Connection pooling (reuse connections from a thread-local pool)
  - Write buffer: accumulates records and flushes in batches
  - PRAGMA tuning: large cache, mmap, journal_size_limit, temp_store=MEMORY
"""

import sqlite3
import time
import threading
from datetime import datetime
from collections import deque

from .config import DB_NAME, COMMIT_INTERVAL, log
from .intel import is_pos_ssid

# Schema version — increment when adding/altering tables or columns
SCHEMA_VERSION = 2

# ─── Write buffer settings ────────────────────────────────────────────────────
WRITE_BUFFER_SIZE = 50       # Flush after N records
WRITE_BUFFER_INTERVAL = 2.0  # Flush every T seconds

# ─── Connection pool settings ─────────────────────────────────────────────────
POOL_SIZE = 4


class _ConnectionPool:
    """Simple thread-safe SQLite connection pool with PRAGMA optimizations."""

    def __init__(self, db_path, size=POOL_SIZE):
        self.db_path = db_path
        self._pool = deque()
        self._lock = threading.Lock()
        # Pre-create connections
        for _ in range(size):
            self._pool.append(self._make_conn())

    def _make_conn(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA cache_size=-16000")       # 16 MB page cache
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("PRAGMA mmap_size=268435456")     # 256 MB mmap
        conn.execute("PRAGMA journal_size_limit=67108864")  # 64 MB WAL limit
        return conn

    def get(self):
        with self._lock:
            if self._pool:
                return self._pool.popleft()
        # Pool exhausted — create a new connection on the fly
        return self._make_conn()

    def put(self, conn):
        with self._lock:
            self._pool.append(conn)

    def close_all(self):
        with self._lock:
            while self._pool:
                try:
                    self._pool.popleft().close()
                except Exception:
                    pass


class POSDatabase:
    def __init__(self, db_path=None):
        self.db_path = db_path or DB_NAME
        # Primary connection (backward compat)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA cache_size=-16000")
        self.conn.execute("PRAGMA temp_store=MEMORY")
        self.conn.execute("PRAGMA mmap_size=268435456")
        self.conn.execute("PRAGMA journal_size_limit=67108864")
        self.cursor = self.conn.cursor()
        self._lock = threading.RLock()
        self._last_commit = time.monotonic()
        self._commit_lock = threading.Lock()
        self._closed = False
        # Connection pool for read-heavy queries
        self._pool = _ConnectionPool(self.db_path)
        # Write buffer for batched inserts
        self._write_buffer = deque()
        self._buffer_lock = threading.Lock()
        self._buffer_last_flush = time.monotonic()
        self._flush_timer = threading.Thread(target=self._buffer_flush_loop, daemon=True)
        self._flush_timer.start()
        self._migrate_schema()
        self._setup_tables()

    # ─── Context manager support ─────────────────────────────────────────────

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def __del__(self):
        try:
            if not self._closed:
                self.close()
        except Exception:
            pass

    # ─── Schema versioning ───────────────────────────────────────────────────

    def _get_schema_version(self):
        """Read current schema version from PRAGMA user_version."""
        with self._lock:
            self.cursor.execute("PRAGMA user_version")
            return self.cursor.fetchone()[0]

    def _set_schema_version(self, version):
        """Set the schema version."""
        with self._lock:
            self.cursor.execute(f"PRAGMA user_version = {int(version)}")
            self.conn.commit()

    def _migrate_schema(self):
        """Apply any needed schema migrations."""
        current = self._get_schema_version()

        if current < 1:
            # Version 1: initial schema (tables created in _setup_tables)
            pass

        if current < 2:
            # Version 2: printer tables added (created in _setup_printer_tables)
            # Tables use IF NOT EXISTS so safe to re-run
            pass

        # After all migrations, set to current version
        if current < SCHEMA_VERSION:
            self._set_schema_version(SCHEMA_VERSION)

    # ─── Table setup ─────────────────────────────────────────────────────────

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

    # ─── Commit helpers ──────────────────────────────────────────────────────

    def _maybe_commit(self):
        now = time.monotonic()
        with self._commit_lock:
            if now - self._last_commit >= COMMIT_INTERVAL:
                self.conn.commit()
                self._last_commit = now

    def _immediate_commit(self):
        """Force an immediate commit for critical events."""
        with self._commit_lock:
            self.conn.commit()
            self._last_commit = time.monotonic()

    # ─── Write buffer (batched inserts) ─────────────────────────────────────

    def _buffer_flush_loop(self):
        """Background thread that flushes the write buffer periodically."""
        while not self._closed:
            time.sleep(WRITE_BUFFER_INTERVAL)
            self._flush_write_buffer()

    def _enqueue_write(self, sql, params):
        """Add a write operation to the buffer; flush if threshold reached."""
        with self._buffer_lock:
            self._write_buffer.append((sql, params))
            if len(self._write_buffer) >= WRITE_BUFFER_SIZE:
                self._flush_write_buffer_locked()

    def _flush_write_buffer(self):
        """Flush all buffered writes using executemany where possible."""
        with self._buffer_lock:
            self._flush_write_buffer_locked()

    def _flush_write_buffer_locked(self):
        """Internal flush — caller must hold _buffer_lock."""
        if not self._write_buffer:
            return
        # Group by SQL statement for executemany
        batches = {}
        while self._write_buffer:
            sql, params = self._write_buffer.popleft()
            batches.setdefault(sql, []).append(params)
        with self._lock:
            for sql, param_list in batches.items():
                try:
                    self.cursor.executemany(sql, param_list)
                except Exception as e:
                    log.error(f"Batch write error: {e}")
                    # Fallback: execute individually
                    for p in param_list:
                        try:
                            self.cursor.execute(sql, p)
                        except Exception:
                            pass
            self.conn.commit()
            self._last_commit = time.monotonic()
        self._buffer_last_flush = time.monotonic()

    # ─── Write methods ───────────────────────────────────────────────────────

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
        self._enqueue_write(
            'INSERT INTO deauth_events (src_mac, dst_mac, bssid, reason, timestamp) VALUES (?,?,?,?,?)',
            (src_mac, dst_mac, bssid, reason, now))

    def log_eapol(self, client_mac, bssid, frame_number):
        """Log an EAPOL frame. Commits immediately — handshake data is critical."""
        now = datetime.now().isoformat(timespec='seconds')
        with self._lock:
            self.cursor.execute(
                'INSERT INTO eapol_frames (client_mac, bssid, frame_number, timestamp) VALUES (?,?,?,?)',
                (client_mac, bssid, frame_number, now))
        self._immediate_commit()

    def log_credential(self, client_ip, client_mac, username, password, url):
        now = datetime.now().isoformat(timespec='seconds')
        with self._lock:
            self.cursor.execute(
                'INSERT INTO credentials (client_ip, client_mac, username, password, url, timestamp) VALUES (?,?,?,?,?,?)',
                (client_ip, client_mac or "", username, password, url, now))
        self._immediate_commit()
        log.critical(f"CREDENTIAL CAPTURED: user='{username}' from {client_ip}")
        log.debug(f"  Password: {'*' * len(password)}")

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
        self._enqueue_write('''
                INSERT INTO print_jobs
                    (printer_ip, timestamp, source_ip, document_name, document_type,
                     page_count, file_size, extracted_content)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (printer_ip, time.time(), source_ip, doc_name, doc_type,
                  page_count, file_size, content))
        log.info(f"Print job logged: {doc_type} from {source_ip} to {printer_ip}")

    def log_printer_credential(self, printer_ip, username, password, auth_method, found_via):
        """Log a captured printer credential. Commits immediately."""
        with self._lock:
            self.cursor.execute('''
                INSERT INTO printer_credentials
                    (printer_ip, username, password, auth_method, found_via, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (printer_ip, username, password, auth_method, found_via, time.time()))
        self._immediate_commit()
        log.critical(f"PRINTER CRED CAPTURED: {auth_method} {username}@{printer_ip}")

    # ─── Query methods ───────────────────────────────────────────────────────

    def get_printers(self):
        """Return all discovered printers."""
        with self._lock:
            self.cursor.execute('SELECT * FROM printers ORDER BY discovery_time DESC')
            columns = [desc[0] for desc in self.cursor.description]
            return [dict(zip(columns, row)) for row in self.cursor.fetchall()]

    def get_print_jobs(self, printer_ip=None):
        """Return intercepted print jobs, optionally filtered by printer IP."""
        with self._lock:
            if printer_ip:
                self.cursor.execute(
                    'SELECT * FROM print_jobs WHERE printer_ip = ? ORDER BY timestamp DESC',
                    (printer_ip,))
            else:
                self.cursor.execute('SELECT * FROM print_jobs ORDER BY timestamp DESC')
            columns = [desc[0] for desc in self.cursor.description]
            return [dict(zip(columns, row)) for row in self.cursor.fetchall()]

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

    # ─── New API methods (replacing raw cursor access in other modules) ──────

    def get_ap_by_bssid(self, bssid):
        """Return a single AP row by BSSID, or None."""
        with self._lock:
            self.cursor.execute(
                'SELECT bssid, ssid, channel, vendor, security, rssi FROM access_points WHERE bssid = ?',
                (bssid,))
            return self.cursor.fetchone()

    def get_probed_ssids(self):
        """Return list of all unique probed SSIDs from clients."""
        with self._lock:
            self.cursor.execute(
                'SELECT DISTINCT probed_ssids FROM clients '
                'WHERE probed_ssids IS NOT NULL AND probed_ssids != ""')
            ssids = []
            for row in self.cursor.fetchall():
                if row[0]:
                    for ssid in row[0].split(','):
                        ssid = ssid.strip()
                        if ssid and ssid not in ssids:
                            ssids.append(ssid)
            return ssids

    def get_unique_usernames(self):
        """Return list of unique usernames from credentials table."""
        with self._lock:
            self.cursor.execute(
                'SELECT DISTINCT username FROM credentials WHERE username IS NOT NULL')
            return [row[0] for row in self.cursor.fetchall()]

    def get_credentials_list(self):
        """Return all credentials as list of dicts."""
        with self._lock:
            self.cursor.execute(
                'SELECT id, client_ip, client_mac, username, password, url, timestamp '
                'FROM credentials WHERE username IS NOT NULL OR password IS NOT NULL')
            columns = ['id', 'client_ip', 'client_mac', 'username', 'password', 'url', 'timestamp']
            return [dict(zip(columns, row)) for row in self.cursor.fetchall()]

    def get_eapol_bssids(self):
        """Return list of distinct BSSIDs that have EAPOL frames."""
        with self._lock:
            self.cursor.execute('SELECT DISTINCT bssid FROM eapol_frames')
            return [row[0] for row in self.cursor.fetchall()]

    def get_eapol_frames_for_bssid(self, bssid):
        """Return EAPOL frames for a given BSSID as list of (client_mac, frame_number, timestamp)."""
        with self._lock:
            self.cursor.execute(
                'SELECT client_mac, frame_number, timestamp FROM eapol_frames '
                'WHERE bssid = ? ORDER BY timestamp',
                (bssid,))
            return self.cursor.fetchall()

    # ─── Stats ───────────────────────────────────────────────────────────────

    def get_stats(self):
        stats = {}
        queries = [
            ("access_points", "SELECT COUNT(*) FROM access_points"),
            ("pos_access_points", "SELECT COUNT(*) FROM access_points WHERE is_pos_vendor=1 OR is_pos_ssid=1"),
            ("clients", "SELECT COUNT(*) FROM clients"),
            ("pos_clients", "SELECT COUNT(*) FROM clients WHERE is_pos_vendor=1"),
            ("deauth_events", "SELECT COUNT(*) FROM deauth_events"),
            ("eapol_frames", "SELECT COUNT(*) FROM eapol_frames"),
            ("credentials", "SELECT COUNT(*) FROM credentials"),
            ("printers", "SELECT COUNT(*) FROM printers"),
            ("print_jobs", "SELECT COUNT(*) FROM print_jobs"),
            ("printer_credentials", "SELECT COUNT(*) FROM printer_credentials"),
        ]
        with self._lock:
            for label, query in queries:
                self.cursor.execute(query)
                stats[label] = self.cursor.fetchone()[0]
        return stats

    # ─── Lifecycle ───────────────────────────────────────────────────────────

    def flush(self):
        self._flush_write_buffer()
        with self._commit_lock:
            self.conn.commit()
            self._last_commit = time.monotonic()

    def close(self):
        if self._closed:
            return
        self._closed = True
        # Wait for flush timer thread to finish
        if self._flush_timer and self._flush_timer.is_alive():
            self._flush_timer.join(timeout=WRITE_BUFFER_INTERVAL + 1)
        try:
            self._flush_write_buffer()
            self.conn.commit()
            self.conn.close()
            self._pool.close_all()
        except Exception:
            pass


# Alias for backward compatibility
Database = POSDatabase
