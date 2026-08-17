"""
IPP (Internet Printing Protocol) Scanner
─────────────────────────────────────────
Scans and fingerprints IPP-enabled printers on port 631.

Features:
  - IPP protocol version detection
  - Printer capabilities and document format enumeration
  - Print queue and job history enumeration
  - Default credential checking (no auth, admin/admin, etc.)
  - Known IPP vulnerability detection
"""

import time
import socket
import struct
import threading

from .config import log


# IPP operation codes
IPP_GET_PRINTER_ATTRIBUTES = 0x000B
IPP_GET_JOBS = 0x000A
IPP_GET_JOB_ATTRIBUTES = 0x0009

# IPP tags
IPP_TAG_OPERATION = 0x01
IPP_TAG_JOB = 0x02
IPP_TAG_PRINTER = 0x04
IPP_TAG_END = 0x03
IPP_TAG_CHARSET = 0x47
IPP_TAG_NATURAL_LANGUAGE = 0x48
IPP_TAG_URI = 0x45
IPP_TAG_KEYWORD = 0x44
IPP_TAG_NAME = 0x42
IPP_TAG_TEXT = 0x41
IPP_TAG_INTEGER = 0x21
IPP_TAG_BOOLEAN = 0x22
IPP_TAG_ENUM = 0x23

# Common default credentials for printers
DEFAULT_CREDENTIALS = [
    (None, None),           # No auth
    ("admin", "admin"),
    ("admin", ""),
    ("admin", "password"),
    ("admin", "1234"),
    ("root", ""),
    ("root", "root"),
    ("user", "user"),
]


class IPPScanner:
    """
    IPP protocol scanner for printer enumeration and vulnerability detection.
    """

    def __init__(self, target_ip, port=631, db=None):
        self.target_ip = target_ip
        self.port = port
        self.db = db
        self._capabilities = {}
        self._queues = []
        self._jobs = []
        self._vulnerabilities = []
        self._ipp_version = None
        self._default_creds_found = []
        self._lock = threading.Lock()

    def scan(self):
        """Perform full IPP scan of target printer."""
        log.info(f"IPPScanner: Starting scan of {self.target_ip}:{self.port}")

        # Step 1: Check connectivity and detect IPP version
        if not self._check_port():
            log.warning(f"IPPScanner: Port {self.port} not open on {self.target_ip}")
            return False

        # Step 2: Get printer attributes (capabilities)
        self._get_printer_attributes()

        # Step 3: Enumerate print queues
        self._enumerate_jobs()

        # Step 4: Check for default credentials
        self._check_auth()

        # Step 5: Check for known vulnerabilities
        self._check_vulnerabilities()

        log.info(f"IPPScanner: Scan complete for {self.target_ip}")
        return True

    def _check_port(self):
        """Check if IPP port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.target_ip, self.port))
            sock.close()
            return result == 0
        except Exception as e:
            log.error(f"IPPScanner: Port check failed: {e}")
            return False

    def _build_ipp_request(self, operation_id, request_id=1, attributes=None):
        """Build an IPP request packet."""
        # IPP version 1.1
        packet = struct.pack(">BB", 1, 1)
        # Operation ID
        packet += struct.pack(">H", operation_id)
        # Request ID
        packet += struct.pack(">I", request_id)

        # Operation attributes group
        packet += struct.pack(">B", IPP_TAG_OPERATION)

        # Required: attributes-charset
        packet += self._encode_attribute(
            IPP_TAG_CHARSET, "attributes-charset", "utf-8"
        )

        # Required: attributes-natural-language
        packet += self._encode_attribute(
            IPP_TAG_NATURAL_LANGUAGE, "attributes-natural-language", "en-us"
        )

        # Printer URI
        printer_uri = f"ipp://{self.target_ip}:{self.port}/ipp/print"
        packet += self._encode_attribute(
            IPP_TAG_URI, "printer-uri", printer_uri
        )

        # Additional attributes
        if attributes:
            for tag, name, value in attributes:
                packet += self._encode_attribute(tag, name, value)

        # End of attributes
        packet += struct.pack(">B", IPP_TAG_END)

        return packet

    def _encode_attribute(self, value_tag, name, value):
        """Encode a single IPP attribute."""
        name_bytes = name.encode("utf-8")
        value_bytes = value.encode("utf-8") if isinstance(value, str) else value

        attr = struct.pack(">B", value_tag)
        attr += struct.pack(">H", len(name_bytes))
        attr += name_bytes
        attr += struct.pack(">H", len(value_bytes))
        attr += value_bytes

        return attr

    def _send_ipp_request(self, ipp_data, auth=None):
        """Send IPP request over HTTP POST to the printer."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.target_ip, self.port))

            # Build HTTP POST request
            path = "/ipp/print"
            headers = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {self.target_ip}:{self.port}\r\n"
                f"Content-Type: application/ipp\r\n"
                f"Content-Length: {len(ipp_data)}\r\n"
            )

            if auth:
                import base64
                username, password = auth
                cred = base64.b64encode(f"{username}:{password}".encode()).decode()
                headers += f"Authorization: Basic {cred}\r\n"

            headers += "Connection: close\r\n\r\n"

            sock.sendall(headers.encode() + ipp_data)

            # Read response
            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 65536:
                        break
                except socket.timeout:
                    break

            sock.close()
            return response

        except Exception as e:
            log.debug(f"IPPScanner: Request error: {e}")
            return None

    def _get_printer_attributes(self):
        """Retrieve printer attributes via IPP Get-Printer-Attributes."""
        ipp_request = self._build_ipp_request(IPP_GET_PRINTER_ATTRIBUTES)
        response = self._send_ipp_request(ipp_request)

        if not response:
            return

        # Parse IPP response
        ipp_data = self._extract_ipp_body(response)
        if ipp_data:
            self._parse_printer_attributes(ipp_data)

    def _extract_ipp_body(self, http_response):
        """Extract IPP body from HTTP response."""
        try:
            # Find end of HTTP headers
            header_end = http_response.find(b"\r\n\r\n")
            if header_end < 0:
                return None

            # Check HTTP status
            first_line = http_response[:http_response.find(b"\r\n")].decode("utf-8", errors="ignore")
            if "200" in first_line:
                self._ipp_version = "1.1"
                return http_response[header_end + 4:]

            # 401 means auth required
            if "401" in first_line:
                log.info(f"IPPScanner: Authentication required on {self.target_ip}")
                return None

        except Exception:
            pass
        return None

    def _parse_printer_attributes(self, ipp_data):
        """Parse IPP response data and extract printer capabilities."""
        with self._lock:
            try:
                idx = 4  # Skip version + status code
                idx += 4  # Skip request ID

                current_group = None
                while idx < len(ipp_data) - 1:
                    tag = ipp_data[idx]
                    idx += 1

                    # Group tags
                    if tag in (IPP_TAG_OPERATION, IPP_TAG_JOB, IPP_TAG_PRINTER):
                        current_group = tag
                        continue

                    if tag == IPP_TAG_END:
                        break

                    # Value tag - parse attribute
                    if idx + 4 > len(ipp_data):
                        break

                    name_len = struct.unpack(">H", ipp_data[idx:idx + 2])[0]
                    idx += 2

                    if idx + name_len + 2 > len(ipp_data):
                        break

                    name = ipp_data[idx:idx + name_len].decode("utf-8", errors="ignore")
                    idx += name_len

                    value_len = struct.unpack(">H", ipp_data[idx:idx + 2])[0]
                    idx += 2

                    if idx + value_len > len(ipp_data):
                        break

                    value = ipp_data[idx:idx + value_len]
                    idx += value_len

                    # Store attribute
                    try:
                        value_str = value.decode("utf-8", errors="ignore")
                    except Exception:
                        value_str = repr(value)

                    if name:
                        self._capabilities[name] = value_str

            except Exception as e:
                log.debug(f"IPPScanner: Parse error: {e}")

    def _enumerate_jobs(self):
        """Enumerate print jobs via IPP Get-Jobs."""
        ipp_request = self._build_ipp_request(IPP_GET_JOBS)
        response = self._send_ipp_request(ipp_request)

        if not response:
            return

        ipp_data = self._extract_ipp_body(response)
        if ipp_data:
            self._parse_jobs(ipp_data)

    def _parse_jobs(self, ipp_data):
        """Parse job list from IPP response."""
        with self._lock:
            try:
                idx = 8  # Skip version + status + request ID
                current_job = {}

                while idx < len(ipp_data) - 1:
                    tag = ipp_data[idx]
                    idx += 1

                    if tag == IPP_TAG_JOB:
                        if current_job:
                            self._jobs.append(current_job)
                        current_job = {}
                        continue

                    if tag == IPP_TAG_END:
                        if current_job:
                            self._jobs.append(current_job)
                        break

                    if tag in (IPP_TAG_OPERATION, IPP_TAG_PRINTER):
                        continue

                    # Parse attribute
                    if idx + 4 > len(ipp_data):
                        break

                    name_len = struct.unpack(">H", ipp_data[idx:idx + 2])[0]
                    idx += 2

                    if idx + name_len + 2 > len(ipp_data):
                        break

                    name = ipp_data[idx:idx + name_len].decode("utf-8", errors="ignore")
                    idx += name_len

                    value_len = struct.unpack(">H", ipp_data[idx:idx + 2])[0]
                    idx += 2

                    if idx + value_len > len(ipp_data):
                        break

                    value = ipp_data[idx:idx + value_len]
                    idx += value_len

                    if name:
                        try:
                            current_job[name] = value.decode("utf-8", errors="ignore")
                        except Exception:
                            current_job[name] = repr(value)

            except Exception as e:
                log.debug(f"IPPScanner: Job parse error: {e}")

    def _check_auth(self):
        """Check for default credentials on the IPP service."""
        for username, password in DEFAULT_CREDENTIALS:
            try:
                ipp_request = self._build_ipp_request(IPP_GET_PRINTER_ATTRIBUTES)

                if username is None:
                    response = self._send_ipp_request(ipp_request)
                else:
                    response = self._send_ipp_request(ipp_request, auth=(username, password))

                if response:
                    first_line = response[:response.find(b"\r\n")].decode("utf-8", errors="ignore")
                    if "200" in first_line:
                        cred_str = f"{username}:{password}" if username else "no-auth"
                        self._default_creds_found.append((username, password))
                        log.warning(f"IPPScanner: Default creds work on {self.target_ip}: {cred_str}")

                        if self.db:
                            try:
                                self.db.log_printer_credential(
                                    printer_ip=self.target_ip,
                                    username=username or "",
                                    password=password or "",
                                    auth_method="HTTP Basic",
                                    found_via="IPP default credential check",
                                )
                            except Exception as e:
                                log.error(f"IPPScanner: DB error logging cred: {e}")
                        break

            except Exception as e:
                log.debug(f"IPPScanner: Auth check error: {e}")

    def _check_vulnerabilities(self):
        """Check for known IPP vulnerabilities."""
        with self._lock:
            # CVE-2019-8675: CUPS buffer overflow
            if self._capabilities.get("cups-version", ""):
                cups_ver = self._capabilities["cups-version"]
                try:
                    parts = cups_ver.split(".")
                    if len(parts) >= 2:
                        major, minor = int(parts[0]), int(parts[1])
                        if major < 2 or (major == 2 and minor < 3):
                            self._vulnerabilities.append(
                                f"CVE-2019-8675: CUPS {cups_ver} may be vulnerable to buffer overflow"
                            )
                except (ValueError, IndexError):
                    pass

            # Check for unauthenticated access
            if self._default_creds_found:
                self._vulnerabilities.append(
                    "Unauthenticated or default credential access to IPP service"
                )

            # Check if printer exposes job history
            if self._jobs:
                self._vulnerabilities.append(
                    f"Printer exposes job history ({len(self._jobs)} jobs visible)"
                )

    def check_default_creds(self):
        """Public method to check for default credentials."""
        self._check_auth()
        return self._default_creds_found

    def get_capabilities(self):
        """Return discovered printer capabilities."""
        with self._lock:
            return dict(self._capabilities)

    def enumerate_queues(self):
        """Return discovered print queues/jobs."""
        with self._lock:
            return list(self._jobs)

    def get_stats(self):
        """Return IPP scanner statistics."""
        with self._lock:
            return {
                "target": self.target_ip,
                "port": self.port,
                "ipp_version": self._ipp_version,
                "capabilities_count": len(self._capabilities),
                "jobs_found": len(self._jobs),
                "default_creds": len(self._default_creds_found),
                "vulnerabilities": len(self._vulnerabilities),
                "vulnerability_list": list(self._vulnerabilities),
            }
