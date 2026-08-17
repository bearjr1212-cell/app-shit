"""
pyWhat Attack Surface Analyzer
------------------------------
Integrates pyWhat (https://github.com/bee-san/pyWhat) for automated
identification of credentials, API keys, hashes, URLs, IPs, crypto
wallets, and other interesting patterns in captured/decrypted traffic.

When pyWhat is not installed, falls back to comprehensive built-in
regex patterns covering common attack surface indicators.

This module provides:
  - PyWhatAnalyzer: Regex/pyWhat pattern matching engine
  - PyWhatCallback: LiveDecryptionSession-compatible callback
"""

import re
import time
from typing import Any, Callable, Dict, List, Optional

from .config import log

# ---- Optional pyWhat import ------------------------------------------------

try:
    from pywhat import Identifier as _PyWhatIdentifier  # type: ignore[import]
    _PYWHAT_AVAILABLE = True
except ImportError:
    _PyWhatIdentifier = None
    _PYWHAT_AVAILABLE = False


# ---- Fallback Regex Patterns ------------------------------------------------

# Each pattern: (name, category, compiled regex, confidence 0.0-1.0)
_FALLBACK_PATTERNS: List[Dict[str, Any]] = []


def _build_patterns() -> List[Dict[str, Any]]:
    """Build and compile fallback regex patterns for common identifiers."""
    raw_patterns = [
        # API Keys
        {
            "name": "AWS Access Key ID",
            "category": "credentials",
            "pattern": r"(?:^|[^A-Z0-9])(?P<match>AKIA[0-9A-Z]{16})(?:[^A-Z0-9]|$)",
            "confidence": 0.9,
        },
        {
            "name": "AWS Secret Access Key",
            "category": "credentials",
            "pattern": r"(?:aws_secret_access_key|secret_key|aws_secret)\s*[:=]\s*['\"]?(?P<match>[A-Za-z0-9/+=]{40})['\"]?",
            "confidence": 0.85,
        },
        {
            "name": "GitHub Token",
            "category": "credentials",
            "pattern": r"(?P<match>(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255})",
            "confidence": 0.95,
        },
        {
            "name": "Slack Token",
            "category": "credentials",
            "pattern": r"(?P<match>xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{20,48})",
            "confidence": 0.95,
        },
        {
            "name": "Slack Webhook URL",
            "category": "credentials",
            "pattern": r"(?P<match>https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+)",
            "confidence": 0.95,
        },
        {
            "name": "Google API Key",
            "category": "credentials",
            "pattern": r"(?P<match>AIza[0-9A-Za-z\-_]{35})",
            "confidence": 0.9,
        },
        {
            "name": "Google OAuth Token",
            "category": "credentials",
            "pattern": r"(?P<match>ya29\.[0-9A-Za-z\-_]+)",
            "confidence": 0.85,
        },
        {
            "name": "Stripe Secret Key",
            "category": "credentials",
            "pattern": r"(?P<match>sk_live_[0-9a-zA-Z]{24,99})",
            "confidence": 0.95,
        },
        {
            "name": "Stripe Publishable Key",
            "category": "credentials",
            "pattern": r"(?P<match>pk_live_[0-9a-zA-Z]{24,99})",
            "confidence": 0.9,
        },
        {
            "name": "Heroku API Key",
            "category": "credentials",
            "pattern": r"(?:heroku.*api[_-]?key|HEROKU_API_KEY)\s*[:=]\s*['\"]?(?P<match>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})['\"]?",
            "confidence": 0.85,
        },
        {
            "name": "Generic API Key",
            "category": "credentials",
            "pattern": r"(?:api[_-]?key|apikey|api_secret)\s*[:=]\s*['\"]?(?P<match>[A-Za-z0-9_\-]{20,64})['\"]?",
            "confidence": 0.6,
        },
        {
            "name": "Bearer Token",
            "category": "credentials",
            "pattern": r"[Bb]earer\s+(?P<match>[A-Za-z0-9\-._~+/]+=*)",
            "confidence": 0.8,
        },
        {
            "name": "Basic Auth",
            "category": "credentials",
            "pattern": r"[Bb]asic\s+(?P<match>[A-Za-z0-9+/]{4,}={0,2})",
            "confidence": 0.8,
        },
        # Hashes
        {
            "name": "MD5 Hash",
            "category": "hashes",
            "pattern": r"(?:^|[^a-fA-F0-9])(?P<match>[a-fA-F0-9]{32})(?:[^a-fA-F0-9]|$)",
            "confidence": 0.5,
        },
        {
            "name": "SHA1 Hash",
            "category": "hashes",
            "pattern": r"(?:^|[^a-fA-F0-9])(?P<match>[a-fA-F0-9]{40})(?:[^a-fA-F0-9]|$)",
            "confidence": 0.5,
        },
        {
            "name": "SHA256 Hash",
            "category": "hashes",
            "pattern": r"(?:^|[^a-fA-F0-9])(?P<match>[a-fA-F0-9]{64})(?:[^a-fA-F0-9]|$)",
            "confidence": 0.6,
        },
        {
            "name": "SHA512 Hash",
            "category": "hashes",
            "pattern": r"(?:^|[^a-fA-F0-9])(?P<match>[a-fA-F0-9]{128})(?:[^a-fA-F0-9]|$)",
            "confidence": 0.6,
        },
        {
            "name": "NTLM Hash",
            "category": "hashes",
            "pattern": r"(?P<match>[a-fA-F0-9]{32}:[a-fA-F0-9]{32})",
            "confidence": 0.8,
        },
        {
            "name": "bcrypt Hash",
            "category": "hashes",
            "pattern": r"(?P<match>\$2[aby]?\$\d{1,2}\$[./A-Za-z0-9]{53})",
            "confidence": 0.9,
        },
        # URLs and Network
        {
            "name": "URL",
            "category": "network",
            "pattern": r"(?P<match>https?://[^\s<>\"']+)",
            "confidence": 0.9,
        },
        {
            "name": "IPv4 Address",
            "category": "network",
            "pattern": r"(?:^|[^0-9.])(?P<match>(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))(?:[^0-9.]|$)",
            "confidence": 0.7,
        },
        {
            "name": "IPv6 Address",
            "category": "network",
            "pattern": r"(?P<match>(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4})",
            "confidence": 0.7,
        },
        # Email
        {
            "name": "Email Address",
            "category": "identifiers",
            "pattern": r"(?P<match>[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})",
            "confidence": 0.85,
        },
        # Credit Cards
        {
            "name": "Visa Card Number",
            "category": "financial",
            "pattern": r"(?:^|[^0-9])(?P<match>4[0-9]{12}(?:[0-9]{3})?)(?:[^0-9]|$)",
            "confidence": 0.7,
        },
        {
            "name": "Mastercard Number",
            "category": "financial",
            "pattern": r"(?:^|[^0-9])(?P<match>5[1-5][0-9]{14})(?:[^0-9]|$)",
            "confidence": 0.7,
        },
        {
            "name": "Amex Card Number",
            "category": "financial",
            "pattern": r"(?:^|[^0-9])(?P<match>3[47][0-9]{13})(?:[^0-9]|$)",
            "confidence": 0.7,
        },
        # Crypto Wallets
        {
            "name": "Bitcoin Address",
            "category": "crypto",
            "pattern": r"(?P<match>[13][a-km-zA-HJ-NP-Z1-9]{25,34})",
            "confidence": 0.7,
        },
        {
            "name": "Bitcoin Bech32 Address",
            "category": "crypto",
            "pattern": r"(?P<match>bc1[a-zA-HJ-NP-Z0-9]{25,89})",
            "confidence": 0.85,
        },
        {
            "name": "Ethereum Address",
            "category": "crypto",
            "pattern": r"(?P<match>0x[0-9a-fA-F]{40})",
            "confidence": 0.8,
        },
        # JWT / Tokens
        {
            "name": "JWT Token",
            "category": "credentials",
            "pattern": r"(?P<match>eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_\-]+)",
            "confidence": 0.95,
        },
        # Private Keys
        {
            "name": "RSA Private Key",
            "category": "credentials",
            "pattern": r"(?P<match>-----BEGIN RSA PRIVATE KEY-----)",
            "confidence": 0.99,
        },
        {
            "name": "Private Key (Generic)",
            "category": "credentials",
            "pattern": r"(?P<match>-----BEGIN (?:EC |DSA |OPENSSH )?PRIVATE KEY-----)",
            "confidence": 0.99,
        },
        # Connection Strings
        {
            "name": "Database Connection String",
            "category": "credentials",
            "pattern": r"(?P<match>(?:mysql|postgres|postgresql|mongodb|redis|mssql)://[^\s<>\"']+)",
            "confidence": 0.9,
        },
        {
            "name": "JDBC Connection String",
            "category": "credentials",
            "pattern": r"(?P<match>jdbc:[a-z]+://[^\s<>\"']+)",
            "confidence": 0.85,
        },
        # Base64 Blobs (substantial size)
        {
            "name": "Base64 Encoded Blob",
            "category": "encoded",
            "pattern": r"(?P<match>[A-Za-z0-9+/]{50,}={0,2})",
            "confidence": 0.4,
        },
        # Password patterns in key=value context
        {
            "name": "Password in Assignment",
            "category": "credentials",
            "pattern": r"(?:password|passwd|pwd|pass)\s*[:=]\s*['\"]?(?P<match>[^\s'\"]{4,64})['\"]?",
            "confidence": 0.75,
        },
    ]

    compiled: List[Dict[str, Any]] = []
    for p in raw_patterns:
        try:
            compiled.append({
                "name": p["name"],
                "category": p["category"],
                "regex": re.compile(p["pattern"], re.IGNORECASE),
                "confidence": p["confidence"],
            })
        except re.error:
            log.warning(f"Failed to compile regex pattern: {p['name']}")
    return compiled


# Build patterns once at module load
_FALLBACK_PATTERNS = _build_patterns()


# ---- PyWhatAnalyzer ---------------------------------------------------------


class PyWhatAnalyzer:
    """
    Automated attack surface identifier using pyWhat or fallback regex.

    Scans text for credentials, API keys, hashes, network identifiers,
    financial data, crypto wallets, and encoded payloads.

    Usage:
        analyzer = PyWhatAnalyzer()
        results = analyzer.analyze("Bearer eyJhbGci...")
        surfaces = analyzer.get_attack_surfaces()
    """

    def __init__(self) -> None:
        self._use_pywhat = _PYWHAT_AVAILABLE
        self._identifier: Optional[Any] = None
        self._findings: List[Dict[str, Any]] = []

        if self._use_pywhat and _PyWhatIdentifier is not None:
            try:
                self._identifier = _PyWhatIdentifier()
                log.info("pyWhat library loaded for attack surface analysis")
            except Exception as exc:
                log.warning(f"pyWhat init failed, using fallback: {exc}")
                self._use_pywhat = False
        else:
            log.info(
                "pyWhat not installed - using built-in regex patterns "
                "for attack surface analysis"
            )

    @property
    def using_pywhat(self) -> bool:
        """Whether the real pyWhat library is active."""
        return self._use_pywhat

    @property
    def findings(self) -> List[Dict[str, Any]]:
        """All accumulated findings from analyze/analyze_traffic calls."""
        return list(self._findings)

    def analyze(self, text: str) -> List[Dict[str, Any]]:
        """
        Analyze a text string for interesting patterns.

        Args:
            text: Input string to scan (URL, header value, body, etc.).

        Returns:
            List of dicts with keys: name, value, category, confidence.
        """
        if not text or not isinstance(text, str):
            return []

        results: List[Dict[str, Any]] = []

        if self._use_pywhat and self._identifier is not None:
            results = self._analyze_pywhat(text)
        else:
            results = self._analyze_fallback(text)

        # Deduplicate by (name, value) and store
        seen: set = set()
        unique: List[Dict[str, Any]] = []
        for item in results:
            key = (item["name"], item["value"])
            if key not in seen:
                seen.add(key)
                unique.append(item)

        self._findings.extend(unique)
        return unique

    def analyze_traffic(self, decrypted_summary: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyze full LiveDecryptionSession output for attack surfaces.

        Processes DNS queries, HTTP requests, DHCP data, EAPOL events,
        and stored credentials from a decryption session summary.

        Args:
            decrypted_summary: Dict from LiveDecryptionSession.get_decrypted_summary()
                Expected keys: dns_queries, http_requests, dhcp_leases,
                eapol_events, credentials.

        Returns:
            List of all identified items across all traffic types.
        """
        all_results: List[Dict[str, Any]] = []

        # Analyze DNS queries (domain names may reveal infrastructure)
        for dns_entry in decrypted_summary.get("dns_queries", []):
            query = dns_entry.get("query", "")
            response = dns_entry.get("response", "")
            if query:
                items = self.analyze(query)
                for item in items:
                    item["source"] = "dns_query"
                all_results.extend(items)
            if response:
                items = self.analyze(response)
                for item in items:
                    item["source"] = "dns_response"
                all_results.extend(items)

        # Analyze HTTP requests (rich source of credentials/keys)
        for http_entry in decrypted_summary.get("http_requests", []):
            # Analyze host
            host = http_entry.get("host", "")
            if host:
                items = self.analyze(host)
                for item in items:
                    item["source"] = "http_host"
                all_results.extend(items)

            # Analyze URI (may contain API keys, tokens)
            uri = http_entry.get("uri", "")
            if uri:
                items = self.analyze(uri)
                for item in items:
                    item["source"] = "http_uri"
                all_results.extend(items)

            # Analyze cookies
            cookie = http_entry.get("cookie", "")
            if cookie:
                items = self.analyze(cookie)
                for item in items:
                    item["source"] = "http_cookie"
                all_results.extend(items)

            # Analyze user-agent (fingerprinting)
            user_agent = http_entry.get("user_agent", "")
            if user_agent:
                items = self.analyze(user_agent)
                for item in items:
                    item["source"] = "http_user_agent"
                all_results.extend(items)

            # Analyze authorization header (high value)
            auth = http_entry.get("authorization", "")
            if auth:
                items = self.analyze(auth)
                for item in items:
                    item["source"] = "http_authorization"
                all_results.extend(items)

        # Analyze DHCP leases (hostnames, IPs)
        for dhcp_entry in decrypted_summary.get("dhcp_leases", []):
            hostname = dhcp_entry.get("hostname", "")
            if hostname:
                items = self.analyze(hostname)
                for item in items:
                    item["source"] = "dhcp_hostname"
                all_results.extend(items)
            requested_ip = dhcp_entry.get("requested_ip", "")
            if requested_ip:
                items = self.analyze(requested_ip)
                for item in items:
                    item["source"] = "dhcp_ip"
                all_results.extend(items)

        # Analyze stored credentials
        for cred_entry in decrypted_summary.get("credentials", []):
            value = cred_entry.get("value", "")
            if value:
                items = self.analyze(value)
                for item in items:
                    item["source"] = "credential"
                all_results.extend(items)

        return all_results

    def get_attack_surfaces(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Return accumulated findings categorized by attack surface type.

        Returns:
            Dict with category keys mapping to lists of findings:
            - credentials: API keys, passwords, tokens, private keys
            - keys: AWS keys, Stripe keys, generic API keys
            - network: URLs, IPs, connection strings
            - identifiers: Emails, hostnames
            - financial: Credit card numbers
            - crypto: Cryptocurrency wallet addresses
            - hashes: MD5, SHA, NTLM hashes
            - encoded: Base64 blobs, JWTs
        """
        surfaces: Dict[str, List[Dict[str, Any]]] = {
            "credentials": [],
            "keys": [],
            "network": [],
            "identifiers": [],
            "financial": [],
            "crypto": [],
            "hashes": [],
            "encoded": [],
        }

        for finding in self._findings:
            category = finding.get("category", "")
            # Map to attack surface categories
            if category == "credentials":
                # Sub-categorize keys vs other credentials
                name_lower = finding["name"].lower()
                if "key" in name_lower or "token" in name_lower:
                    surfaces["keys"].append(finding)
                else:
                    surfaces["credentials"].append(finding)
            elif category == "hashes":
                surfaces["hashes"].append(finding)
            elif category == "network":
                surfaces["network"].append(finding)
            elif category == "identifiers":
                surfaces["identifiers"].append(finding)
            elif category == "financial":
                surfaces["financial"].append(finding)
            elif category == "crypto":
                surfaces["crypto"].append(finding)
            elif category == "encoded":
                surfaces["encoded"].append(finding)
            else:
                # Default bucket
                surfaces["credentials"].append(finding)

        return surfaces

    def clear_findings(self) -> None:
        """Clear all accumulated findings."""
        self._findings.clear()

    def _analyze_pywhat(self, text: str) -> List[Dict[str, Any]]:
        """Use pyWhat library for identification."""
        results: List[Dict[str, Any]] = []
        try:
            output = self._identifier.identify(text)  # type: ignore[union-attr]
            matches = output.get("Regexes", []) if isinstance(output, dict) else []
            # Handle pywhat's Identifier output format
            if hasattr(output, "Regexes"):
                matches = output.Regexes
            elif isinstance(output, dict):
                matches = output.get("Regexes", output.get("regexes", []))

            for match in matches:
                if isinstance(match, dict):
                    results.append({
                        "name": match.get("Regex Pattern", {}).get("Name", "Unknown"),
                        "value": match.get("Matched", str(match)),
                        "category": self._map_pywhat_category(
                            match.get("Regex Pattern", {}).get("Tags", [])
                        ),
                        "confidence": 0.8,
                    })
        except Exception as exc:
            log.debug(f"pyWhat analysis error: {exc}")
            # Fall back to regex on error
            results = self._analyze_fallback(text)
        return results

    def _analyze_fallback(self, text: str) -> List[Dict[str, Any]]:
        """Use built-in regex patterns for identification."""
        results: List[Dict[str, Any]] = []

        for pattern_info in _FALLBACK_PATTERNS:
            regex = pattern_info["regex"]
            try:
                for match in regex.finditer(text):
                    # Extract the named group 'match' if available
                    try:
                        matched_value = match.group("match")
                    except IndexError:
                        matched_value = match.group(0)

                    if matched_value:
                        results.append({
                            "name": pattern_info["name"],
                            "value": matched_value,
                            "category": pattern_info["category"],
                            "confidence": pattern_info["confidence"],
                        })
            except Exception:
                continue

        return results

    @staticmethod
    def _map_pywhat_category(tags: List[str]) -> str:
        """Map pyWhat tags to our category names."""
        if not tags:
            return "credentials"
        tag_str = " ".join(t.lower() for t in tags)
        if "crypto" in tag_str or "wallet" in tag_str:
            return "crypto"
        if "hash" in tag_str:
            return "hashes"
        if "network" in tag_str or "ip" in tag_str or "url" in tag_str:
            return "network"
        if "email" in tag_str:
            return "identifiers"
        if "credit" in tag_str or "card" in tag_str or "financial" in tag_str:
            return "financial"
        if "key" in tag_str or "token" in tag_str or "password" in tag_str:
            return "credentials"
        return "credentials"


# ---- PyWhatCallback ---------------------------------------------------------


class PyWhatCallback:
    """
    LiveDecryptionSession-compatible callback that routes decrypted
    traffic through PyWhatAnalyzer in real-time.

    Conforms to Callable[[Dict[str, Any]], None] interface expected
    by LiveDecryptionSession's callback parameter.

    Usage:
        analyzer = PyWhatAnalyzer()
        callback = PyWhatCallback(analyzer)
        session = LiveDecryptionSession(callback=callback)

    Can also wrap an existing callback to chain processing:
        callback = PyWhatCallback(analyzer, chain=existing_callback)
    """

    def __init__(
        self,
        analyzer: Optional[PyWhatAnalyzer] = None,
        chain: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        """
        Initialize the pyWhat callback.

        Args:
            analyzer: PyWhatAnalyzer instance (creates one if not provided).
            chain: Optional existing callback to invoke after analysis.
        """
        self._analyzer = analyzer or PyWhatAnalyzer()
        self._chain = chain
        self._event_count = 0
        self._finding_count = 0

    @property
    def analyzer(self) -> PyWhatAnalyzer:
        """Access the underlying PyWhatAnalyzer instance."""
        return self._analyzer

    @property
    def event_count(self) -> int:
        """Number of events processed."""
        return self._event_count

    @property
    def finding_count(self) -> int:
        """Number of findings identified."""
        return self._finding_count

    def __call__(self, event: Dict[str, Any]) -> None:
        """
        Process a decrypted traffic event through pyWhat analysis.

        Args:
            event: Dict with keys: protocol, data, timestamp.
                   Data varies by protocol (dns, http, dhcp, eapol).
        """
        self._event_count += 1

        protocol = event.get("protocol", "")
        data = event.get("data", {})

        # Extract text fields to analyze based on protocol
        texts_to_analyze: List[str] = []

        if protocol == "dns":
            texts_to_analyze.append(data.get("query", ""))
            texts_to_analyze.append(data.get("response", ""))
        elif protocol == "http":
            texts_to_analyze.append(data.get("host", ""))
            texts_to_analyze.append(data.get("uri", ""))
            texts_to_analyze.append(data.get("cookie", ""))
            texts_to_analyze.append(data.get("user_agent", ""))
            texts_to_analyze.append(data.get("authorization", ""))
        elif protocol == "dhcp":
            texts_to_analyze.append(data.get("hostname", ""))
            texts_to_analyze.append(data.get("requested_ip", ""))
            texts_to_analyze.append(data.get("mac_addr", ""))
        elif protocol == "eapol":
            texts_to_analyze.append(data.get("source", ""))
            texts_to_analyze.append(data.get("destination", ""))

        # Analyze each text field
        for text in texts_to_analyze:
            if text:
                findings = self._analyzer.analyze(text)
                if findings:
                    self._finding_count += len(findings)
                    for finding in findings:
                        log.info(
                            f"[PYWHAT] {finding['name']}: "
                            f"{finding['value'][:60]}... "
                            f"(confidence: {finding['confidence']:.0%}, "
                            f"source: {protocol})"
                        )

        # Chain to existing callback if provided
        if self._chain is not None:
            try:
                self._chain(event)
            except Exception as exc:
                log.error(f"Chained callback error: {exc}")
