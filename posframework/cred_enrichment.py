"""
Credential Enrichment
---------------------
Wraps captured credentials with rich metadata:
  - source_url: URL or service where credential was captured
  - target_service: protocol://host:port
  - timestamp: ISO-8601 capture time
  - client_mac: source device MAC address
  - client_hostname: resolved hostname (from mDNS/DHCP)
  - confidence_score: 0.0-1.0 based on capture method reliability
  - capture_method: how the credential was obtained
  - associated_bssid: AP BSSID the client was connected to

Integrates with POSDatabase to persist enriched credentials.
"""

import time
from datetime import datetime

from .config import log


# Confidence scores based on capture method reliability
CONFIDENCE_SCORES = {
    "http_form": 0.95,
    "http_basic": 0.90,
    "ftp_cleartext": 0.95,
    "smtp_auth": 0.85,
    "imap_login": 0.85,
    "pop3_pass": 0.85,
    "ntlm_hash": 0.70,
    "kerberos_ticket": 0.65,
    "ldap_bind": 0.90,
    "wifi_handshake": 0.60,
    "wifi_pmkid": 0.55,
    "captive_portal": 0.90,
    "session_cookie": 0.75,
    "api_key": 0.80,
    "cloud_credential": 0.85,
    "browser_autofill": 0.92,
    "unknown": 0.50,
}


class CredentialEnrichment:
    """
    Enrich captured credentials with contextual metadata.

    Takes raw credential dictionaries and adds source tracking,
    confidence scoring, client identification, and network context.
    """

    def __init__(self, db=None):
        self.db = db
        self._hostname_cache = {}  # mac -> hostname mapping from mDNS/DHCP
        self._enriched_count = 0

    def register_hostname(self, mac, hostname):
        """
        Register a hostname discovered via mDNS or DHCP for a client MAC.

        Args:
            mac: Client MAC address (lowercase, colon-separated)
            hostname: Discovered hostname string
        """
        if mac and hostname:
            self._hostname_cache[mac.lower()] = hostname

    def enrich(self, credential_dict):
        """
        Enrich a credential dictionary with metadata fields.

        Args:
            credential_dict: Dict with at minimum 'username' and 'password' keys.
                Optional keys: 'client_mac', 'url', 'protocol', 'host', 'port',
                'bssid', 'capture_method'

        Returns:
            Enriched credential dictionary with all metadata fields added.
        """
        enriched = dict(credential_dict)

        # Timestamp
        enriched.setdefault("timestamp", datetime.now().isoformat(timespec='seconds'))

        # Source URL
        url = credential_dict.get("url", "")
        host = credential_dict.get("host", "")
        port = credential_dict.get("port", "")
        protocol = credential_dict.get("protocol", "")
        if not url and host:
            url = f"{protocol}://{host}:{port}" if port else f"{protocol}://{host}"
        enriched["source_url"] = url

        # Target service
        if host and port and protocol:
            enriched["target_service"] = f"{protocol}://{host}:{port}"
        elif url:
            enriched["target_service"] = url
        else:
            enriched["target_service"] = ""

        # Client MAC
        client_mac = credential_dict.get("client_mac", "").lower()
        enriched["client_mac"] = client_mac

        # Client hostname from cache
        hostname = ""
        if client_mac:
            hostname = self._hostname_cache.get(client_mac, "")
        enriched["client_hostname"] = credential_dict.get("client_hostname", hostname)

        # Confidence score based on capture method
        capture_method = credential_dict.get("capture_method", "unknown")
        enriched["capture_method"] = capture_method
        base_confidence = CONFIDENCE_SCORES.get(capture_method, 0.50)

        # Adjust confidence based on credential quality
        password = credential_dict.get("password", "")
        if password and len(password) >= 8:
            base_confidence = min(1.0, base_confidence + 0.05)
        if credential_dict.get("validated", False):
            base_confidence = min(1.0, base_confidence + 0.10)

        enriched["confidence_score"] = round(base_confidence, 2)

        # Associated BSSID
        enriched["associated_bssid"] = credential_dict.get("bssid", "")

        self._enriched_count += 1

        # Persist to database if available
        if self.db:
            self._store_enriched(enriched)

        log.info(f"Credential enriched: {enriched.get('username', 'N/A')} "
                 f"[confidence={enriched['confidence_score']}] "
                 f"via {capture_method}")

        return enriched

    def _store_enriched(self, enriched):
        """Store enriched credential in database."""
        try:
            self.db.store_enriched_credential(
                username=enriched.get("username", ""),
                password=enriched.get("password", ""),
                source_url=enriched.get("source_url", ""),
                target_service=enriched.get("target_service", ""),
                timestamp=enriched.get("timestamp", ""),
                client_mac=enriched.get("client_mac", ""),
                client_hostname=enriched.get("client_hostname", ""),
                confidence_score=enriched.get("confidence_score", 0.5),
                capture_method=enriched.get("capture_method", "unknown"),
                associated_bssid=enriched.get("associated_bssid", ""),
            )
        except Exception as e:
            log.error(f"Failed to store enriched credential: {e}")

    def get_stats(self):
        """Return enrichment statistics."""
        return {
            "enriched_count": self._enriched_count,
            "known_hostnames": len(self._hostname_cache),
        }
