"""
Cloud Credential Detection Module
──────────────────────────────────
Detects cloud service credentials in intercepted network traffic:
  - AWS access keys (AKIA pattern) and secret keys
  - GCP service account JSON (private_key_id, client_email)
  - Azure AD tokens (Bearer eyJ with aud/iss claims)
  - Azure storage account keys
  - Generic cloud API tokens and service credentials
  - Confidence scoring for each detection
"""

import re
import time
import json
import base64
import threading
from collections import defaultdict

from scapy.all import IP, TCP, Raw, sniff

from .config import log


class CloudCredentialDetector:
    """
    Cloud credential detection engine.

    Inspects intercepted HTTP traffic for cloud service credentials:
    AWS keys, GCP service accounts, Azure tokens, and other cloud
    provider secrets. Uses regex-based pattern matching with confidence
    scoring to minimize false positives.
    """

    # Confidence levels
    CONFIDENCE_HIGH = "high"
    CONFIDENCE_MEDIUM = "medium"
    CONFIDENCE_LOW = "low"

    def __init__(self, interface):
        self.interface = interface
        self._running = False
        self._thread = None
        self._detections = []
        self._lock = threading.Lock()
        self._seen_keys = set()  # Deduplication
        self._packets_processed = 0

        # Compile detection patterns
        self._patterns = self._compile_patterns()

    def _compile_patterns(self):
        """Compile regex patterns for cloud credential detection."""
        return {
            # AWS Credentials
            "aws_access_key": re.compile(
                r'(?:^|[^A-Z0-9])(AKIA[A-Z0-9]{16})(?:[^A-Z0-9]|$)'
            ),
            "aws_secret_key": re.compile(
                r'(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|SecretAccessKey)'
                r'["\s:=]+([A-Za-z0-9/+=]{40})(?:[^A-Za-z0-9/+=]|$)',
                re.I
            ),
            "aws_session_token": re.compile(
                r'(?:aws_session_token|AWS_SESSION_TOKEN|SessionToken)'
                r'["\s:=]+([A-Za-z0-9/+=]{100,})',
                re.I
            ),
            "aws_arn": re.compile(
                r'(arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:\d{12}:[a-zA-Z0-9\-_/:.]+)'
            ),

            # GCP Credentials
            "gcp_service_account": re.compile(
                r'"type"\s*:\s*"service_account"'
            ),
            "gcp_private_key_id": re.compile(
                r'"private_key_id"\s*:\s*"([a-f0-9]{40})"'
            ),
            "gcp_client_email": re.compile(
                r'"client_email"\s*:\s*"([^"]+@[^"]*\.iam\.gserviceaccount\.com)"'
            ),
            "gcp_api_key": re.compile(
                r'(?:^|[^A-Za-z0-9])(AIza[A-Za-z0-9_-]{35})(?:[^A-Za-z0-9_-]|$)'
            ),

            # Azure Credentials
            "azure_tenant_id": re.compile(
                r'(?:tenant_id|tenantId|AZURE_TENANT_ID)'
                r'["\s:=]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})',
                re.I
            ),
            "azure_client_secret": re.compile(
                r'(?:client_secret|clientSecret|AZURE_CLIENT_SECRET)'
                r'["\s:=]+([A-Za-z0-9~._-]{34,})',
                re.I
            ),
            "azure_storage_key": re.compile(
                r'(?:AccountKey|AZURE_STORAGE_KEY|StorageAccountKey)'
                r'["\s:=]+([A-Za-z0-9+/]{86}==)',
                re.I
            ),
            "azure_connection_string": re.compile(
                r'(DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/]{86}==)',
                re.I
            ),
            "azure_sas_token": re.compile(
                r'(sv=\d{4}-\d{2}-\d{2}&[^"\s]{20,}(?:sig=[A-Za-z0-9%+/=]+))',
                re.I
            ),

            # Generic tokens
            "bearer_jwt": re.compile(
                r'Authorization:\s*Bearer\s+(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
                re.I
            ),
            "private_key_pem": re.compile(
                r'(-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)'
            ),
            "github_token": re.compile(
                r'(?:^|[^A-Za-z0-9_])(gh[ps]_[A-Za-z0-9]{36,})(?:[^A-Za-z0-9_]|$)'
            ),
            "slack_token": re.compile(
                r'(xox[baprs]-[A-Za-z0-9\-]+)'
            ),
        }

    def _decode_jwt_claims(self, token):
        """Decode JWT to extract claims for Azure/cloud token identification."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None
            payload_b64 = parts[1]
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += "=" * padding
            payload_bytes = base64.urlsafe_b64decode(payload_b64)
            return json.loads(payload_bytes)
        except (ValueError, json.JSONDecodeError, Exception):
            return None

    def _classify_jwt_token(self, token):
        """Classify a JWT token as a specific cloud provider token."""
        claims = self._decode_jwt_claims(token)
        if not claims:
            return None, self.CONFIDENCE_LOW

        # Azure AD token indicators
        iss = claims.get("iss", "")
        aud = claims.get("aud", "")
        if "sts.windows.net" in iss or "login.microsoftonline.com" in iss:
            return "azure_ad_token", self.CONFIDENCE_HIGH
        if "management.azure.com" in aud or "graph.microsoft.com" in aud:
            return "azure_ad_token", self.CONFIDENCE_HIGH

        # Google token indicators
        if "accounts.google.com" in iss or "googleapis.com" in aud:
            return "gcp_oauth_token", self.CONFIDENCE_HIGH

        # AWS Cognito
        if "cognito-idp" in iss:
            return "aws_cognito_token", self.CONFIDENCE_HIGH

        # Generic cloud token (has common JWT claims)
        if "sub" in claims and "iat" in claims:
            return "cloud_jwt_token", self.CONFIDENCE_LOW

        return None, self.CONFIDENCE_LOW

    def scan_payload(self, payload, source_ip="unknown", dst_ip="unknown"):
        """
        Scan a payload string for cloud credentials.
        Can be called directly (e.g., from HTTPSInterceptor) or via packet sniffing.

        Returns list of detections found.
        """
        if isinstance(payload, bytes):
            try:
                payload = payload.decode(errors='ignore')
            except Exception:
                return []

        detections = []

        # AWS Access Key
        for match in self._patterns["aws_access_key"].finditer(payload):
            key = match.group(1)
            dedup_key = f"aws_access:{key}"
            if dedup_key not in self._seen_keys:
                self._seen_keys.add(dedup_key)
                detection = self._create_detection(
                    "aws_access_key", key, self.CONFIDENCE_HIGH,
                    source_ip, dst_ip, "AWS Access Key ID (AKIA...)"
                )
                detections.append(detection)

        # AWS Secret Key
        for match in self._patterns["aws_secret_key"].finditer(payload):
            key = match.group(1)
            dedup_key = f"aws_secret:{key[:16]}"
            if dedup_key not in self._seen_keys:
                self._seen_keys.add(dedup_key)
                detection = self._create_detection(
                    "aws_secret_key", key, self.CONFIDENCE_HIGH,
                    source_ip, dst_ip, "AWS Secret Access Key"
                )
                detections.append(detection)

        # AWS Session Token
        for match in self._patterns["aws_session_token"].finditer(payload):
            token = match.group(1)
            dedup_key = f"aws_session:{token[:32]}"
            if dedup_key not in self._seen_keys:
                self._seen_keys.add(dedup_key)
                detection = self._create_detection(
                    "aws_session_token", token[:64] + "...",
                    self.CONFIDENCE_MEDIUM, source_ip, dst_ip,
                    "AWS Session Token"
                )
                detections.append(detection)

        # GCP Service Account JSON
        if self._patterns["gcp_service_account"].search(payload):
            email_match = self._patterns["gcp_client_email"].search(payload)
            key_id_match = self._patterns["gcp_private_key_id"].search(payload)
            if email_match:
                email = email_match.group(1)
                dedup_key = f"gcp_sa:{email}"
                if dedup_key not in self._seen_keys:
                    self._seen_keys.add(dedup_key)
                    detection = self._create_detection(
                        "gcp_service_account", email, self.CONFIDENCE_HIGH,
                        source_ip, dst_ip,
                        f"GCP Service Account (key_id={key_id_match.group(1)[:8] if key_id_match else 'unknown'}...)"
                    )
                    detections.append(detection)

        # GCP API Key
        for match in self._patterns["gcp_api_key"].finditer(payload):
            key = match.group(1)
            dedup_key = f"gcp_api:{key}"
            if dedup_key not in self._seen_keys:
                self._seen_keys.add(dedup_key)
                detection = self._create_detection(
                    "gcp_api_key", key, self.CONFIDENCE_MEDIUM,
                    source_ip, dst_ip, "GCP API Key (AIza...)"
                )
                detections.append(detection)

        # Azure Storage Key
        for match in self._patterns["azure_storage_key"].finditer(payload):
            key = match.group(1)
            dedup_key = f"azure_storage:{key[:16]}"
            if dedup_key not in self._seen_keys:
                self._seen_keys.add(dedup_key)
                detection = self._create_detection(
                    "azure_storage_key", key[:32] + "...",
                    self.CONFIDENCE_HIGH, source_ip, dst_ip,
                    "Azure Storage Account Key"
                )
                detections.append(detection)

        # Azure Connection String
        for match in self._patterns["azure_connection_string"].finditer(payload):
            conn_str = match.group(1)
            dedup_key = f"azure_conn:{conn_str[:32]}"
            if dedup_key not in self._seen_keys:
                self._seen_keys.add(dedup_key)
                detection = self._create_detection(
                    "azure_connection_string", conn_str[:64] + "...",
                    self.CONFIDENCE_HIGH, source_ip, dst_ip,
                    "Azure Storage Connection String"
                )
                detections.append(detection)

        # Azure Client Secret
        for match in self._patterns["azure_client_secret"].finditer(payload):
            secret = match.group(1)
            dedup_key = f"azure_secret:{secret[:16]}"
            if dedup_key not in self._seen_keys:
                self._seen_keys.add(dedup_key)
                detection = self._create_detection(
                    "azure_client_secret", secret[:16] + "...",
                    self.CONFIDENCE_MEDIUM, source_ip, dst_ip,
                    "Azure Client Secret"
                )
                detections.append(detection)

        # Azure SAS Token
        for match in self._patterns["azure_sas_token"].finditer(payload):
            sas = match.group(1)
            dedup_key = f"azure_sas:{sas[:32]}"
            if dedup_key not in self._seen_keys:
                self._seen_keys.add(dedup_key)
                detection = self._create_detection(
                    "azure_sas_token", sas[:64] + "...",
                    self.CONFIDENCE_HIGH, source_ip, dst_ip,
                    "Azure SAS Token"
                )
                detections.append(detection)

        # Bearer JWT tokens (classify as cloud provider)
        for match in self._patterns["bearer_jwt"].finditer(payload):
            token = match.group(1)
            provider, confidence = self._classify_jwt_token(token)
            if provider:
                dedup_key = f"jwt:{token[:32]}"
                if dedup_key not in self._seen_keys:
                    self._seen_keys.add(dedup_key)
                    detection = self._create_detection(
                        provider, token[:64] + "...", confidence,
                        source_ip, dst_ip,
                        f"Cloud JWT Token ({provider})"
                    )
                    detections.append(detection)

        # Private Key PEM
        if self._patterns["private_key_pem"].search(payload):
            dedup_key = f"pem:{hash(payload[:200])}"
            if dedup_key not in self._seen_keys:
                self._seen_keys.add(dedup_key)
                detection = self._create_detection(
                    "private_key_pem", "[PEM PRIVATE KEY]",
                    self.CONFIDENCE_HIGH, source_ip, dst_ip,
                    "Private Key in PEM format"
                )
                detections.append(detection)

        # GitHub tokens
        for match in self._patterns["github_token"].finditer(payload):
            token = match.group(1)
            dedup_key = f"github:{token[:16]}"
            if dedup_key not in self._seen_keys:
                self._seen_keys.add(dedup_key)
                detection = self._create_detection(
                    "github_token", token[:16] + "...",
                    self.CONFIDENCE_HIGH, source_ip, dst_ip,
                    "GitHub Personal Access Token"
                )
                detections.append(detection)

        # Slack tokens
        for match in self._patterns["slack_token"].finditer(payload):
            token = match.group(1)
            dedup_key = f"slack:{token[:16]}"
            if dedup_key not in self._seen_keys:
                self._seen_keys.add(dedup_key)
                detection = self._create_detection(
                    "slack_token", token[:16] + "...",
                    self.CONFIDENCE_HIGH, source_ip, dst_ip,
                    "Slack API Token"
                )
                detections.append(detection)

        # Store detections
        if detections:
            with self._lock:
                self._detections.extend(detections)

        return detections

    def _create_detection(self, cred_type, value, confidence, source_ip, dst_ip, description):
        """Create a detection record."""
        detection = {
            "type": cred_type,
            "value": value,
            "confidence": confidence,
            "source_ip": source_ip,
            "dst_ip": dst_ip,
            "description": description,
            "timestamp": time.time(),
        }
        log.critical(
            f"CLOUD CREDENTIAL DETECTED: [{cred_type}] "
            f"confidence={confidence} from {source_ip} "
            f"- {description}"
        )
        return detection

    def _packet_handler(self, pkt):
        """Process packets for cloud credential detection."""
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return

        self._packets_processed += 1
        try:
            payload = bytes(pkt[Raw].load)
            src_ip = pkt[IP].src if pkt.haslayer(IP) else "unknown"
            dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "unknown"
            self.scan_payload(payload, src_ip, dst_ip)
        except Exception as e:
            log.debug(f"Cloud cred detection packet error: {e}")

    def _sniff_loop(self):
        """Background sniffing thread."""
        try:
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                store=False,
                filter="tcp port 80 or tcp port 443 or tcp port 8080 or tcp port 8443",
                stop_filter=lambda x: not self._running
            )
        except Exception as e:
            log.error(f"Cloud credential detector sniff error: {e}")

    def start(self):
        """Start cloud credential detection."""
        if self._running:
            log.warning("Cloud credential detector already running")
            return False

        self._running = True
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()
        log.info(f"Cloud credential detector started on {self.interface}")
        return True

    def stop(self):
        """Stop cloud credential detection."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        log.info(f"Cloud credential detector stopped. {len(self._detections)} detections")

    def get_detections(self):
        """Return all cloud credential detections."""
        with self._lock:
            return list(self._detections)

    def get_high_confidence(self):
        """Return only high-confidence detections."""
        with self._lock:
            return [d for d in self._detections if d["confidence"] == self.CONFIDENCE_HIGH]

    def get_detections_by_provider(self, provider):
        """Return detections for a specific provider (aws, azure, gcp)."""
        with self._lock:
            return [d for d in self._detections if provider in d["type"]]

    def get_stats(self):
        """Return detection statistics."""
        with self._lock:
            by_type = defaultdict(int)
            by_confidence = defaultdict(int)
            for d in self._detections:
                by_type[d["type"]] += 1
                by_confidence[d["confidence"]] += 1

            return {
                "running": self._running,
                "total_detections": len(self._detections),
                "unique_keys": len(self._seen_keys),
                "packets_processed": self._packets_processed,
                "by_type": dict(by_type),
                "by_confidence": dict(by_confidence),
            }
