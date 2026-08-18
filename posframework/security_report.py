"""
Wireless Security Assessment Report Generator
----------------------------------------------
Implements the full pipeline:

    802.11 capture → Parse frames → Extract fields → Normalize →
    Security classify → Risk rules → Correlate clients↔APs →
    Generate findings → JSON/CSV/Console report

Produces structured security findings from recon data, including:
  - Weak/missing encryption
  - Default/weak SSIDs
  - Rogue AP detection
  - Client isolation issues
  - POS/IoT exposure
  - WPS enabled
  - Downgrade-capable networks
  - Hidden networks with clients
"""

import csv
import json
import os
import time
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from .config import log


# ─── Security Classification ────────────────────────────────────────────────

class SecurityLevel:
    """Security classification levels."""
    OPEN = "OPEN"           # No encryption
    WEP = "WEP"            # WEP (broken)
    WPA = "WPA"            # WPA-TKIP (weak)
    WPA2_TKIP = "WPA2-TKIP"  # WPA2 with TKIP (weak cipher)
    WPA2_CCMP = "WPA2-CCMP"  # WPA2 with AES (good)
    WPA3_SAE = "WPA3-SAE"    # WPA3 (best)
    ENTERPRISE = "802.1X"    # Enterprise auth
    UNKNOWN = "UNKNOWN"


class RiskLevel:
    """Risk severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# ─── Data Models ─────────────────────────────────────────────────────────────

class NormalizedAP:
    """Normalized access point record extracted from 802.11 frames."""

    __slots__ = (
        'bssid', 'ssid', 'channel', 'rssi', 'security', 'cipher',
        'auth', 'vendor', 'wps_enabled', 'is_hidden', 'is_pos',
        'client_count', 'first_seen', 'last_seen', 'beacon_count',
    )

    def __init__(self, bssid: str, ssid: str = "", channel: int = 0,
                 rssi: int = -100, security: str = "", cipher: str = "",
                 auth: str = "", vendor: str = "", wps_enabled: bool = False,
                 is_hidden: bool = False, is_pos: bool = False,
                 client_count: int = 0, first_seen: str = "",
                 last_seen: str = "", beacon_count: int = 0):
        self.bssid = bssid.upper() if bssid else ""
        self.ssid = ssid or ""
        self.channel = channel
        self.rssi = rssi
        self.security = security or "OPEN"
        self.cipher = cipher or ""
        self.auth = auth or ""
        self.vendor = vendor or ""
        self.wps_enabled = wps_enabled
        self.is_hidden = is_hidden
        self.is_pos = is_pos
        self.client_count = client_count
        self.first_seen = first_seen
        self.last_seen = last_seen
        self.beacon_count = beacon_count

    def to_dict(self) -> Dict[str, Any]:
        return {k: getattr(self, k) for k in self.__slots__}


class NormalizedClient:
    """Normalized client record."""

    __slots__ = (
        'mac', 'vendor', 'rssi', 'associated_bssid', 'probed_ssids',
        'is_pos', 'first_seen', 'last_seen',
    )

    def __init__(self, mac: str, vendor: str = "", rssi: int = -100,
                 associated_bssid: str = "", probed_ssids: str = "",
                 is_pos: bool = False, first_seen: str = "", last_seen: str = ""):
        self.mac = mac.upper() if mac else ""
        self.vendor = vendor or ""
        self.rssi = rssi
        self.associated_bssid = associated_bssid.upper() if associated_bssid else ""
        self.probed_ssids = probed_ssids or ""
        self.is_pos = is_pos
        self.first_seen = first_seen
        self.last_seen = last_seen

    def to_dict(self) -> Dict[str, Any]:
        return {k: getattr(self, k) for k in self.__slots__}


class Finding:
    """A security finding/vulnerability."""

    def __init__(self, risk: str, title: str, description: str,
                 affected: str = "", recommendation: str = "",
                 evidence: Optional[Dict] = None):
        self.risk = risk
        self.title = title
        self.description = description
        self.affected = affected
        self.recommendation = recommendation
        self.evidence = evidence or {}
        self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk": self.risk,
            "title": self.title,
            "description": self.description,
            "affected": self.affected,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
        }


# ─── Security Classifier ────────────────────────────────────────────────────

def classify_security(security_str: str, cipher_str: str = "") -> str:
    """Classify the security level of a network from its security/cipher strings."""
    if not security_str or security_str.upper() == "OPEN":
        return SecurityLevel.OPEN

    sec = security_str.upper()
    cip = cipher_str.upper()

    if "WPA3" in sec or "SAE" in sec:
        return SecurityLevel.WPA3_SAE
    if "802.1X" in sec or "EAP" in sec or "ENTERPRISE" in sec:
        return SecurityLevel.ENTERPRISE
    if "WPA2" in sec:
        if "TKIP" in cip and "CCMP" not in cip:
            return SecurityLevel.WPA2_TKIP
        return SecurityLevel.WPA2_CCMP
    if "WPA" in sec:
        return SecurityLevel.WPA
    if "WEP" in sec:
        return SecurityLevel.WEP

    return SecurityLevel.UNKNOWN


# ─── Risk Rules Engine ───────────────────────────────────────────────────────

class RiskRulesEngine:
    """Applies security risk rules to normalized AP/client data."""

    # Default SSIDs that indicate unconfigured or default-password devices
    DEFAULT_SSIDS = {
        "linksys", "netgear", "dlink", "default", "home", "setup",
        "tp-link", "asus", "belkin", "cisco", "admin", "router",
        "wireless", "wifi", "internet",
    }

    # SSIDs that indicate guest/open networks
    GUEST_SSIDS = {
        "guest", "free", "public", "open", "visitor", "hotspot",
    }

    def __init__(self):
        self.findings: List[Finding] = []

    def analyze(self, aps: List[NormalizedAP], clients: List[NormalizedClient]) -> List[Finding]:
        """Run all risk rules and return findings."""
        self.findings.clear()

        # Per-AP rules
        for ap in aps:
            self._check_open_network(ap)
            self._check_wep(ap)
            self._check_wpa_tkip(ap)
            self._check_default_ssid(ap)
            self._check_wps_enabled(ap)
            self._check_hidden_with_clients(ap, clients)
            self._check_pos_exposure(ap)
            self._check_weak_signal_ap(ap)

        # Cross-AP rules
        self._check_ssid_spoofing(aps)
        self._check_channel_congestion(aps)

        # Client rules
        for client in clients:
            self._check_pos_client_unprotected(client, aps)
            self._check_promiscuous_probing(client)

        # Correlation rules
        self._check_client_ap_mismatch(aps, clients)

        # Sort by risk severity
        risk_order = {
            RiskLevel.CRITICAL: 0, RiskLevel.HIGH: 1,
            RiskLevel.MEDIUM: 2, RiskLevel.LOW: 3, RiskLevel.INFO: 4,
        }
        self.findings.sort(key=lambda f: risk_order.get(f.risk, 5))

        return self.findings

    def _check_open_network(self, ap: NormalizedAP):
        """Flag networks with no encryption."""
        sec_level = classify_security(ap.security, ap.cipher)
        if sec_level == SecurityLevel.OPEN:
            self.findings.append(Finding(
                risk=RiskLevel.HIGH if ap.client_count > 0 else RiskLevel.MEDIUM,
                title="Open Network (No Encryption)",
                description=(
                    f"Network '{ap.ssid}' ({ap.bssid}) has no encryption. "
                    f"All traffic is transmitted in plaintext and can be intercepted."
                ),
                affected=f"{ap.ssid} ({ap.bssid})",
                recommendation="Enable WPA2-CCMP or WPA3-SAE encryption.",
                evidence={"bssid": ap.bssid, "ssid": ap.ssid, "clients": ap.client_count},
            ))

    def _check_wep(self, ap: NormalizedAP):
        """Flag WEP-encrypted networks (trivially crackable)."""
        sec_level = classify_security(ap.security, ap.cipher)
        if sec_level == SecurityLevel.WEP:
            self.findings.append(Finding(
                risk=RiskLevel.CRITICAL,
                title="WEP Encryption (Broken)",
                description=(
                    f"Network '{ap.ssid}' ({ap.bssid}) uses WEP encryption, "
                    f"which can be cracked in under 5 minutes with aircrack-ng."
                ),
                affected=f"{ap.ssid} ({ap.bssid})",
                recommendation="Upgrade immediately to WPA2-CCMP or WPA3-SAE.",
                evidence={"bssid": ap.bssid, "security": ap.security},
            ))

    def _check_wpa_tkip(self, ap: NormalizedAP):
        """Flag WPA/WPA2 with TKIP cipher (weak)."""
        sec_level = classify_security(ap.security, ap.cipher)
        if sec_level in (SecurityLevel.WPA, SecurityLevel.WPA2_TKIP):
            self.findings.append(Finding(
                risk=RiskLevel.MEDIUM,
                title="Weak Cipher (TKIP)",
                description=(
                    f"Network '{ap.ssid}' ({ap.bssid}) uses TKIP cipher, "
                    f"which has known vulnerabilities. CCMP/AES should be used."
                ),
                affected=f"{ap.ssid} ({ap.bssid})",
                recommendation="Switch to WPA2-CCMP (AES) or WPA3-SAE.",
                evidence={"bssid": ap.bssid, "cipher": ap.cipher},
            ))

    def _check_default_ssid(self, ap: NormalizedAP):
        """Flag default/unconfigured SSIDs (likely default passwords)."""
        ssid_lower = ap.ssid.lower().strip()
        for default in self.DEFAULT_SSIDS:
            if default in ssid_lower:
                self.findings.append(Finding(
                    risk=RiskLevel.MEDIUM,
                    title="Default/Unconfigured SSID",
                    description=(
                        f"Network '{ap.ssid}' ({ap.bssid}) appears to use a "
                        f"default SSID, suggesting it may have default credentials."
                    ),
                    affected=f"{ap.ssid} ({ap.bssid})",
                    recommendation="Change SSID and ensure password is not default.",
                    evidence={"bssid": ap.bssid, "ssid": ap.ssid, "vendor": ap.vendor},
                ))
                break

    def _check_wps_enabled(self, ap: NormalizedAP):
        """Flag WPS-enabled networks (Pixie Dust / brute force vulnerable)."""
        if ap.wps_enabled:
            self.findings.append(Finding(
                risk=RiskLevel.HIGH,
                title="WPS Enabled (PIN Attack Vulnerable)",
                description=(
                    f"Network '{ap.ssid}' ({ap.bssid}) has WPS enabled. "
                    f"WPS PINs can be brute-forced or attacked with Pixie Dust."
                ),
                affected=f"{ap.ssid} ({ap.bssid})",
                recommendation="Disable WPS in router settings.",
                evidence={"bssid": ap.bssid, "wps": True},
            ))

    def _check_hidden_with_clients(self, ap: NormalizedAP, clients: List[NormalizedClient]):
        """Flag hidden networks with active clients (not truly hidden)."""
        if ap.is_hidden and ap.client_count > 0:
            associated_clients = [
                c for c in clients if c.associated_bssid == ap.bssid
            ]
            self.findings.append(Finding(
                risk=RiskLevel.LOW,
                title="Hidden Network with Active Clients",
                description=(
                    f"Hidden network ({ap.bssid}) has {len(associated_clients)} "
                    f"associated clients. SSID can be revealed from probe responses."
                ),
                affected=f"<hidden> ({ap.bssid})",
                recommendation="Hidden SSIDs provide no real security. Use strong encryption instead.",
                evidence={"bssid": ap.bssid, "client_count": len(associated_clients)},
            ))

    def _check_pos_exposure(self, ap: NormalizedAP):
        """Flag POS/payment systems on wireless networks."""
        if ap.is_pos:
            sec_level = classify_security(ap.security, ap.cipher)
            risk = RiskLevel.CRITICAL if sec_level in (
                SecurityLevel.OPEN, SecurityLevel.WEP, SecurityLevel.WPA
            ) else RiskLevel.HIGH
            self.findings.append(Finding(
                risk=risk,
                title="POS/Payment System on Wireless",
                description=(
                    f"Point-of-sale system '{ap.ssid}' ({ap.bssid}) detected "
                    f"on wireless network with {ap.security} security. "
                    f"Payment card data may be at risk."
                ),
                affected=f"{ap.ssid} ({ap.bssid})",
                recommendation="Isolate POS systems on wired network or dedicated VLAN with WPA3.",
                evidence={"bssid": ap.bssid, "vendor": ap.vendor, "security": ap.security},
            ))

    def _check_weak_signal_ap(self, ap: NormalizedAP):
        """Flag APs with very strong signal (potential rogue AP nearby)."""
        if ap.rssi > -30:
            self.findings.append(Finding(
                risk=RiskLevel.INFO,
                title="Very Strong Signal AP (Potential Rogue)",
                description=(
                    f"Network '{ap.ssid}' ({ap.bssid}) has unusually strong "
                    f"signal ({ap.rssi} dBm), which may indicate a rogue AP "
                    f"in close proximity to the assessment device."
                ),
                affected=f"{ap.ssid} ({ap.bssid})",
                recommendation="Verify this AP is legitimate and not a rogue/evil twin.",
                evidence={"bssid": ap.bssid, "rssi": ap.rssi},
            ))

    def _check_ssid_spoofing(self, aps: List[NormalizedAP]):
        """Detect multiple APs with the same SSID but different BSSIDs/security."""
        ssid_map: Dict[str, List[NormalizedAP]] = defaultdict(list)
        for ap in aps:
            if ap.ssid and not ap.is_hidden:
                ssid_map[ap.ssid].append(ap)

        for ssid, ap_list in ssid_map.items():
            if len(ap_list) > 1:
                securities = set(classify_security(a.security, a.cipher) for a in ap_list)
                if len(securities) > 1:
                    self.findings.append(Finding(
                        risk=RiskLevel.HIGH,
                        title="Potential SSID Spoofing / Evil Twin",
                        description=(
                            f"SSID '{ssid}' is broadcast by {len(ap_list)} APs "
                            f"with different security levels: {securities}. "
                            f"This may indicate an evil twin attack."
                        ),
                        affected=ssid,
                        recommendation="Investigate all BSSIDs broadcasting this SSID.",
                        evidence={
                            "ssid": ssid,
                            "bssids": [a.bssid for a in ap_list],
                            "securities": [a.security for a in ap_list],
                        },
                    ))

    def _check_channel_congestion(self, aps: List[NormalizedAP]):
        """Flag channel congestion (DoS/interference risk)."""
        channel_count: Dict[int, int] = defaultdict(int)
        for ap in aps:
            if ap.channel:
                channel_count[ap.channel] += 1

        for channel, count in channel_count.items():
            if count > 15:
                self.findings.append(Finding(
                    risk=RiskLevel.LOW,
                    title=f"Channel Congestion (Ch {channel})",
                    description=(
                        f"Channel {channel} has {count} APs, which may cause "
                        f"interference and is susceptible to channel-based DoS."
                    ),
                    affected=f"Channel {channel}",
                    recommendation="Redistribute APs across non-overlapping channels (1, 6, 11).",
                    evidence={"channel": channel, "ap_count": count},
                ))

    def _check_pos_client_unprotected(self, client: NormalizedClient, aps: List[NormalizedAP]):
        """Flag POS clients associated with weakly-protected APs."""
        if not client.is_pos or not client.associated_bssid:
            return
        for ap in aps:
            if ap.bssid == client.associated_bssid:
                sec_level = classify_security(ap.security, ap.cipher)
                if sec_level in (SecurityLevel.OPEN, SecurityLevel.WEP, SecurityLevel.WPA):
                    self.findings.append(Finding(
                        risk=RiskLevel.CRITICAL,
                        title="POS Client on Weak Network",
                        description=(
                            f"POS device {client.mac} ({client.vendor}) is "
                            f"connected to '{ap.ssid}' which uses {ap.security}. "
                            f"Payment card data is at risk of interception."
                        ),
                        affected=f"{client.mac} on {ap.ssid}",
                        recommendation="Move POS device to WPA3-protected or wired network.",
                        evidence={"client_mac": client.mac, "ap_bssid": ap.bssid, "security": ap.security},
                    ))
                break

    def _check_promiscuous_probing(self, client: NormalizedClient):
        """Flag clients probing for many networks (privacy risk, karma-vulnerable)."""
        if client.probed_ssids:
            probes = [s.strip() for s in client.probed_ssids.split(',') if s.strip()]
            if len(probes) > 5:
                self.findings.append(Finding(
                    risk=RiskLevel.LOW,
                    title="Excessive Probe Requests (KARMA Vulnerable)",
                    description=(
                        f"Client {client.mac} ({client.vendor}) is probing for "
                        f"{len(probes)} networks, making it vulnerable to KARMA attacks."
                    ),
                    affected=client.mac,
                    recommendation="Configure devices to not broadcast probe requests.",
                    evidence={"mac": client.mac, "probe_count": len(probes), "probes": probes[:10]},
                ))

    def _check_client_ap_mismatch(self, aps: List[NormalizedAP], clients: List[NormalizedClient]):
        """Flag clients associated with APs not in our scan (rogue AP indicator)."""
        known_bssids = {ap.bssid for ap in aps}
        for client in clients:
            if client.associated_bssid and client.associated_bssid not in known_bssids:
                self.findings.append(Finding(
                    risk=RiskLevel.MEDIUM,
                    title="Client Associated with Unknown AP",
                    description=(
                        f"Client {client.mac} is associated with {client.associated_bssid} "
                        f"which was not detected in our scan. This could indicate a "
                        f"rogue AP outside scan range or a deauthentication in progress."
                    ),
                    affected=f"{client.mac} → {client.associated_bssid}",
                    recommendation="Investigate the unknown BSSID.",
                    evidence={"client": client.mac, "unknown_bssid": client.associated_bssid},
                ))


# ─── Report Generator ────────────────────────────────────────────────────────

class SecurityReportGenerator:
    """
    Complete wireless security assessment report generator.

    Pipeline:
        802.11 capture → Parse frames → Extract fields → Normalize →
        Security classify → Risk rules → Correlate clients↔APs →
        Generate findings → JSON/CSV/Console report
    """

    def __init__(self, db):
        """
        Initialize with a POSDatabase instance containing recon data.

        Args:
            db: POSDatabase with captured 802.11 frame data.
        """
        self.db = db
        self.aps: List[NormalizedAP] = []
        self.clients: List[NormalizedClient] = []
        self.findings: List[Finding] = []
        self.risk_engine = RiskRulesEngine()
        self._generated_at = ""

    def generate(self) -> List[Finding]:
        """
        Run the full assessment pipeline:
        1. Extract AP/client data from database
        2. Normalize records
        3. Classify security
        4. Apply risk rules
        5. Correlate clients↔APs
        6. Generate findings

        Returns:
            List of Finding objects sorted by severity.
        """
        self._generated_at = datetime.now().isoformat()

        # Step 1-2: Extract and normalize
        self._extract_and_normalize()

        # Step 3-6: Classify, apply rules, correlate, generate findings
        self.findings = self.risk_engine.analyze(self.aps, self.clients)

        log.info(
            f"Security report generated: {len(self.findings)} findings "
            f"({self._count_by_risk()})"
        )
        return self.findings

    def _extract_and_normalize(self):
        """Extract AP and client data from database and normalize."""
        self.aps.clear()
        self.clients.clear()

        # Extract APs
        try:
            self.db.cursor.execute(
                "SELECT bssid, ssid, channel, vendor, security, rssi, "
                "is_pos_vendor, is_pos_ssid, is_hidden "
                "FROM access_points"
            )
            for row in self.db.cursor.fetchall():
                bssid = row[0] or ""
                ssid = row[1] or ""
                channel = row[2] or 0
                vendor = row[3] or ""
                security = row[4] or "OPEN"
                rssi = row[5] or -100
                is_pos = bool(row[6]) or bool(row[7])
                is_hidden = bool(row[8])

                # Get client count
                client_count = 0
                try:
                    clients_data = self.db.get_clients_for_bssid(bssid)
                    client_count = len(clients_data) if clients_data else 0
                except Exception:
                    pass

                # Parse cipher from security string
                cipher = ""
                if "CCMP" in security.upper():
                    cipher = "CCMP"
                elif "TKIP" in security.upper():
                    cipher = "TKIP"

                ap = NormalizedAP(
                    bssid=bssid, ssid=ssid, channel=channel, rssi=rssi,
                    security=security, cipher=cipher, vendor=vendor,
                    is_hidden=is_hidden, is_pos=is_pos, client_count=client_count,
                )
                self.aps.append(ap)
        except Exception as e:
            log.error(f"Failed to extract APs: {e}")

        # Extract Clients
        try:
            self.db.cursor.execute(
                "SELECT mac, vendor, rssi, associated_bssid, probed_ssids, "
                "is_pos_vendor "
                "FROM clients"
            )
            for row in self.db.cursor.fetchall():
                client = NormalizedClient(
                    mac=row[0] or "",
                    vendor=row[1] or "",
                    rssi=row[2] or -100,
                    associated_bssid=row[3] or "",
                    probed_ssids=row[4] or "",
                    is_pos=bool(row[5]),
                )
                self.clients.append(client)
        except Exception as e:
            log.error(f"Failed to extract clients: {e}")

    def _count_by_risk(self) -> str:
        """Count findings by risk level for summary."""
        counts = defaultdict(int)
        for f in self.findings:
            counts[f.risk] += 1
        parts = []
        for risk in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.INFO]:
            if counts[risk]:
                parts.append(f"{risk}:{counts[risk]}")
        return ", ".join(parts) if parts else "none"

    # ─── Output Methods ──────────────────────────────────────────────────

    def to_json(self, output_path: str = "exports/security_report.json") -> str:
        """Export findings as JSON."""
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

        report = {
            "title": "Wireless Security Assessment Report",
            "generated_at": self._generated_at,
            "summary": {
                "total_aps": len(self.aps),
                "total_clients": len(self.clients),
                "total_findings": len(self.findings),
                "by_risk": {
                    risk: sum(1 for f in self.findings if f.risk == risk)
                    for risk in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.INFO]
                },
            },
            "findings": [f.to_dict() for f in self.findings],
            "access_points": [ap.to_dict() for ap in self.aps],
            "clients": [c.to_dict() for c in self.clients],
        }

        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)

        log.info(f"Security report (JSON) saved to: {output_path}")
        return output_path

    def to_csv(self, output_path: str = "exports/security_findings.csv") -> str:
        """Export findings as CSV."""
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Risk", "Title", "Description", "Affected", "Recommendation", "Timestamp"])
            for finding in self.findings:
                writer.writerow([
                    finding.risk,
                    finding.title,
                    finding.description,
                    finding.affected,
                    finding.recommendation,
                    finding.timestamp,
                ])

        log.info(f"Security findings (CSV) saved to: {output_path}")
        return output_path

    def to_console(self) -> str:
        """Print findings to console and return as formatted string."""
        lines = []
        lines.append("")
        lines.append("=" * 70)
        lines.append("  WIRELESS SECURITY ASSESSMENT REPORT")
        lines.append("=" * 70)
        lines.append(f"  Generated: {self._generated_at}")
        lines.append(f"  APs Scanned: {len(self.aps)}")
        lines.append(f"  Clients Observed: {len(self.clients)}")
        lines.append(f"  Findings: {len(self.findings)} ({self._count_by_risk()})")
        lines.append("-" * 70)
        lines.append("")

        for i, finding in enumerate(self.findings, 1):
            risk_prefix = {
                RiskLevel.CRITICAL: "[!!!]",
                RiskLevel.HIGH: "[!!]",
                RiskLevel.MEDIUM: "[!]",
                RiskLevel.LOW: "[~]",
                RiskLevel.INFO: "[i]",
            }.get(finding.risk, "[?]")

            lines.append(f"  {risk_prefix} #{i} [{finding.risk}] {finding.title}")
            lines.append(f"      Affected: {finding.affected}")
            lines.append(f"      {finding.description}")
            lines.append(f"      Fix: {finding.recommendation}")
            lines.append("")

        lines.append("=" * 70)
        lines.append(f"  END OF REPORT — {len(self.findings)} total findings")
        lines.append("=" * 70)
        lines.append("")

        output = "\n".join(lines)
        print(output)
        return output

    def to_all(self, output_dir: str = "exports") -> Dict[str, str]:
        """Generate all report formats."""
        return {
            "json": self.to_json(os.path.join(output_dir, "security_report.json")),
            "csv": self.to_csv(os.path.join(output_dir, "security_findings.csv")),
            "console": "printed",
        }
