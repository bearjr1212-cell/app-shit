"""
Nmap Integration
────────────────
Post-connection network scanning for service enumeration,
vulnerability detection, and lateral movement planning.

Used after clients connect to rogue AP to map the local network
and identify high-value targets (POS terminals, printers, servers).
"""

import os
import re
import json
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from typing import Optional, List, Dict, Any

from posframework.config import log
from posframework.tools import is_available, which, run_tool


class NmapScanner:
    """
    Nmap wrapper for network reconnaissance after rogue AP capture.

    Usage:
        scanner = NmapScanner()
        hosts = scanner.quick_scan("10.0.0.0/24")
        details = scanner.service_scan("10.0.0.5")
        vulns = scanner.vuln_scan("10.0.0.5")
    """

    def __init__(self):
        if not is_available("nmap"):
            raise FileNotFoundError(
                "nmap not installed. Install: apt-get install nmap"
            )

    def quick_scan(
        self,
        target: str,
        timeout: int = 60,
    ) -> List[Dict[str, Any]]:
        """
        Fast host discovery scan (-sn ping sweep).

        Args:
            target: IP range (e.g., '10.0.0.0/24', '192.168.1.1-50').
            timeout: Max scan time in seconds.

        Returns:
            List of discovered hosts [{ip, mac, vendor, hostname}].
        """
        xml_file = tempfile.mktemp(suffix=".xml")
        args = ["-sn", "-oX", xml_file, target]

        try:
            run_tool("nmap", args, timeout=timeout)
            return self._parse_xml_hosts(xml_file)
        except subprocess.TimeoutExpired:
            log.warning(f"Quick scan timed out after {timeout}s")
            return self._parse_xml_hosts(xml_file)
        except Exception as e:
            log.error(f"nmap quick scan failed: {e}")
            return []
        finally:
            if os.path.isfile(xml_file):
                os.unlink(xml_file)

    def service_scan(
        self,
        target: str,
        ports: str = "1-1024,3306,5432,6379,8080,8443,9100,631",
        timeout: int = 120,
    ) -> Dict[str, Any]:
        """
        Service version detection scan (-sV).

        Args:
            target: Single IP or hostname.
            ports: Port specification (nmap format).
            timeout: Max scan time.

        Returns:
            Dict with host info and open services.
        """
        xml_file = tempfile.mktemp(suffix=".xml")
        args = [
            "-sV", "--version-intensity", "5",
            "-p", ports,
            "-oX", xml_file,
            target,
        ]

        try:
            run_tool("nmap", args, timeout=timeout)
            return self._parse_xml_services(xml_file)
        except subprocess.TimeoutExpired:
            log.warning("Service scan timed out")
            return self._parse_xml_services(xml_file)
        except Exception as e:
            log.error(f"nmap service scan failed: {e}")
            return {}
        finally:
            if os.path.isfile(xml_file):
                os.unlink(xml_file)

    def os_detect(self, target: str, timeout: int = 90) -> Dict[str, Any]:
        """
        OS detection scan (-O).

        Args:
            target: Single IP.
            timeout: Max scan time.

        Returns:
            Dict with OS guess information.
        """
        xml_file = tempfile.mktemp(suffix=".xml")
        args = ["-O", "--osscan-guess", "-oX", xml_file, target]

        try:
            run_tool("nmap", args, timeout=timeout)
            return self._parse_xml_os(xml_file)
        except Exception as e:
            log.error(f"nmap OS detect failed: {e}")
            return {}
        finally:
            if os.path.isfile(xml_file):
                os.unlink(xml_file)

    def vuln_scan(
        self,
        target: str,
        scripts: str = "vuln,exploit",
        timeout: int = 300,
    ) -> List[Dict[str, str]]:
        """
        Vulnerability scan using NSE scripts.

        Args:
            target: Single IP or range.
            scripts: NSE script categories (comma-separated).
            timeout: Max scan time.

        Returns:
            List of found vulnerabilities [{port, script, output}].
        """
        xml_file = tempfile.mktemp(suffix=".xml")
        args = [
            "--script", scripts,
            "-oX", xml_file,
            target,
        ]

        try:
            run_tool("nmap", args, timeout=timeout)
            return self._parse_xml_vulns(xml_file)
        except subprocess.TimeoutExpired:
            log.warning("Vuln scan timed out")
            return self._parse_xml_vulns(xml_file)
        except Exception as e:
            log.error(f"nmap vuln scan failed: {e}")
            return []
        finally:
            if os.path.isfile(xml_file):
                os.unlink(xml_file)

    def pos_targeted_scan(
        self,
        target: str,
        timeout: int = 180,
    ) -> Dict[str, Any]:
        """
        POS-specific scan targeting payment infrastructure ports and services.

        Scans for: POS terminals, card readers, receipt printers,
        payment gateways, back-office systems.

        Args:
            target: IP range of the rogue AP network.
            timeout: Max scan time.

        Returns:
            Categorized scan results.
        """
        # POS-relevant ports
        pos_ports = ",".join([
            "80", "443", "8080", "8443",       # Web interfaces
            "9100", "515", "631",              # Printers (RAW, LPD, IPP)
            "3306", "5432", "1433", "1521",    # Databases
            "22", "23", "3389",                # Remote access
            "5555", "5900", "5901",            # Android debug, VNC
            "8008", "8009",                     # Payment gateways
            "2000", "4070",                     # POS-specific
            "161", "162",                       # SNMP
            "445", "139",                       # SMB
            "21",                               # FTP
        ])

        xml_file = tempfile.mktemp(suffix=".xml")
        args = [
            "-sV", "--version-intensity", "5",
            "-O", "--osscan-guess",
            "-p", pos_ports,
            "--script", "banner,http-title,ssl-cert,snmp-info",
            "-oX", xml_file,
            target,
        ]

        try:
            run_tool("nmap", args, timeout=timeout)
            results = self._parse_xml_full(xml_file)

            # Categorize findings
            categorized = {
                "pos_terminals": [],
                "printers": [],
                "databases": [],
                "web_interfaces": [],
                "remote_access": [],
                "other": [],
            }

            for host in results.get("hosts", []):
                for service in host.get("services", []):
                    port = service.get("port", 0)
                    if port in (9100, 515, 631):
                        categorized["printers"].append({**service, "ip": host["ip"]})
                    elif port in (3306, 5432, 1433, 1521):
                        categorized["databases"].append({**service, "ip": host["ip"]})
                    elif port in (80, 443, 8080, 8443):
                        categorized["web_interfaces"].append({**service, "ip": host["ip"]})
                    elif port in (22, 23, 3389, 5900, 5901):
                        categorized["remote_access"].append({**service, "ip": host["ip"]})
                    elif port in (2000, 4070, 5555, 8008, 8009):
                        categorized["pos_terminals"].append({**service, "ip": host["ip"]})
                    else:
                        categorized["other"].append({**service, "ip": host["ip"]})

            return categorized

        except Exception as e:
            log.error(f"POS scan failed: {e}")
            return {}
        finally:
            if os.path.isfile(xml_file):
                os.unlink(xml_file)

    # ─── XML Parsers ──────────────────────────────────────────────────────────

    def _parse_xml_hosts(self, xml_file: str) -> List[Dict[str, Any]]:
        """Parse nmap XML for host discovery results."""
        hosts = []
        if not os.path.isfile(xml_file):
            return hosts

        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            for host_elem in root.findall(".//host"):
                status = host_elem.find("status")
                if status is not None and status.get("state") != "up":
                    continue

                host_info = {"ip": None, "mac": None, "vendor": None, "hostname": None}

                for addr in host_elem.findall("address"):
                    if addr.get("addrtype") == "ipv4":
                        host_info["ip"] = addr.get("addr")
                    elif addr.get("addrtype") == "mac":
                        host_info["mac"] = addr.get("addr")
                        host_info["vendor"] = addr.get("vendor", "")

                hostnames = host_elem.find("hostnames")
                if hostnames is not None:
                    hn = hostnames.find("hostname")
                    if hn is not None:
                        host_info["hostname"] = hn.get("name")

                if host_info["ip"]:
                    hosts.append(host_info)

        except ET.ParseError as e:
            log.debug(f"XML parse error: {e}")

        return hosts

    def _parse_xml_services(self, xml_file: str) -> Dict[str, Any]:
        """Parse nmap XML for service detection results."""
        result = {"ip": None, "services": []}
        if not os.path.isfile(xml_file):
            return result

        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            for host_elem in root.findall(".//host"):
                for addr in host_elem.findall("address"):
                    if addr.get("addrtype") == "ipv4":
                        result["ip"] = addr.get("addr")

                ports_elem = host_elem.find("ports")
                if ports_elem is None:
                    continue

                for port_elem in ports_elem.findall("port"):
                    state = port_elem.find("state")
                    if state is None or state.get("state") != "open":
                        continue

                    service_elem = port_elem.find("service")
                    service_info = {
                        "port": int(port_elem.get("portid", 0)),
                        "protocol": port_elem.get("protocol", "tcp"),
                        "service": service_elem.get("name", "") if service_elem is not None else "",
                        "version": service_elem.get("version", "") if service_elem is not None else "",
                        "product": service_elem.get("product", "") if service_elem is not None else "",
                    }
                    result["services"].append(service_info)

        except ET.ParseError:
            pass

        return result

    def _parse_xml_os(self, xml_file: str) -> Dict[str, Any]:
        """Parse nmap XML for OS detection."""
        result = {"os_matches": []}
        if not os.path.isfile(xml_file):
            return result

        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            for host_elem in root.findall(".//host"):
                os_elem = host_elem.find("os")
                if os_elem is None:
                    continue
                for osmatch in os_elem.findall("osmatch"):
                    result["os_matches"].append({
                        "name": osmatch.get("name", ""),
                        "accuracy": int(osmatch.get("accuracy", 0)),
                    })
        except ET.ParseError:
            pass

        return result

    def _parse_xml_vulns(self, xml_file: str) -> List[Dict[str, str]]:
        """Parse nmap XML for vulnerability script output."""
        vulns = []
        if not os.path.isfile(xml_file):
            return vulns

        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            for host_elem in root.findall(".//host"):
                for port_elem in host_elem.findall(".//port"):
                    for script in port_elem.findall("script"):
                        output = script.get("output", "")
                        if "VULNERABLE" in output or "vuln" in script.get("id", ""):
                            vulns.append({
                                "port": port_elem.get("portid", ""),
                                "script": script.get("id", ""),
                                "output": output[:500],
                            })
        except ET.ParseError:
            pass

        return vulns

    def _parse_xml_full(self, xml_file: str) -> Dict[str, Any]:
        """Parse nmap XML into a full structured result."""
        result = {"hosts": []}
        if not os.path.isfile(xml_file):
            return result

        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            for host_elem in root.findall(".//host"):
                host = {"ip": None, "mac": None, "os": None, "services": []}

                for addr in host_elem.findall("address"):
                    if addr.get("addrtype") == "ipv4":
                        host["ip"] = addr.get("addr")
                    elif addr.get("addrtype") == "mac":
                        host["mac"] = addr.get("addr")

                ports_elem = host_elem.find("ports")
                if ports_elem:
                    for port_elem in ports_elem.findall("port"):
                        state = port_elem.find("state")
                        if state is None or state.get("state") != "open":
                            continue
                        svc = port_elem.find("service")
                        host["services"].append({
                            "port": int(port_elem.get("portid", 0)),
                            "service": svc.get("name", "") if svc is not None else "",
                            "version": svc.get("version", "") if svc is not None else "",
                            "product": svc.get("product", "") if svc is not None else "",
                        })

                if host["ip"]:
                    result["hosts"].append(host)

        except ET.ParseError:
            pass

        return result
