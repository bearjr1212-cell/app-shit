"""
Post-Attack Analysis & Next Steps
─────────────────────────────────
Analyzes attack results and provides actionable next steps:
  - Credential analysis
  - Handshake evaluation
  - Network topology mapping
  - Lateral movement recommendations
  - Data exfiltration planning
"""

import time
import json
import os
from collections import defaultdict
from datetime import datetime

from .config import DB_NAME, log


class PostAttackAnalyzer:
    """
    Analyzes attack results and generates next steps.
    Evaluates success metrics, identifies high-value targets,
    and recommends follow-up actions.
    """

    def __init__(self, db):
        self.db = db
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "attack_summary": {},
            "success_metrics": {},
            "recommendations": []
        }

    def analyze_attack(self):
        """Analyze entire attack and generate report."""
        stats = self.db.get_stats()

        self.results["attack_summary"] = {
            "access_points": stats.get("access_points", 0),
            "pos_access_points": stats.get("pos_access_points", 0),
            "clients": stats.get("clients", 0),
            "pos_clients": stats.get("pos_clients", 0),
            "deauth_events": stats.get("deauth_events", 0),
            "eapol_frames": stats.get("eapol_frames", 0),
            "credentials": stats.get("credentials", 0),
            "handshakes": stats.get("eapol_frames", 0) // 4  # Estimate
        }

        self.results["success_metrics"] = self._calculate_success_metrics(stats)
        self.results["recommendations"] = self._generate_recommendations()

        return self.results

    def _calculate_success_metrics(self, stats):
        """Calculate success metrics based on attack results."""
        metrics = {}

        # Credential capture rate
        total_clients = stats.get("clients", 1)
        credentials = stats.get("credentials", 0)
        metrics["credential_capture_rate"] = round(credentials / max(total_clients, 1) * 100, 2)

        # Handshake capture rate (percentage of clients with at least one complete handshake)
        total_clients = stats.get("clients", 1)
        handshakes = stats.get("eapol_frames", 0)
        # A complete 4-way handshake requires 4 EAPOL frames
        complete_handshakes = handshakes // 4
        metrics["handshake_capture_rate"] = min(100.0, round(
            complete_handshakes / max(total_clients, 1) * 100, 2))

        # POS target detection
        pos_aps = stats.get("pos_access_points", 0)
        total_aps = stats.get("access_points", 1)
        metrics["pos_target_percentage"] = round(pos_aps / max(total_aps, 1) * 100, 2)

        # Attack coverage
        metrics["total_targets"] = total_aps + total_clients
        metrics["compromised_targets"] = credentials + (handshakes // 4)

        # Success score (0-100)
        success_score = (
            metrics["credential_capture_rate"] * 0.3 +
            metrics["handshake_capture_rate"] * 0.3 +
            metrics["pos_target_percentage"] * 0.4
        )
        metrics["overall_success_score"] = round(min(success_score, 100), 2)

        return metrics

    def _generate_recommendations(self):
        """Generate actionable next steps based on attack results."""
        recommendations = []

        stats = self.db.get_stats()
        metrics = self._calculate_success_metrics(stats)

        # Credential-based recommendations
        if stats.get("credentials", 0) > 0:
            recommendations.append({
                "priority": "HIGH",
                "category": "credentials",
                "action": "Extract and analyze captured credentials",
                "details": f"{stats['credentials']} credentials captured from {stats['clients']} clients",
                "next_steps": [
                    "Export credentials from database for offline analysis",
                    "Identify high-value accounts (admin, financial, email)",
                    "Test credentials against common services",
                    "Look for credential reuse patterns"
                ]
            })

        # Handshake-based recommendations
        if stats.get("eapol_frames", 0) >= 4:
            recommendations.append({
                "priority": "HIGH",
                "category": "handshakes",
                "action": "Crack WPA handshakes offline",
                "details": f"{stats['eapol_frames'] // 4} complete handshakes captured",
                "next_steps": [
                    "Export handshakes to PCAP format",
                    "Use hashcat or aircrack-ng for cracking",
                    "Use wordlists: rockyou.txt, SecLists, custom wordlists",
                    "Consider cloud cracking services (HashKiller, CrackStation)"
                ]
            })

        # POS-specific recommendations
        if stats.get("pos_access_points", 0) > 0:
            recommendations.append({
                "priority": "CRITICAL",
                "category": "pos",
                "action": "Prioritize POS terminal attacks",
                "details": f"{stats['pos_access_points']} POS APs identified",
                "next_steps": [
                    "Map POS terminal network topology",
                    "Check for payment card data exposure",
                    "Target POS-specific services (credit card processing)",
                    "Look for unpatched vulnerabilities in payment systems"
                ]
            })

        # Network reconnaissance recommendations
        if metrics["pos_target_percentage"] < 50:
            recommendations.append({
                "priority": "MEDIUM",
                "category": "reconnaissance",
                "action": "Expand reconnaissance scope",
                "details": f"Only {metrics['pos_target_percentage']}% targets are POS-related",
                "next_steps": [
                    "Scan for additional POS infrastructure",
                    "Look for wireless controllers and management APs",
                    "Identify network segmentation points",
                    "Map full network topology"
                ]
            })

        # High success score - advanced options
        if metrics["overall_success_score"] >= 70:
            recommendations.append({
                "priority": "HIGH",
                "category": "lateral_movement",
                "action": "Begin lateral movement operations",
                "details": f"Attack success score: {metrics['overall_success_score']}%",
                "next_steps": [
                    "Use captured credentials for internal access",
                    "Exploit SMB/SSH/RDP with cracked passwords",
                    "Move to file servers and workstations",
                    "Target domain controllers if accessible"
                ]
            })

        # Client isolation detected
        if stats.get("isolation_detected", False):
            recommendations.append({
                "priority": "MEDIUM",
                "category": "isolation",
                "action": "Overcome AP isolation",
                "details": "AP isolation detected - client-to-client attacks blocked",
                "next_steps": [
                    "Target AP directly for firmware exploits",
                    "Use rogue AP to intercept traffic",
                    "Attempt ARP poisoning from rogue AP",
                    "Look for wireless client isolation bypass techniques"
                ]
            })

        # General recommendations
        if stats.get("eapol_frames", 0) < 4:
            recommendations.append({
                "priority": "LOW",
                "category": "optimization",
                "action": "Improve handshake capture rate",
                "details": "Handshake capture rate below optimal threshold",
                "next_steps": [
                    "Increase deauth frequency during handshake window",
                    "Position closer to target clients",
                    "Use multiple interfaces for better coverage",
                    "Target reassociation sequences"
                ]
            })

        return recommendations

    def get_next_steps(self, priority_filter=None):
        """Get filtered list of next steps."""
        self.analyze_attack()

        steps = []
        for rec in self.results["recommendations"]:
            if priority_filter is None or rec["priority"] == priority_filter:
                steps.extend(rec["next_steps"])

        return steps

    def generate_report(self, output_file=None):
        """Generate comprehensive attack report."""
        self.analyze_attack()

        report = {
            "title": "POS Attack Post-Mortem Analysis",
            "timestamp": self.results["timestamp"],
            "summary": self.results["attack_summary"],
            "metrics": self.results["success_metrics"],
            "recommendations": self.results["recommendations"]
        }

        # Add top compromised targets
        pos_aps = self.db.get_pos_access_points()
        if pos_aps:
            report["pos_targets"] = [
                {"bssid": ap[0], "ssid": ap[1], "channel": ap[2], "vendor": ap[3]}
                for ap in pos_aps[:10]
            ]

        # Add credential breakdown
        report["unique_users"] = self.db.get_unique_usernames()[:20]

        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            log.info(f"Report saved to {output_file}")

        return report

    def export_credentials(self, output_file="exports/credentials.json"):
        """Export captured credentials to file."""
        os.makedirs("exports", exist_ok=True)

        credentials = self.db.get_credentials_list()

        with open(output_file, 'w') as f:
            json.dump(credentials, f, indent=2)

        log.info(f"Exported {len(credentials)} credentials to {output_file}")
        return credentials

    def export_handshakes(self, output_dir="exports/handshakes"):
        """Export captured handshakes to directory."""
        os.makedirs(output_dir, exist_ok=True)

        bssids = self.db.get_eapol_bssids()

        handshake_info = {
            "total_bssids": len(bssids),
            "handshakes": []
        }

        for bssid in bssids:
            frames = self.db.get_eapol_frames_for_bssid(bssid)

            handshake_info["handshakes"].append({
                "bssid": bssid,
                "client_macs": list(set(f[0] for f in frames)),
                "frame_count": len(frames),
                "complete": len(frames) >= 4
            })

        output_file = os.path.join(output_dir, "handshakes.json")
        with open(output_file, 'w') as f:
            json.dump(handshake_info, f, indent=2)

        log.info(f"Exported handshake info to {output_file}")
        return handshake_info

    def print_summary(self):
        """Print formatted attack summary."""
        self.analyze_attack()

        print("\n" + "=" * 60)
        print("ATTACK SUMMARY")
        print("=" * 60)

        print(f"\nTargets Scanned:")
        print(f"  APs: {self.results['attack_summary']['access_points']} "
              f"({self.results['attack_summary']['pos_access_points']} POS)")
        print(f"  Clients: {self.results['attack_summary']['clients']} "
              f"({self.results['attack_summary']['pos_clients']} POS)")

        print(f"\nAttack Results:")
        print(f"  Credentials: {self.results['attack_summary']['credentials']}")
        print(f"  Handshakes: {self.results['attack_summary']['handshakes']}")
        print(f"  Deauths: {self.results['attack_summary']['deauth_events']}")

        print(f"\nSuccess Metrics:")
        print(f"  Credential Capture Rate: {self.results['success_metrics']['credential_capture_rate']}%")
        print(f"  Handshake Capture Rate: {self.results['success_metrics']['handshake_capture_rate']}%")
        print(f"  POS Target Percentage: {self.results['success_metrics']['pos_target_percentage']}%")
        print(f"  Overall Success Score: {self.results['success_metrics']['overall_success_score']}/100")

        print(f"\nTop Recommendations:")
        for i, rec in enumerate(self.results["recommendations"][:3], 1):
            print(f"  {i}. [{rec['priority']}] {rec['action']}")
            print(f"     {rec['details']}")

        print("=" * 60)


def analyze_post_attack(db_path=None):
    """Quick analysis function."""
    from .database import POSDatabase
    db = POSDatabase(db_path)
    analyzer = PostAttackAnalyzer(db)
    analyzer.print_summary()
    db.close()
    return analyzer.results


if __name__ == "__main__":
    analyze_post_attack()