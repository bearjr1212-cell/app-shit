"""
Hashcat Integration
───────────────────
GPU-accelerated password cracking for WPA/WPA2 handshakes,
PMKID hashes, and other captured credentials.

Supports:
  - WPA/WPA2 handshake cracking (mode 22000 / 2500)
  - PMKID cracking (mode 22000)
  - Dictionary attack with rules
  - Brute-force with masks
  - Combination attacks
  - Status monitoring and progress tracking
"""

import os
import re
import time
import signal
import subprocess
import tempfile
from typing import Optional, List, Dict
from pathlib import Path

from posframework.config import log
from posframework.tools import is_available, which, run_tool


# ─── Hashcat Hash Modes ───────────────────────────────────────────────────────

HASH_MODES = {
    "wpa_pmkid": 22000,       # WPA-PBKDF2-PMKID+EAPOL (modern)
    "wpa_eapol": 22000,       # Same mode handles both PMKID and EAPOL
    "wpa_legacy": 2500,       # Legacy .hccapx format
    "md5": 0,
    "sha1": 100,
    "sha256": 1400,
    "ntlm": 1000,
    "mysql": 300,
    "wpa_enterprise": 5500,   # NetNTLMv1 (captured via MITM)
    "mschapv2": 5600,         # NetNTLMv2
}

# Common rule files
RULES = {
    "best64": "best64.rule",
    "rockyou": "rockyou-30000.rule",
    "dive": "dive.rule",
    "oneruletorulethemall": "OneRuleToRuleThemAll.rule",
    "toggles": "toggles1.rule",
}

# Common masks for WiFi passwords (8-63 chars)
WIFI_MASKS = {
    "8digit": "?d?d?d?d?d?d?d?d",
    "10digit": "?d?d?d?d?d?d?d?d?d?d",
    "8lower": "?l?l?l?l?l?l?l?l",
    "word+digits": "?l?l?l?l?l?d?d?d",
    "upper+lower+digits_8": "?1?1?1?1?1?1?1?1",  # custom charset needed
    "phone_us": "?d?d?d?d?d?d?d?d?d?d",
}


class HashcatCracker:
    """
    GPU-accelerated password cracking via hashcat.

    Usage:
        cracker = HashcatCracker()
        result = cracker.crack_wpa("handshake.22000",
                                    wordlist="/usr/share/wordlists/rockyou.txt")
        if result:
            print(f"Password: {result}")
    """

    def __init__(self):
        if not is_available("hashcat"):
            raise FileNotFoundError(
                "hashcat not installed. Install: apt-get install hashcat"
            )
        self._proc: Optional[subprocess.Popen] = None
        self._potfile = os.path.expanduser("~/.local/share/hashcat/hashcat.potfile")

    @property
    def available_devices(self) -> str:
        """List available cracking devices (GPU/CPU)."""
        try:
            result = run_tool("hashcat", ["-I"], timeout=10)
            return result.stdout
        except Exception:
            return "Unable to query devices"

    def crack_wpa(
        self,
        hash_file: str,
        wordlist: Optional[str] = None,
        mask: Optional[str] = None,
        rules: Optional[str] = None,
        timeout: Optional[int] = None,
        workload: int = 3,
        force_cpu: bool = False,
    ) -> Optional[str]:
        """
        Crack WPA/WPA2 hash (PMKID or EAPOL handshake in mode 22000 format).

        Args:
            hash_file: Path to .22000 hash file (from hcxpcapngtool).
            wordlist: Path to wordlist (for dictionary attack).
            mask: Hashcat mask (for brute-force, e.g., '?d?d?d?d?d?d?d?d').
            rules: Rule file name or path (applied to wordlist).
            timeout: Max runtime in seconds.
            workload: Hashcat workload profile (1=low, 2=default, 3=high, 4=nightmare).
            force_cpu: Force CPU-only cracking (no GPU).

        Returns:
            Cracked password, or None if not found.
        """
        if not os.path.isfile(hash_file):
            log.error(f"Hash file not found: {hash_file}")
            return None

        args = [
            "-m", str(HASH_MODES["wpa_pmkid"]),
            "-w", str(workload),
            "--quiet",
            "--potfile-disable",  # Don't save to potfile (we parse output)
        ]

        if force_cpu:
            args.extend(["-D", "1"])  # Device type 1 = CPU

        # Attack mode
        if wordlist and mask:
            # Hybrid: wordlist + mask
            args.extend(["-a", "6", hash_file, wordlist, mask])
        elif mask:
            # Brute-force with mask
            args.extend(["-a", "3", hash_file, mask])
        elif wordlist:
            # Dictionary attack
            args.extend(["-a", "0"])
            if rules:
                rule_path = self._resolve_rule(rules)
                if rule_path:
                    args.extend(["-r", rule_path])
            args.extend([hash_file, wordlist])
        else:
            log.error("Must specify wordlist or mask")
            return None

        # Output file for cracked passwords
        outfile = tempfile.mktemp(suffix=".cracked")
        args.extend(["-o", outfile])

        log.info(f"hashcat: cracking {Path(hash_file).name} "
                 f"({'mask=' + mask if mask else 'wordlist=' + Path(wordlist).name if wordlist else ''})")

        try:
            result = run_tool("hashcat", args, timeout=timeout)

            # Check output file for cracked password
            if os.path.isfile(outfile):
                with open(outfile, "r") as f:
                    content = f.read().strip()
                os.unlink(outfile)
                if content:
                    # Format: hash:password
                    parts = content.split(":")
                    if len(parts) >= 2:
                        password = parts[-1]
                        log.critical(f"CRACKED: {password}")
                        return password

            # Also check stdout for status
            output = result.stdout + result.stderr
            if "Cracked" in output:
                crack_match = re.search(r":(.+)$", output, re.MULTILINE)
                if crack_match:
                    return crack_match.group(1)

        except subprocess.TimeoutExpired:
            log.info(f"hashcat timed out after {timeout}s")
        except Exception as e:
            log.error(f"hashcat error: {e}")
        finally:
            if os.path.isfile(outfile):
                os.unlink(outfile)

        return None

    def crack_mask_incremental(
        self,
        hash_file: str,
        min_len: int = 8,
        max_len: int = 12,
        charset: str = "?d",
        timeout_per_len: int = 300,
    ) -> Optional[str]:
        """
        Incremental brute-force from min_len to max_len.

        Args:
            hash_file: Path to hash file.
            min_len: Minimum password length (default: 8 for WPA).
            max_len: Maximum length to try.
            charset: Hashcat charset to use (?d=digits, ?l=lower, ?a=all).
            timeout_per_len: Timeout per length attempt.

        Returns:
            Cracked password or None.
        """
        for length in range(min_len, max_len + 1):
            mask = charset * length
            log.info(f"hashcat: trying length {length} ({charset}×{length})")
            result = self.crack_wpa(
                hash_file, mask=mask, timeout=timeout_per_len
            )
            if result:
                return result
        return None

    def benchmark(self) -> Dict[str, float]:
        """
        Run hashcat benchmark for WPA mode.

        Returns:
            Dict with benchmark results (speed in H/s).
        """
        try:
            result = run_tool(
                "hashcat", ["-m", "22000", "-b", "--quiet"], timeout=60
            )
            output = result.stdout
            speed_match = re.search(r"Speed\.#\*.*?:\s+([\d.]+)\s*(\w+)", output)
            if speed_match:
                speed = float(speed_match.group(1))
                unit = speed_match.group(2)
                return {"speed": speed, "unit": unit, "raw_output": output}
        except Exception as e:
            log.error(f"hashcat benchmark failed: {e}")
        return {}

    def _resolve_rule(self, rule_name: str) -> Optional[str]:
        """Resolve a rule name to its full path."""
        if os.path.isfile(rule_name):
            return rule_name

        # Check common locations
        search_paths = [
            "/usr/share/hashcat/rules",
            "/usr/local/share/hashcat/rules",
            os.path.expanduser("~/.hashcat/rules"),
        ]
        # Also try registry name
        filename = RULES.get(rule_name, rule_name)
        if not filename.endswith(".rule"):
            filename += ".rule"

        for base in search_paths:
            full = os.path.join(base, filename)
            if os.path.isfile(full):
                return full

        log.warning(f"Rule file not found: {rule_name}")
        return None


# ─── Conversion Utilities ─────────────────────────────────────────────────────

def cap_to_22000(capture_file: str, output_file: Optional[str] = None) -> Optional[str]:
    """
    Convert .cap/.pcap to hashcat 22000 format using hcxpcapngtool.

    Args:
        capture_file: Input .cap or .pcap file.
        output_file: Output .22000 file (auto-generated if None).

    Returns:
        Path to the .22000 file, or None on failure.
    """
    if not is_available("hcxpcapngtool"):
        # Fallback: try aircrack-ng's hccapx conversion path
        log.warning("hcxpcapngtool not available, cannot convert to 22000 format")
        return None

    if output_file is None:
        output_file = capture_file.rsplit(".", 1)[0] + ".22000"

    try:
        result = run_tool(
            "hcxpcapngtool",
            ["-o", output_file, capture_file],
            timeout=30,
        )
        if os.path.isfile(output_file) and os.path.getsize(output_file) > 0:
            log.info(f"Converted to hashcat format: {output_file}")
            return output_file
        else:
            log.warning("hcxpcapngtool produced empty output (no valid handshake/PMKID)")
    except Exception as e:
        log.error(f"hcxpcapngtool conversion failed: {e}")

    return None
