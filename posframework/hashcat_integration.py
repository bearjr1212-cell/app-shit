"""
Hashcat Integration for WPA Cracking
-------------------------------------
Manages hashcat subprocess for cracking WPA handshakes:
  - Detects hashcat binary path
  - Supports mode 2500 (hccapx) and 22000 (modern PMKID/EAPOL)
  - Parses stdout for speed, progress, recovered passwords
  - Imports cracked passwords back into the database
  - Supports wordlist and rule-based attacks
"""

import os
import re
import time
import shutil
import subprocess
import threading

from .config import log


class HashcatIntegration:
    """
    Manage hashcat for WPA/WPA2 handshake cracking.

    Automatically detects hashcat, starts cracking jobs with appropriate
    modes, monitors progress, and imports results into the database.
    """

    def __init__(self, hashcat_path=None, workdir="/tmp/hashcat_work"):
        self._hashcat_path = hashcat_path or self._detect_hashcat()
        self._workdir = workdir
        self._process = None
        self._running = False
        self._monitor_thread = None
        self._lock = threading.Lock()

        # Progress tracking
        self._progress = {
            "status": "idle",
            "speed": "",
            "progress_pct": 0.0,
            "recovered": 0,
            "total_hashes": 0,
            "elapsed": "",
            "estimated_remaining": "",
        }

        # Cracked passwords
        self._cracked = []

        # Output file for cracked results
        self._outfile = None

        # Ensure workdir exists
        os.makedirs(workdir, exist_ok=True)

    def _detect_hashcat(self):
        """Detect hashcat binary path."""
        # Try common locations
        paths_to_check = [
            "hashcat",
            "/usr/bin/hashcat",
            "/usr/local/bin/hashcat",
            "/opt/hashcat/hashcat",
            os.path.expanduser("~/hashcat/hashcat"),
        ]

        for path in paths_to_check:
            found = shutil.which(path)
            if found:
                log.info(f"Hashcat found at: {found}")
                return found

        # Try to find via which
        result = shutil.which("hashcat")
        if result:
            return result

        log.warning("Hashcat binary not found - cracking will not be available")
        return None

    def _detect_hash_mode(self, handshake_file):
        """
        Detect appropriate hashcat mode based on file extension.

        Returns:
            Integer hash mode (2500 for hccapx, 22000 for modern format)
        """
        ext = os.path.splitext(handshake_file)[1].lower()
        if ext == ".hccapx":
            return 2500
        elif ext in (".22000", ".hc22000"):
            return 22000
        elif ext == ".pcap" or ext == ".cap":
            # Default to modern format for pcap (needs conversion)
            return 22000
        else:
            return 22000  # Default to modern format

    def start_crack(self, handshake_file, wordlist, rules=None,
                    hash_mode=None, extra_args=None):
        """
        Start hashcat cracking job.

        Args:
            handshake_file: Path to .hccapx or .22000 file
            wordlist: Path to wordlist file
            rules: Optional path to rules file (e.g., best64.rule)
            hash_mode: Override hash mode (auto-detected from extension)
            extra_args: Additional hashcat arguments as list

        Returns:
            True if hashcat started successfully, False otherwise
        """
        if not self._hashcat_path:
            log.error("Hashcat not available")
            return False

        if not os.path.isfile(handshake_file):
            log.error(f"Handshake file not found: {handshake_file}")
            return False

        if not os.path.isfile(wordlist):
            log.error(f"Wordlist not found: {wordlist}")
            return False

        if self._running:
            log.warning("Hashcat already running, stop first")
            return False

        # Detect mode
        mode = hash_mode or self._detect_hash_mode(handshake_file)

        # Output file for cracked passwords
        self._outfile = os.path.join(
            self._workdir, f"cracked_{int(time.time())}.txt"
        )

        # Build command
        cmd = [
            self._hashcat_path,
            "-m", str(mode),
            "-a", "0",  # Wordlist attack
            "--status",
            "--status-timer", "5",
            "--machine-readable",
            "-o", self._outfile,
            "--outfile-format", "2",  # plain password only
            handshake_file,
            wordlist,
        ]

        if rules and os.path.isfile(rules):
            cmd.extend(["-r", rules])

        if extra_args:
            cmd.extend(extra_args)

        log.info(f"Starting hashcat: mode={mode}, wordlist={wordlist}")
        log.debug(f"Hashcat command: {' '.join(cmd)}")

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
        except (OSError, FileNotFoundError) as e:
            log.error(f"Failed to start hashcat: {e}")
            return False

        self._running = True
        self._progress["status"] = "running"

        # Start monitor thread
        self._monitor_thread = threading.Thread(
            target=self._monitor_output, daemon=True, name="hashcat-monitor"
        )
        self._monitor_thread.start()

        return True

    def _monitor_output(self):
        """Monitor hashcat stdout for progress updates and results."""
        try:
            while self._running and self._process:
                line = self._process.stdout.readline()
                if not line:
                    if self._process.poll() is not None:
                        break
                    continue

                line = line.strip()
                self._parse_status_line(line)

        except Exception as e:
            log.debug(f"Hashcat monitor error: {e}")

        # Process finished
        with self._lock:
            returncode = self._process.poll() if self._process else -1
            if returncode == 0:
                self._progress["status"] = "cracked"
            elif returncode == 1:
                self._progress["status"] = "exhausted"
            else:
                self._progress["status"] = "finished"

        # Import any cracked passwords
        self._import_outfile()
        self._running = False

    def _parse_status_line(self, line):
        """Parse hashcat status output line."""
        with self._lock:
            # Speed line: "Speed.#1.........: 500.0 kH/s"
            speed_match = re.search(r'Speed[^:]*:\s*(.+)', line)
            if speed_match:
                self._progress["speed"] = speed_match.group(1).strip()

            # Progress line: "Progress.........: 1234567/9999999 (12.35%)"
            prog_match = re.search(r'Progress[^:]*:\s*\d+/\d+\s*\((\d+\.?\d*)%\)', line)
            if prog_match:
                self._progress["progress_pct"] = float(prog_match.group(1))

            # Recovered line: "Recovered........: 1/1 (100.00%)"
            rec_match = re.search(r'Recovered[^:]*:\s*(\d+)/(\d+)', line)
            if rec_match:
                self._progress["recovered"] = int(rec_match.group(1))
                self._progress["total_hashes"] = int(rec_match.group(2))

            # Time estimated: "Time.Estimated...: Thu Jan 01 00:05:00 2024 (0 secs)"
            time_match = re.search(r'Time\.Estimated[^:]*:\s*(.+)', line)
            if time_match:
                self._progress["estimated_remaining"] = time_match.group(1).strip()

            # Machine-readable status (STATUS lines)
            if line.startswith("STATUS"):
                parts = line.split("\t")
                if len(parts) >= 2:
                    status_code = parts[1] if len(parts) > 1 else ""
                    if status_code == "3":
                        self._progress["status"] = "running"
                    elif status_code == "5":
                        self._progress["status"] = "exhausted"
                    elif status_code == "6":
                        self._progress["status"] = "cracked"

    def _import_outfile(self):
        """Import cracked passwords from hashcat output file."""
        if not self._outfile or not os.path.isfile(self._outfile):
            return

        try:
            with open(self._outfile, "r") as f:
                for line in f:
                    password = line.strip()
                    if password:
                        self._cracked.append({
                            "password": password,
                            "timestamp": time.time()
                        })
                        log.critical(f"HASHCAT CRACKED: {password}")
        except (OSError, IOError) as e:
            log.error(f"Failed to read hashcat output: {e}")

    def get_progress(self):
        """Return current cracking progress."""
        with self._lock:
            return dict(self._progress)

    def get_cracked(self):
        """Return list of cracked passwords."""
        # Also check outfile for any new results
        self._import_outfile()
        return list(self._cracked)

    def auto_import_cracked(self, db):
        """
        Import cracked passwords into the database.

        Args:
            db: POSDatabase instance

        Returns:
            Number of passwords imported
        """
        cracked = self.get_cracked()
        imported = 0

        for entry in cracked:
            password = entry.get("password", "")
            if password:
                try:
                    db.log_credential(
                        client_ip="hashcat",
                        client_mac="",
                        username="WPA",
                        password=password,
                        url="hashcat-cracked"
                    )
                    imported += 1
                except Exception as e:
                    log.error(f"Failed to import cracked password: {e}")

        if imported:
            log.info(f"Imported {imported} cracked passwords to database")
        return imported

    def stop(self):
        """Stop hashcat process."""
        self._running = False

        if self._process:
            try:
                self._process.terminate()
                self._process.wait(timeout=10)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    self._process.kill()
                except OSError:
                    pass
            self._process = None

        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
            self._monitor_thread = None

        self._progress["status"] = "stopped"
        log.info("Hashcat integration stopped")

    def get_stats(self):
        """Return hashcat integration statistics."""
        with self._lock:
            return {
                "hashcat_available": self._hashcat_path is not None,
                "hashcat_path": self._hashcat_path,
                "running": self._running,
                "cracked_count": len(self._cracked),
                "progress": dict(self._progress),
            }
