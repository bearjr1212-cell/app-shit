"""
John the Ripper Integration - Password cracking via john CLI.

Wraps john(1) via asyncio.create_subprocess_exec for:
- Dictionary attacks (--wordlist)
- Incremental/brute-force mode (--incremental)
- Mask attacks (--mask=?a?a?a?a)
- Rule-based mutations (--rules=best64, Jumbo, etc.)
- Single crack mode (--single, uses GECOS field info)
- WPAPSK format for WiFi handshake cracking
- Progress monitoring via --status flag parsing
- Potfile management for cracked password retrieval

Requirements:
- John the Ripper (john) binary in PATH
- hccap2john or wpapcap2john for format conversion
- No Python package dependencies (pure subprocess)

Usage:
    from posframework.john_integration import JohnManager, JohnMode
    from pathlib import Path

    manager = JohnManager()
    await manager.start()

    # Crack with wordlist
    job = await manager.crack_file(
        Path("capture.john"),
        mode=JohnMode.WORDLIST,
        wordlist=Path("/usr/share/wordlists/rockyou.txt"),
        format="wpapsk",
    )

    # Check status
    while job.status == JohnStatus.RUNNING:
        await asyncio.sleep(5)
        status = await manager.get_status(job.id)
        print(f"Progress: {status.speed_gps:.0f} g/s")

    # Get results
    if job.cracked_passwords:
        print(f"Cracked: {job.cracked_passwords[0]}")
"""

from __future__ import annotations

import asyncio
import logging
import re
import shutil
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class JohnMode(str, Enum):
    """John attack modes."""
    WORDLIST = "wordlist"       # --wordlist=FILE
    INCREMENTAL = "incremental" # --incremental[=MODE]
    SINGLE = "single"           # --single (uses login/GECOS info)
    MASK = "mask"               # --mask=?a?a?a?a
    RULES = "rules"             # --wordlist + --rules=RULESET


class JohnStatus(str, Enum):
    """John job execution status."""
    PENDING = "pending"
    RUNNING = "running"
    CRACKED = "cracked"
    EXHAUSTED = "exhausted"
    STOPPED = "stopped"
    ERROR = "error"


@dataclass
class JohnResult:
    """Result of a completed John cracking attempt."""
    hash_file: str
    password: str | None = None
    cracked: bool = False
    guesses: int = 0
    speed_gps: float = 0.0
    duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "hash_file": self.hash_file,
            "password": self.password,
            "cracked": self.cracked,
            "guesses": self.guesses,
            "speed_gps": self.speed_gps,
            "duration_seconds": round(self.duration_seconds, 2),
        }


@dataclass
class JohnJob:
    """A John cracking job with progress tracking."""
    id: str
    hash_file: Path
    status: JohnStatus = JohnStatus.PENDING
    mode: JohnMode = JohnMode.WORDLIST
    wordlist: Path | None = None
    mask: str | None = None
    rules: str | None = None
    format: str = "wpapsk"

    # Progress
    progress_percent: float = 0.0
    speed_gps: float = 0.0
    guesses: int = 0

    # Results
    cracked_passwords: list[str] = field(default_factory=list)

    # Timing
    started_at: datetime | None = None
    finished_at: datetime | None = None

    @property
    def duration_seconds(self) -> float:
        if self.started_at is None:
            return 0.0
        end = self.finished_at or datetime.now(UTC)
        return (end - self.started_at).total_seconds()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "hash_file": str(self.hash_file),
            "status": self.status.value,
            "mode": self.mode.value,
            "format": self.format,
            "progress_percent": round(self.progress_percent, 1),
            "speed_gps": round(self.speed_gps, 1),
            "cracked_count": len(self.cracked_passwords),
            "duration_seconds": round(self.duration_seconds, 2),
        }


class JohnManager:
    """
    John the Ripper wrapper for async password cracking.

    Manages john processes, monitors progress, and collects results.
    Supports all major john modes and provides real-time status updates.

    Usage:
        manager = JohnManager(max_runtime_seconds=600)
        await manager.start()

        # Convert capture file
        john_file = await manager.convert_hccapx(Path("capture.hccapx"))

        # Start cracking
        job = await manager.crack_file(
            john_file,
            mode=JohnMode.WORDLIST,
            wordlist=Path("rockyou.txt"),
            format="wpapsk",
        )

        # Monitor progress
        while job.status == JohnStatus.RUNNING:
            await asyncio.sleep(10)
            print(f"Speed: {job.speed_gps} g/s")

        # Show results
        cracked = await manager.show_cracked(john_file)
        for password in cracked:
            print(f"Password: {password}")
    """

    def __init__(
        self,
        john_path: str = "john",
        pot_file: Path | None = None,
        session_dir: Path | None = None,
        max_runtime_seconds: int = 300,
    ):
        self.john_path = john_path
        self.pot_file = pot_file or Path.home() / ".john" / "john.pot"
        self.session_dir = session_dir or Path("/tmp/posframework_john")
        self.max_runtime_seconds = max_runtime_seconds

        self._running = False
        self._jobs: dict[str, JohnJob] = {}
        self._processes: dict[str, asyncio.subprocess.Process] = {}
        self._tasks: set[asyncio.Task[None]] = set()
        self._stats = {
            "jobs_total": 0,
            "jobs_cracked": 0,
            "jobs_exhausted": 0,
            "passwords_found": 0,
            "total_guesses": 0,
        }

    async def start(self) -> None:
        """Initialize the manager and verify john is available."""
        self.session_dir.mkdir(parents=True, exist_ok=True)

        john_binary = shutil.which(self.john_path)
        if not john_binary:
            logger.warning(
                "John the Ripper not found in PATH (%s). "
                "Cracking jobs will fail until john is installed.",
                self.john_path,
            )

        self._running = True
        logger.info("JohnManager started (session_dir=%s)", self.session_dir)

    async def stop(self) -> None:
        """Stop all running jobs and cleanup."""
        for job_id in list(self._processes.keys()):
            await self.stop_job(job_id)
        self._running = False
        logger.info("JohnManager stopped")

    async def convert_hccapx(self, hccapx_file: Path) -> Path | None:
        """
        Convert hccapx/pcap capture to John format.

        Tries hccap2john first (for .hccapx), then wpapcap2john (for .pcap/.cap).
        Returns path to converted file, or None on failure.
        """
        output = hccapx_file.with_suffix(".john")

        # Find converter binary
        converter = shutil.which("hccap2john") or shutil.which("wpapcap2john")
        if not converter:
            logger.error("No converter found (hccap2john or wpapcap2john)")
            return None

        try:
            proc = await asyncio.create_subprocess_exec(
                converter, str(hccapx_file),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode == 0 and stdout:
                output.write_bytes(stdout)
                logger.info("Converted %s -> %s", hccapx_file.name, output.name)
                return output
            else:
                logger.error("Conversion failed: %s", stderr.decode().strip())
                return None
        except Exception as e:
            logger.error("Conversion error: %s", e)
            return None

    async def crack_file(
        self,
        hash_file: Path,
        mode: JohnMode = JohnMode.WORDLIST,
        wordlist: Path | None = None,
        mask: str | None = None,
        rules: str | None = None,
        format: str = "wpapsk",
    ) -> JohnJob:
        """
        Start cracking a hash file.

        Args:
            hash_file: Path to John-format hash file
            mode: Attack mode (wordlist, incremental, mask, etc.)
            wordlist: Wordlist path for dictionary/rules attack
            mask: Mask pattern for mask attack (e.g., ?a?a?a?a?a?a?a?a)
            rules: John rule name (best64, Jumbo, KoreLogic, etc.)
            format: Hash format (wpapsk, wpa-pmk, raw-md5, etc.)

        Returns:
            JohnJob object (tracks status and results)
        """
        job_id = str(uuid.uuid4())[:8]
        job = JohnJob(
            id=job_id,
            hash_file=hash_file,
            mode=mode,
            wordlist=wordlist,
            mask=mask,
            rules=rules,
            format=format,
        )

        self._jobs[job_id] = job
        self._stats["jobs_total"] += 1

        # Build john command line
        cmd = [self.john_path]

        # Runtime cap
        if self.max_runtime_seconds > 0:
            cmd.append(f"--max-run-time={self.max_runtime_seconds}")

        # Session for this job (allows status queries and restore)
        session_path = self.session_dir / f"session_{job_id}"
        cmd.append(f"--session={session_path}")

        # Hash format
        cmd.append(f"--format={format}")

        # Pot file
        cmd.append(f"--pot={self.pot_file}")

        # Mode-specific arguments
        if mode == JohnMode.WORDLIST and wordlist:
            cmd.append(f"--wordlist={wordlist}")
            if rules:
                cmd.append(f"--rules={rules}")
        elif mode == JohnMode.INCREMENTAL:
            cmd.append("--incremental")
        elif mode == JohnMode.SINGLE:
            cmd.append("--single")
        elif mode == JohnMode.MASK and mask:
            cmd.append(f"--mask={mask}")
        elif mode == JohnMode.RULES and wordlist:
            cmd.append(f"--wordlist={wordlist}")
            cmd.append(f"--rules={rules or 'best64'}")

        # Hash file (must be last argument)
        cmd.append(str(hash_file))

        # Start job
        job.status = JohnStatus.RUNNING
        job.started_at = datetime.now(UTC)

        task = asyncio.create_task(self._run_john(job, cmd))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

        logger.info(
            "Started john job %s: mode=%s format=%s file=%s",
            job_id, mode.value, format, hash_file.name,
        )
        return job

    async def _run_john(self, job: JohnJob, cmd: list[str]) -> None:
        """Run john process and monitor output for cracked passwords."""
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            self._processes[job.id] = proc

            # Watchdog: enforce runtime cap even if john ignores --max-run-time
            watchdog: asyncio.Task[None] | None = None
            if self.max_runtime_seconds > 0:
                async def _watchdog(p: asyncio.subprocess.Process) -> None:
                    try:
                        # Grace period of 15s beyond the cap
                        await asyncio.sleep(self.max_runtime_seconds + 15)
                        if p.returncode is None:
                            logger.warning(
                                "John job %s exceeded %ds cap, terminating",
                                job.id, self.max_runtime_seconds,
                            )
                            p.terminate()
                    except asyncio.CancelledError:
                        pass

                watchdog = asyncio.create_task(_watchdog(proc))

            # Read stdout for cracked passwords and progress
            while True:
                line = await proc.stdout.readline() if proc.stdout else b""
                if not line:
                    break

                decoded = line.decode(errors="replace").strip()
                if not decoded:
                    continue

                logger.debug("john[%s]: %s", job.id, decoded)

                # Parse cracked password lines (format: "hash:password")
                if ":" in decoded and not decoded.startswith(("Warning", "Using", "Loaded")):
                    parts = decoded.rsplit(":", 1)
                    if len(parts) == 2:
                        password = parts[1]
                        if password and not password.startswith(" "):
                            job.cracked_passwords.append(password)
                            self._stats["passwords_found"] += 1
                            logger.info("CRACKED [%s]: %s", job.id, password)

                # Parse speed from status output
                speed_match = re.search(r"(\d+(?:\.\d+)?)\s*[gGpP]/s", decoded)
                if speed_match:
                    job.speed_gps = float(speed_match.group(1))

                # Parse progress percentage
                pct_match = re.search(r"(\d+(?:\.\d+)?)%", decoded)
                if pct_match:
                    job.progress_percent = float(pct_match.group(1))

            await proc.wait()

            if watchdog is not None:
                watchdog.cancel()

            # Determine final status
            job.finished_at = datetime.now(UTC)

            if job.cracked_passwords:
                job.status = JohnStatus.CRACKED
                self._stats["jobs_cracked"] += 1
            elif proc.returncode == 0:
                job.status = JohnStatus.EXHAUSTED
                self._stats["jobs_exhausted"] += 1
            else:
                job.status = JohnStatus.ERROR
                logger.warning("john[%s] exited with code %d", job.id, proc.returncode)

        except asyncio.CancelledError:
            job.status = JohnStatus.STOPPED
            job.finished_at = datetime.now(UTC)
        except FileNotFoundError:
            job.status = JohnStatus.ERROR
            job.finished_at = datetime.now(UTC)
            logger.error("john binary not found: %s", self.john_path)
        except Exception as e:
            job.status = JohnStatus.ERROR
            job.finished_at = datetime.now(UTC)
            logger.error("john[%s] error: %s", job.id, e)
        finally:
            self._processes.pop(job.id, None)

    async def stop_job(self, job_id: str) -> bool:
        """Stop a running john job."""
        proc = self._processes.get(job_id)
        if proc and proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=5.0)
            except TimeoutError:
                proc.kill()

            job = self._jobs.get(job_id)
            if job:
                job.status = JohnStatus.STOPPED
                job.finished_at = datetime.now(UTC)
            return True
        return False

    async def get_status(self, job_id: str) -> JohnJob | None:
        """
        Get current status of a job.

        For running jobs, sends SIGUSR1 to john to trigger status output.
        """
        job = self._jobs.get(job_id)
        if not job:
            return None

        # If running, try to get live status
        proc = self._processes.get(job_id)
        if proc and proc.returncode is None:
            try:
                # Send SIGUSR1 to john to trigger status line on stderr
                import signal
                proc.send_signal(signal.SIGUSR1)
            except (ProcessLookupError, OSError):
                pass

        return job

    async def show_cracked(self, hash_file: Path) -> list[str]:
        """
        Show already-cracked passwords from the pot file.

        Uses `john --show` to display passwords cracked in previous sessions.
        """
        cmd = [
            self.john_path,
            "--show",
            f"--pot={self.pot_file}",
            str(hash_file),
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()

            passwords = []
            for line in stdout.decode(errors="replace").splitlines():
                if ":" in line and not line.startswith(("0 password", "Use the")):
                    parts = line.rsplit(":", 1)
                    if len(parts) == 2 and parts[1].strip():
                        passwords.append(parts[1].strip())

            return passwords

        except FileNotFoundError:
            logger.error("john binary not found for --show")
            return []
        except Exception as e:
            logger.error("show_cracked error: %s", e)
            return []

    def get_job(self, job_id: str) -> JohnJob | None:
        """Get a specific job by ID."""
        return self._jobs.get(job_id)

    def get_all_jobs(self) -> list[JohnJob]:
        """Get all jobs."""
        return list(self._jobs.values())

    def get_running_jobs(self) -> list[JohnJob]:
        """Get currently running jobs."""
        return [j for j in self._jobs.values() if j.status == JohnStatus.RUNNING]

    def get_stats(self) -> dict[str, Any]:
        """Get manager statistics."""
        return dict(self._stats)

    def get_metrics(self) -> dict[str, Any]:
        """Prometheus-compatible metrics."""
        return {
            "posframework_john_jobs_total": self._stats["jobs_total"],
            "posframework_john_jobs_cracked": self._stats["jobs_cracked"],
            "posframework_john_jobs_exhausted": self._stats["jobs_exhausted"],
            "posframework_john_passwords_found": self._stats["passwords_found"],
            "posframework_john_running": len(self._processes),
        }
