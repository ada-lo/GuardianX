"""
GuardianX Main Engine v2.0
Orchestrates file monitoring, threat detection, response actions,
and integrates all industry-grade defense modules.
"""

import os
import sys
import time
import queue
import logging
import threading
import psutil
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime

from guardianx.config import ThreatLevel, IDLE_TIMEOUT
from guardianx.detection.slow_burn import SlowBurnDetector
from guardianx.detection.magic_byte import MagicByteSentry
from guardianx.detection.signature import RansomwareSignatureChecker
from guardianx.detection.idle_monitor import IdleMonitor
from guardianx.detection.adaptive_baseline import AdaptiveBaseline
from guardianx.detection.evasion import EvasionDetector
from guardianx.detection.pipeline import ThreatPipeline
from guardianx.enforcement.process_manager import ProcessManager
from guardianx.enforcement.self_defense import SelfDefense
from guardianx.enforcement.diagnostics import (
    check_admin,
    log_etw_attribution,
    log_detection_context,
    log_pre_enforcement,
    log_race_condition_check,
)
from guardianx.monitoring.etw_monitor import ETWFileMonitor
from guardianx.recovery.file_recovery import FileRecoveryManager

logger = logging.getLogger("GuardianX")


class GuardianXHandler(FileSystemEventHandler):
    """
    File system event handler.
    Called whenever a file is created, modified, or deleted.
    """

    def __init__(self, guardian):
        self.guardian = guardian
        self._event_count = 0
        super().__init__()

    def on_modified(self, event):
        if not event.is_directory:
            self._event_count += 1
            if self._event_count <= 5 or self._event_count % 50 == 0:
                logger.debug(f"File event #{self._event_count}: modified {event.src_path}")
            self.guardian.analyze_file_event(event.src_path, 'modified')

    def on_created(self, event):
        if not event.is_directory:
            self._event_count += 1
            self.guardian.analyze_file_event(event.src_path, 'created')

    def on_deleted(self, event):
        if not event.is_directory:
            self._event_count += 1
            self.guardian.analyze_file_event(event.src_path, 'deleted')


class GuardianX:
    """
    Main orchestration class.
    Coordinates all detectors, industry-grade modules, and takes action
    based on comprehensive threat assessment.

    All subsystem instances are injected via constructor to support testing.
    """

    def __init__(self, watch_paths=None, enable_dashboard=True,
                 slow_burn=None, magic_sentry=None, signature_checker=None,
                 idle_monitor=None, process_manager=None, etw_monitor=None,
                 recovery=None, adaptive_baseline=None, evasion_detector=None):
        """
        Initialize GuardianX with all defense modules.

        watch_paths: List of directories to monitor (default: user's Documents, Desktop, Downloads)
        enable_dashboard: Start the web dashboard on port 9090

        All other parameters are optional subsystem overrides for dependency injection.
        Pass None (default) to auto-create each subsystem.
        """
        logger.info("Initializing defense systems...")

        # ─── Core Detectors (Trinity Architecture) ───
        self.slow_burn = slow_burn or SlowBurnDetector()
        self.magic_sentry = magic_sentry or MagicByteSentry()
        self.signature_checker = signature_checker or RansomwareSignatureChecker()
        self.idle_monitor = idle_monitor or IdleMonitor()
        self.process_manager = process_manager or ProcessManager()

        # ─── ETW-Based Process Attribution ───
        # Pass watch_paths so ETW can filter events to monitored directories only
        etw_roots = [str(p) for p in (watch_paths or self._get_default_watch_paths())]
        self.etw_monitor = etw_monitor or ETWFileMonitor(monitored_roots=etw_roots)
        logger.info("ETW Monitor initialized")

        # ─── File Recovery Manager ───
        self.recovery = recovery or FileRecoveryManager()
        logger.info("File Recovery Manager ready")

        # ─── Adaptive Baselines ───
        self.adaptive_baseline = adaptive_baseline or AdaptiveBaseline()
        if self.adaptive_baseline.is_learning:
            logger.info("Adaptive Baseline: LEARNING MODE (building profiles)")
        else:
            logger.info("Adaptive Baseline: ENFORCING MODE")

        # ─── Evasion Detector ───
        self.evasion_detector = evasion_detector or EvasionDetector()
        logger.info("Evasion Detector active")

        # ─── Threat Pipeline (DI wiring) ───
        self.pipeline = ThreatPipeline(
            slow_burn=self.slow_burn,
            magic_sentry=self.magic_sentry,
            signature_checker=self.signature_checker,
            idle_monitor=self.idle_monitor,
            adaptive_baseline=self.adaptive_baseline,
            evasion_detector=self.evasion_detector,
        )

        # ─── Dashboard Event Bus ───
        self.event_bus = None
        self._dashboard_enabled = enable_dashboard

        # Set up monitoring paths
        if watch_paths is None:
            self.watch_paths = self._get_default_watch_paths()
        else:
            self.watch_paths = [Path(p) for p in watch_paths]

        # File system observer
        self.observer = Observer()

        # ─── Async Worker Queue (Fix 2) ───
        self._event_queue = queue.Queue(maxsize=5000)
        self._running = True
        self._worker_thread = threading.Thread(
            target=self._worker_loop,
            daemon=True,
            name="GuardianX-Worker"
        )

        # ─── Incident Cooldown (Fix 5) ───
        # dir_path → timestamp: suppress duplicate alerts for 30s per directory
        self._incident_cooldown = {}
        self._cooldown_seconds = 30.0

        # ─── Restore Suppression (Fix 5) ───
        # filepath → timestamp: ignore watchdog events from our own restores
        self._recently_restored = {}

        # Statistics
        self.stats = {
            'events_processed': 0,
            'threats_detected': 0,
            'threats_contained': 0,
            'processes_killed': 0,
            'processes_suspended': 0,
            'false_positives_undone': 0,
            'files_backed_up': 0,
            'files_restored': 0,
            'start_time': datetime.now(),
        }

        logger.info(f"Monitoring {len(self.watch_paths)} directories")
        for path in self.watch_paths:
            logger.info(f"  - {path}")

    def _get_default_watch_paths(self):
        """Get default user directories to monitor"""
        user_profile = Path(os.environ.get('USERPROFILE', os.path.expanduser('~')))

        paths = [
            user_profile / 'Documents',
            user_profile / 'Desktop',
            user_profile / 'Downloads',
            user_profile / 'Pictures',
            user_profile / 'Videos',
        ]

        # Only return paths that exist
        return [p for p in paths if p.exists()]

    def analyze_file_event(self, filepath, event_type):
        """
        Lightweight callback — backup file and enqueue for worker thread.
        This runs on the watchdog thread, so it must be fast.
        """
        self.stats['events_processed'] += 1

        # Suppress events triggered by our own file restores
        fp_norm = os.path.normpath(filepath).lower()
        restore_ts = self._recently_restored.get(fp_norm)
        if restore_ts and time.time() - restore_ts < 2.0:
            return  # Skip — this is our own restore

        try:
            # Backup file BEFORE analysis (fast I/O, stays on callback thread)
            if event_type in ['modified', 'created']:
                success, _ = self.recovery.backup_file(filepath)
                if success:
                    self.stats['files_backed_up'] += 1

            # Enqueue for worker thread (non-blocking)
            self._event_queue.put_nowait((filepath, event_type, time.time()))
        except queue.Full:
            logger.warning("Event queue full — dropping event")
        except Exception as e:
            logger.error(f"Error in file event callback: {e}")

    def _worker_loop(self):
        """Worker thread: dequeues events and runs heavy analysis."""
        logger.info("Analysis worker thread started")
        while self._running:
            try:
                filepath, event_type, recv_time = self._event_queue.get(timeout=1.0)
                self._process_event(filepath, event_type, recv_time)
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Worker error: {e}")

    def _process_event(self, filepath, event_type, recv_time):
        """Heavy analysis — runs on worker thread, not the watchdog callback."""
        try:
            # ETW-based process attribution (cache lookup — fast)
            pid = self.etw_monitor.get_process_for_file(filepath)

            if pid is None:
                log_etw_attribution(filepath)

            # Record event for slow-burn detection
            if pid is not None:
                self.slow_burn.record_event(pid, filepath)

            # Record activity for adaptive baselines
            proc_info = None
            proc_name = None
            if pid is not None:
                proc_info = self.process_manager.get_process_info(pid)
                
                # Fallback: if psutil can't find it (process exited), use ETW process cache
                if proc_info is None:
                    cached = self.etw_monitor.get_cached_process_info(pid)
                    if cached:
                        logger.debug(f"Using ETW process cache for exited PID {pid}: {cached.get('name')}")
                        proc_info = {
                            'pid': pid,
                            'name': cached.get('name', ''),
                            'exe': cached.get('exe', ''),
                            'cmdline': cached.get('cmdline', ''),
                            'is_whitelisted': False,
                            'signer': None,
                            'has_window': False,
                        }
                
                proc_name = proc_info['name'] if proc_info else None
                event_count = len(self.slow_burn.process_events.get(pid, []))
                self.adaptive_baseline.record_activity(pid, event_count, proc_name)

            # === THREAT ASSESSMENT ===
            threat_indicators = self.pipeline.assess(pid, filepath, event_type, proc_info)

            # === DECISION TREE ===
            action, reason = self.process_manager.decide_action(pid, threat_indicators)

            # === INCIDENT COOLDOWN (Fix 5) ===
            if action in (ThreatLevel.KILL, ThreatLevel.SUSPEND, ThreatLevel.CONTAIN):
                dir_path = os.path.normpath(Path(filepath).parent).lower()
                now = time.time()
                last_alert = self._incident_cooldown.get(dir_path, 0)
                if now - last_alert < self._cooldown_seconds:
                    # Suppress duplicate — already alerted for this directory
                    return
                self._incident_cooldown[dir_path] = now

            # === ENFORCEMENT DIAGNOSTICS ===
            if action in (ThreatLevel.KILL, ThreatLevel.SUSPEND, ThreatLevel.CONTAIN):
                action_name = {ThreatLevel.KILL: 'KILL', ThreatLevel.SUSPEND: 'SUSPEND',
                               ThreatLevel.CONTAIN: 'CONTAIN'}.get(action, 'UNKNOWN')
                log_detection_context(filepath, pid, threat_indicators, action_name, reason)
                latency = time.time() - recv_time
                logger.info(f"[TIMING] Detection latency: {latency:.3f}s")

            # === TAKE ACTION ===
            if action == ThreatLevel.KILL:
                self._handle_kill(pid, filepath, reason)
            elif action == ThreatLevel.SUSPEND:
                self._handle_suspend(pid, filepath, reason)
            elif action == ThreatLevel.CONTAIN:
                self._handle_contain(filepath, reason)
            elif action == ThreatLevel.ALLOW:
                self._log_event(pid, filepath, event_type, 'ALLOWED', reason)

            # Publish event to dashboard
            self._publish_event(pid, filepath, event_type, action, reason)

        except Exception as e:
            logger.error(f"Exception analyzing {filepath}: {e}")

    def _handle_kill(self, pid, filepath, reason):
        """Handle KILL decision — terminate and attempt file restore."""
        self.stats['threats_detected'] += 1

        if pid is not None:
            # Race condition check: 500ms delay then re-verify PID
            still_alive = log_race_condition_check(pid)
            log_pre_enforcement(pid, 'KILL')
            if still_alive:
                success, message = self.process_manager.kill_process(pid, reason)
            else:
                success, message = False, f"Process {pid} exited before enforcement could act"
        else:
            success, message = False, "No PID to kill (unknown process)"

        logger.warning("=" * 60)
        if success:
            self.stats['processes_killed'] += 1
            logger.warning(f"[THREAT NEUTRALIZED] PID {pid}")
        else:
            logger.warning(f"[THREAT DETECTED] {message}")

        logger.warning(f"File: {filepath}")
        logger.warning(f"Reason: {reason}")

        # Attempt automatic file restore
        restore_success, restore_msg = self.recovery.restore_file(filepath)
        if restore_success:
            self.stats['files_restored'] += 1
            # Suppress watchdog retrigger from our own restore (same as _handle_contain)
            fp_norm = os.path.normpath(filepath).lower()
            self._recently_restored[fp_norm] = time.time()
            logger.info(f"[RECOVERY] ✓ {restore_msg}")
        else:
            logger.info(f"[RECOVERY] ✗ {restore_msg}")

        logger.warning("=" * 60)

    def _handle_contain(self, filepath, reason):
        """Handle CONTAIN — threat detected but no PID. Quarantine + restore."""
        self.stats['threats_detected'] += 1
        self.stats['threats_contained'] = self.stats.get('threats_contained', 0) + 1

        logger.warning("=" * 60)
        logger.warning(f"[CONTAINED] Threat detected — PID unknown")
        logger.warning(f"File: {filepath}")
        logger.warning(f"Reason: {reason}")

        # Attempt automatic file restore
        restore_success, restore_msg = self.recovery.restore_file(filepath)
        if restore_success:
            self.stats['files_restored'] += 1
            # Track restore to suppress the watchdog event it will trigger
            fp_norm = os.path.normpath(filepath).lower()
            self._recently_restored[fp_norm] = time.time()
            logger.info(f"[RECOVERY] ✓ {restore_msg}")
        else:
            logger.info(f"[RECOVERY] ✗ {restore_msg}")

        logger.warning("=" * 60)

    def _handle_suspend(self, pid, filepath, reason):
        """Handle SUSPEND decision"""
        if pid is not None:
            # Race condition check: 500ms delay then re-verify PID
            still_alive = log_race_condition_check(pid)
            log_pre_enforcement(pid, 'SUSPEND')
            if still_alive:
                success, message = self.process_manager.suspend_process(pid, reason)
            else:
                success, message = False, f"Process {pid} exited before enforcement could act"
        else:
            success, message = False, "No PID to suspend (unknown process)"

        logger.warning("=" * 60)
        if success:
            self.stats['processes_suspended'] += 1
            logger.warning(f"[PROCESS SUSPENDED] PID {pid}")
            logger.warning(f"File: {filepath}")
            logger.warning(f"Reason: {reason}")
            logger.info(f"Action: Use 'guardianx undo {pid}' to resume if false positive")
        else:
            logger.warning(f"[THREAT DETECTED] {reason}")
            logger.warning(f"File: {filepath}")
            logger.info(f"Note: {message}")
        logger.warning("=" * 60)

    def _log_event(self, pid, filepath, event_type, action, reason):
        """Log non-threatening events for analysis."""
        logger.debug(f"Event: pid={pid} file={filepath} type={event_type} action={action} reason={reason}")

    def _publish_event(self, pid, filepath, event_type, action, reason):
        """Publish event to the dashboard event bus."""
        if self.event_bus:
            action_name = {
                ThreatLevel.KILL: 'KILL',
                ThreatLevel.SUSPEND: 'SUSPEND',
                ThreatLevel.CONTAIN: 'CONTAIN',
                ThreatLevel.ALLOW: 'ALLOW',
            }.get(action, 'UNKNOWN')

            event = {
                'type': 'threat' if action in [ThreatLevel.KILL, ThreatLevel.SUSPEND, ThreatLevel.CONTAIN] else 'event',
                'pid': pid,
                'filepath': str(filepath),
                'event_type': event_type,
                'action': action_name,
                'reason': reason,
            }
            self.event_bus.publish(event)

            # Update dashboard stats
            self.event_bus.update_stats(
                events_processed=self.stats['events_processed'],
                threats_detected=self.stats['threats_detected'],
                processes_killed=self.stats['processes_killed'],
                processes_suspended=self.stats['processes_suspended'],
            )

    def start(self):
        """Start monitoring with all defense systems."""
        logger.info("Starting defense systems...")

        # Start ETW Monitor
        self.etw_monitor.start()
        logger.info(f"Process Attribution: {self.etw_monitor.monitoring_mode}")

        # Start worker thread
        self._worker_thread.start()
        logger.info("Analysis worker thread ready")

        # Start Dashboard
        if self._dashboard_enabled:
            try:
                from guardianx.dashboard.app import start_dashboard, event_bus
                self.event_bus = event_bus
                self.event_bus.update_stats(
                    start_time=self.stats['start_time'].isoformat(),
                    monitoring_mode=self.etw_monitor.monitoring_mode,
                )
                start_dashboard(host="0.0.0.0", port=9090)
                logger.info("Dashboard: http://localhost:9090")
            except ImportError as e:
                logger.warning(f"Dashboard unavailable (install fastapi + uvicorn): {e}")
            except Exception as e:
                logger.warning(f"Dashboard startup error: {e}")

        logger.info(f"User idle timeout: {IDLE_TIMEOUT}s")
        logger.info(f"Baseline mode: {'LEARNING' if self.adaptive_baseline.is_learning else 'ENFORCING'}")
        logger.info(f"Recovery: {self.recovery.get_backup_stats()['total_files']} backed up files")
        logger.info("Press Ctrl+C to stop\n")

        # Set up file system watchers
        handler = GuardianXHandler(self)

        for path in self.watch_paths:
            self.observer.schedule(handler, str(path), recursive=True)

        self.observer.start()

        try:
            while True:
                time.sleep(1)

                # Update idle state
                self.idle_monitor.check_idle_state()

                # Periodic cleanup
                if self.stats['events_processed'] % 100 == 0 and self.stats['events_processed'] > 0:
                    active_pids = [p.pid for p in psutil.process_iter()]
                    self.slow_burn.cleanup_old_processes(active_pids)
                    self.adaptive_baseline.cleanup_pid_baselines(active_pids)
                    self.etw_monitor.cleanup_cache()
                    self.evasion_detector.cleanup_cache()

        except KeyboardInterrupt:
            logger.info("Shutting down...")
            self._running = False
            self.observer.stop()
            self.etw_monitor.stop()
            self._worker_thread.join(timeout=3)
            self.adaptive_baseline.save_profiles()

        self.observer.join()

        # Print statistics
        self._print_statistics()

    def _print_statistics(self):
        """Print session statistics"""
        runtime = datetime.now() - self.stats['start_time']

        logger.info("\n" + "=" * 60)
        logger.info("GuardianX Session Statistics")
        logger.info("=" * 60)
        logger.info(f"Runtime: {runtime}")
        logger.info(f"Events Processed: {self.stats['events_processed']}")
        logger.info(f"Threats Detected: {self.stats['threats_detected']}")
        logger.info(f"Processes Killed: {self.stats['processes_killed']}")
        logger.info(f"Processes Suspended: {self.stats['processes_suspended']}")
        logger.info(f"False Positives Undone: {self.stats['false_positives_undone']}")
        logger.info(f"Files Backed Up: {self.stats['files_backed_up']}")
        logger.info(f"Files Restored: {self.stats['files_restored']}")
        logger.info(f"Monitoring Mode: {self.etw_monitor.monitoring_mode}")
        logger.info(f"Baseline Mode: {'LEARNING' if self.adaptive_baseline.is_learning else 'ENFORCING'}")

        backup_stats = self.recovery.get_backup_stats()
        logger.info(f"Backup Storage: {backup_stats['total_size_mb']}MB / {backup_stats['max_size_mb']}MB")
        logger.info("=" * 60 + "\n")


def main():
    """Entry point"""
    print("""
    ╔═══════════════════════════════════════════╗
    ║         GuardianX v2.0                    ║
    ║   Ransomware Early-Warning System         ║
    ║                                           ║
    ║   Industry-Grade Protection               ║
    ║   ▸ ETW Process Attribution               ║
    ║   ▸ File Recovery & VSS Rollback          ║
    ║   ▸ Real-Time Web Dashboard               ║
    ║   ▸ Adaptive Baseline Learning            ║
    ║   ▸ Evasion Resistance                    ║
    ║   ▸ Process Self-Protection               ║
    ╚═══════════════════════════════════════════╝
    """)

    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='[%(name)s] %(levelname)s: %(message)s'
    )

    # Check if running on Windows
    if sys.platform != 'win32':
        print("[ERROR] GuardianX currently only supports Windows")
        sys.exit(1)

    # Self-Protection
    self_defense = SelfDefense()

    # Check for admin privileges
    is_admin = check_admin()
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if not is_admin:
            print("[WARNING] Not running as administrator. Some features may not work.")
            print("         ▸ ETW kernel tracing requires admin")
            print("         ▸ VSS restore requires admin")
            print("         ▸ DACL protection requires admin")
    except Exception:
        pass

    # Activate self-defense
    if not self_defense.activate():
        print("[WARNING] Another GuardianX instance may be running")

    protection = SelfDefense.get_protection_status()
    print(f"[GuardianX] Process Priority: {protection['priority']}")
    print(f"[GuardianX] PID: {protection['pid']}")

    # Check for dashboard argument
    enable_dashboard = '--no-dashboard' not in sys.argv

    # Check for help
    if '--help' in sys.argv or '-h' in sys.argv:
        print("Usage: python run.py [OPTIONS]")
        print()
        print("Options:")
        print("  --no-dashboard    Start without the web dashboard")
        print("  --help, -h        Show this help message")
        return

    # Initialize and start
    try:
        guardian = GuardianX(enable_dashboard=enable_dashboard)
        guardian.start()
    finally:
        self_defense.deactivate()


if __name__ == '__main__':
    main()
