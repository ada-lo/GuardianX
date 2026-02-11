"""
GuardianX Main Engine v2.0
Orchestrates file monitoring, threat detection, response actions,
and integrates all industry-grade defense modules.
"""
import os
import sys
import time
import logging
import psutil
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime

from config import *
from detectors import (
    SlowBurnDetector, 
    MagicByteSentry, 
    RansomwareSignatureChecker,
    IdleMonitor
)
from process_manager import ProcessManager
from etw_monitor import ETWFileMonitor
from file_recovery import FileRecoveryManager
from adaptive_baseline import AdaptiveBaseline
from evasion_detector import EvasionDetector
from self_defense import SelfDefense

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(name)s] %(levelname)s: %(message)s'
)
logger = logging.getLogger("GuardianX")


class GuardianXHandler(FileSystemEventHandler):
    """
    File system event handler.
    Called whenever a file is created, modified, or deleted.
    """
    
    def __init__(self, guardian):
        self.guardian = guardian
        super().__init__()
    
    def on_modified(self, event):
        if not event.is_directory:
            self.guardian.analyze_file_event(event.src_path, 'modified')
    
    def on_created(self, event):
        if not event.is_directory:
            self.guardian.analyze_file_event(event.src_path, 'created')
    
    def on_deleted(self, event):
        if not event.is_directory:
            self.guardian.analyze_file_event(event.src_path, 'deleted')


class GuardianX:
    """
    Main orchestration class.
    Coordinates all detectors, industry-grade modules, and takes action
    based on comprehensive threat assessment.
    """
    
    def __init__(self, watch_paths=None, enable_dashboard=True):
        """
        Initialize GuardianX with all defense modules.
        
        watch_paths: List of directories to monitor (default: user's Documents, Desktop, Downloads)
        enable_dashboard: Start the web dashboard on port 9090
        """
        print("[GuardianX] Initializing defense systems...")
        
        # ─── Core Detectors (Trinity Architecture) ───
        self.slow_burn = SlowBurnDetector()
        self.magic_sentry = MagicByteSentry()
        self.signature_checker = RansomwareSignatureChecker()
        self.idle_monitor = IdleMonitor()
        self.process_manager = ProcessManager()
        
        # ─── Gap 1: ETW-Based Process Attribution ───
        self.etw_monitor = ETWFileMonitor()
        print("[GuardianX] ETW Monitor initialized")
        
        # ─── Gap 2: File Recovery Manager ───
        self.recovery = FileRecoveryManager()
        print("[GuardianX] File Recovery Manager ready")
        
        # ─── Gap 4: Adaptive Baselines ───
        self.adaptive_baseline = AdaptiveBaseline()
        if self.adaptive_baseline.is_learning:
            print("[GuardianX] Adaptive Baseline: LEARNING MODE (building profiles)")
        else:
            print("[GuardianX] Adaptive Baseline: ENFORCING MODE")
        
        # ─── Gap 5: Evasion Detector ───
        self.evasion_detector = EvasionDetector()
        print("[GuardianX] Evasion Detector active")
        
        # ─── Gap 3: Dashboard Event Bus ───
        self.event_bus = None
        self._dashboard_enabled = enable_dashboard
        
        # Set up monitoring paths
        if watch_paths is None:
            self.watch_paths = self._get_default_watch_paths()
        else:
            self.watch_paths = [Path(p) for p in watch_paths]
        
        # File system observer
        self.observer = Observer()
        
        # Statistics
        self.stats = {
            'events_processed': 0,
            'threats_detected': 0,
            'processes_killed': 0,
            'processes_suspended': 0,
            'false_positives_undone': 0,
            'files_backed_up': 0,
            'files_restored': 0,
            'start_time': datetime.now(),
        }
        
        print(f"[GuardianX] Monitoring {len(self.watch_paths)} directories")
        for path in self.watch_paths:
            print(f"  - {path}")
    
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
        Main analysis function called on every file event.
        Implements the full decision tree with all industry-grade checks.
        """
        self.stats['events_processed'] += 1
        
        try:
            # ─── Gap 2: Backup file BEFORE analysis ───
            if event_type in ['modified', 'created']:
                success, _ = self.recovery.backup_file(filepath)
                if success:
                    self.stats['files_backed_up'] += 1
            
            # ─── Gap 1: ETW-based process attribution ───
            pid = self.etw_monitor.get_process_for_file(filepath)
            
            if pid is None:
                # Fallback to legacy method
                pid = self._get_modifying_process(filepath)
            
            if pid is None:
                return  # Couldn't determine process
            
            # Record event for slow-burn detection
            self.slow_burn.record_event(pid, filepath)
            
            # ─── Gap 4: Record activity for adaptive baselines ───
            proc_info = self.process_manager.get_process_info(pid)
            proc_name = proc_info['name'] if proc_info else None
            event_count = len(self.slow_burn.process_events.get(pid, []))
            self.adaptive_baseline.record_activity(pid, event_count, proc_name)
            
            # === THREAT ASSESSMENT ===
            threat_indicators = self._assess_threat(pid, filepath, event_type)
            
            # === DECISION TREE ===
            action, reason = self.process_manager.decide_action(pid, threat_indicators)
            
            # === TAKE ACTION ===
            if action == ThreatLevel.KILL:
                self._handle_kill(pid, filepath, reason)
            elif action == ThreatLevel.SUSPEND:
                self._handle_suspend(pid, filepath, reason)
            elif action == ThreatLevel.ALLOW:
                # Log but don't act
                self._log_event(pid, filepath, event_type, 'ALLOWED', reason)
            
            # ─── Publish event to dashboard ───
            self._publish_event(pid, filepath, event_type, action, reason)
            
        except Exception as e:
            logger.error(f"Exception analyzing {filepath}: {e}")
    
    def _assess_threat(self, pid, filepath, event_type):
        """
        Run all threat detectors and compile indicators.
        Returns dict of threat indicators.
        """
        indicators = {}
        
        # 1. Check for known ransomware signature
        proc_info = self.process_manager.get_process_info(pid)
        if proc_info:
            is_known, threat_name = self.signature_checker.check_process_name(proc_info['name'])
            indicators['is_known_ransomware'] = is_known
        else:
            indicators['is_known_ransomware'] = False
        
        # 2. Check for ransom notes
        parent_dir = Path(filepath).parent
        ransom_notes = self.signature_checker.scan_directory_for_ransom_notes(parent_dir)
        indicators['ransom_notes_found'] = ransom_notes
        
        # 3. Check magic bytes (file corruption)
        if event_type in ['modified', 'created']:
            time.sleep(0.1)  # Give filesystem time to flush
            is_valid, reason = self.magic_sentry.check_file_integrity(filepath)
            indicators['has_corrupted_files'] = not is_valid
            
            if not is_valid:
                # Also check entropy
                entropy, entropy_reason = self.magic_sentry.calculate_entropy(filepath)
                indicators['file_entropy'] = entropy
        else:
            indicators['has_corrupted_files'] = False
        
        # 4. Check file modification rate (slow-burn) — with ADAPTIVE THRESHOLD
        is_user_idle, idle_duration = self.idle_monitor.check_idle_state()
        
        # ─── Gap 4: Use adaptive threshold instead of hardcoded ───
        proc_name = proc_info['name'] if proc_info else None
        dynamic_threshold = self.adaptive_baseline.get_threshold(pid, proc_name)
        is_suspicious, count, window = self.slow_burn.check_threshold(
            pid, is_user_idle, dynamic_threshold=dynamic_threshold
        )
        indicators['high_file_rate'] = is_suspicious
        indicators['file_count'] = count
        indicators['dynamic_threshold'] = dynamic_threshold
        
        # 5. Check for suspicious extensions
        is_sus_ext, ext = self.signature_checker.check_suspicious_extension(filepath)
        if is_sus_ext:
            indicators['suspicious_extensions'] = [ext]
        else:
            indicators['suspicious_extensions'] = []
        
        # 6. User idle state
        indicators['is_user_idle'] = is_user_idle
        indicators['idle_duration'] = idle_duration
        indicators['idle_level'] = self.idle_monitor.get_idle_level()
        
        # ─── Gap 5: Evasion analysis ───
        evasion_result = self.evasion_detector.get_evasion_score(pid)
        indicators['evasion_score'] = evasion_result['score']
        indicators['evasion_indicators'] = evasion_result['indicators']
        indicators['evasion_override_whitelist'] = evasion_result['should_override_whitelist']
        
        return indicators
    
    def _get_modifying_process(self, filepath):
        """
        Find the process that is modifying this file.
        Legacy fallback — used when ETW doesn't have data.
        """
        try:
            filepath_normalized = os.path.normpath(filepath).lower()
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    for item in proc.open_files():
                        if os.path.normpath(item.path).lower() == filepath_normalized:
                            return proc.info['pid']
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue
            
            return None
            
        except Exception:
            return None
    
    def _handle_kill(self, pid, filepath, reason):
        """Handle KILL decision — terminate and attempt file restore."""
        success, message = self.process_manager.kill_process(pid, reason)
        
        if success:
            self.stats['processes_killed'] += 1
            self.stats['threats_detected'] += 1
            
            print(f"\n{'='*60}")
            print(f"[THREAT NEUTRALIZED] PID {pid}")
            print(f"File: {filepath}")
            print(f"Reason: {reason}")
            
            # ─── Gap 2: Attempt automatic file restore ───
            restore_success, restore_msg = self.recovery.restore_file(filepath)
            if restore_success:
                self.stats['files_restored'] += 1
                print(f"[RECOVERY] ✓ {restore_msg}")
            else:
                print(f"[RECOVERY] ✗ {restore_msg}")
            
            print(f"{'='*60}\n")
        else:
            print(f"[WARNING] Failed to kill PID {pid}: {message}")
    
    def _handle_suspend(self, pid, filepath, reason):
        """Handle SUSPEND decision"""
        success, message = self.process_manager.suspend_process(pid, reason)
        
        if success:
            self.stats['processes_suspended'] += 1
            
            print(f"\n{'='*60}")
            print(f"[PROCESS SUSPENDED] PID {pid}")
            print(f"File: {filepath}")
            print(f"Reason: {reason}")
            print(f"Action: Use 'guardianx undo {pid}' to resume if false positive")
            print(f"{'='*60}\n")
        else:
            print(f"[WARNING] Failed to suspend PID {pid}: {message}")
    
    def _log_event(self, pid, filepath, event_type, action, reason):
        """Log non-threatening events for analysis."""
        logger.debug(f"Event: pid={pid} file={filepath} type={event_type} action={action} reason={reason}")
    
    def _publish_event(self, pid, filepath, event_type, action, reason):
        """Publish event to the dashboard event bus."""
        if self.event_bus:
            action_name = {ThreatLevel.KILL: 'KILL', ThreatLevel.SUSPEND: 'SUSPEND', ThreatLevel.ALLOW: 'ALLOW'}.get(action, 'UNKNOWN')
            event = {
                'type': 'threat' if action in [ThreatLevel.KILL, ThreatLevel.SUSPEND] else 'event',
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
        print(f"\n[GuardianX] Starting defense systems...")
        
        # ─── Gap 1: Start ETW Monitor ───
        self.etw_monitor.start()
        print(f"[GuardianX] Process Attribution: {self.etw_monitor.monitoring_mode}")
        
        # ─── Gap 3: Start Dashboard ───
        if self._dashboard_enabled:
            try:
                from dashboard.app import start_dashboard, event_bus
                self.event_bus = event_bus
                self.event_bus.update_stats(
                    start_time=self.stats['start_time'].isoformat(),
                    monitoring_mode=self.etw_monitor.monitoring_mode,
                )
                start_dashboard(host="0.0.0.0", port=9090)
                print(f"[GuardianX] Dashboard: http://localhost:9090")
            except ImportError as e:
                print(f"[GuardianX] Dashboard unavailable (install fastapi + uvicorn): {e}")
            except Exception as e:
                print(f"[GuardianX] Dashboard startup error: {e}")
        
        print(f"[GuardianX] User idle timeout: {IDLE_TIMEOUT}s")
        print(f"[GuardianX] Baseline mode: {'LEARNING' if self.adaptive_baseline.is_learning else 'ENFORCING'}")
        print(f"[GuardianX] Recovery: {self.recovery.get_backup_stats()['total_files']} backed up files")
        print(f"[GuardianX] Press Ctrl+C to stop\n")
        
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
            print("\n[GuardianX] Shutting down...")
            self.observer.stop()
            self.etw_monitor.stop()
            self.adaptive_baseline.save_profiles()
        
        self.observer.join()
        
        # Print statistics
        self._print_statistics()
    
    def _print_statistics(self):
        """Print session statistics"""
        runtime = datetime.now() - self.stats['start_time']
        
        print("\n" + "="*60)
        print("GuardianX Session Statistics")
        print("="*60)
        print(f"Runtime: {runtime}")
        print(f"Events Processed: {self.stats['events_processed']}")
        print(f"Threats Detected: {self.stats['threats_detected']}")
        print(f"Processes Killed: {self.stats['processes_killed']}")
        print(f"Processes Suspended: {self.stats['processes_suspended']}")
        print(f"False Positives Undone: {self.stats['false_positives_undone']}")
        print(f"Files Backed Up: {self.stats['files_backed_up']}")
        print(f"Files Restored: {self.stats['files_restored']}")
        print(f"Monitoring Mode: {self.etw_monitor.monitoring_mode}")
        print(f"Baseline Mode: {'LEARNING' if self.adaptive_baseline.is_learning else 'ENFORCING'}")
        
        backup_stats = self.recovery.get_backup_stats()
        print(f"Backup Storage: {backup_stats['total_size_mb']}MB / {backup_stats['max_size_mb']}MB")
        print("="*60 + "\n")


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
    
    # Check if running on Windows
    if sys.platform != 'win32':
        print("[ERROR] GuardianX currently only supports Windows")
        sys.exit(1)
    
    # ─── Gap 6: Self-Protection ───
    self_defense = SelfDefense()
    
    # Check for admin privileges
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
    
    # Initialize and start
    try:
        guardian = GuardianX(enable_dashboard=enable_dashboard)
        guardian.start()
    finally:
        self_defense.deactivate()


if __name__ == '__main__':
    main()
