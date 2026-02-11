"""
GuardianX Main Engine
Orchestrates file monitoring, threat detection, and response actions.
"""

import sys
import time
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
    Coordinates all detectors and takes action based on threat assessment.
    """
    
    def __init__(self, watch_paths=None):
        """
        Initialize GuardianX.
        
        watch_paths: List of directories to monitor (default: user's Documents, Desktop, Downloads)
        """
        print("[GuardianX] Initializing defense systems...")
        
        # Initialize detectors
        self.slow_burn = SlowBurnDetector()
        self.magic_sentry = MagicByteSentry()
        self.signature_checker = RansomwareSignatureChecker()
        self.idle_monitor = IdleMonitor()
        self.process_manager = ProcessManager()
        
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
            'start_time': datetime.now(),
        }
        
        print(f"[GuardianX] Monitoring {len(self.watch_paths)} directories")
        for path in self.watch_paths:
            print(f"  - {path}")
    
    def _get_default_watch_paths(self):
        """Get default user directories to monitor"""
        import os
        
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
        Implements the full decision tree.
        """
        self.stats['events_processed'] += 1
        
        try:
            # Get the process that modified the file
            pid = self._get_modifying_process(filepath)
            
            if pid is None:
                return  # Couldn't determine process
            
            # Record event for slow-burn detection
            self.slow_burn.record_event(pid, filepath)
            
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
            
        except Exception as e:
            print(f"[ERROR] Exception analyzing {filepath}: {e}")
    
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
        
        # 4. Check file modification rate (slow-burn)
        is_user_idle, idle_duration = self.idle_monitor.check_idle_state()
        is_suspicious, count, window = self.slow_burn.check_threshold(pid, is_user_idle)
        indicators['high_file_rate'] = is_suspicious
        indicators['file_count'] = count
        
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
        
        return indicators
    
    def _get_modifying_process(self, filepath):
        """
        Find the process that is modifying this file.
        This is tricky - we look for processes with open handles to the file.
        """
        try:
            # Iterate through all processes
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    # Check if process has this file open
                    for item in proc.open_files():
                        if item.path == filepath:
                            return proc.info['pid']
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue
            
            # If we can't find the process, return None
            return None
            
        except Exception:
            return None
    
    def _handle_kill(self, pid, filepath, reason):
        """Handle KILL decision"""
        success, message = self.process_manager.kill_process(pid, reason)
        
        if success:
            self.stats['processes_killed'] += 1
            self.stats['threats_detected'] += 1
            
            print(f"\n{'='*60}")
            print(f"[THREAT NEUTRALIZED] PID {pid}")
            print(f"File: {filepath}")
            print(f"Reason: {reason}")
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
        """Log non-threatening events for analysis"""
        # Could write to activity log here
        pass
    
    def start(self):
        """Start monitoring"""
        print("\n[GuardianX] Starting file system monitoring...")
        print(f"[GuardianX] User idle timeout: {IDLE_TIMEOUT}s")
        print(f"[GuardianX] Slow-burn threshold: {SLOW_BURN_THRESHOLD} files/{SLOW_BURN_WINDOW}s")
        print(f"[GuardianX] Press Ctrl+C to stop\n")
        
        # Set up file system watchers
        handler = GuardianXHandler(self)
        
        for path in self.watch_paths:
            self.observer.schedule(handler, str(path), recursive=True)
        
        self.observer.start()
        
        try:
            while True:
                time.sleep(1)
                
                # Update idle state (would be done by input listener in production)
                self.idle_monitor.check_idle_state()
                
                # Periodic cleanup
                if self.stats['events_processed'] % 100 == 0:
                    active_pids = [p.pid for p in psutil.process_iter()]
                    self.slow_burn.cleanup_old_processes(active_pids)
        
        except KeyboardInterrupt:
            print("\n[GuardianX] Shutting down...")
            self.observer.stop()
        
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
        print("="*60 + "\n")


def main():
    """Entry point"""
    print("""
    ╔═══════════════════════════════════════════╗
    ║         GuardianX v1.0                    ║
    ║   Ransomware Early-Warning System         ║
    ║                                           ║
    ║   "Set it and Forget it" Protection       ║
    ╚═══════════════════════════════════════════╝
    """)
    
    # Check if running on Windows
    if sys.platform != 'win32':
        print("[ERROR] GuardianX currently only supports Windows")
        sys.exit(1)
    
    # Check for admin privileges (optional but recommended)
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if not is_admin:
            print("[WARNING] Not running as administrator. Some features may not work.")
    except:
        pass
    
    # Initialize and start
    guardian = GuardianX()
    guardian.start()


if __name__ == '__main__':
    main()
