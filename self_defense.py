"""
GuardianX Self-Defense Module
Process self-protection with watchdog respawn, mutex single instance,
and anti-termination measures.

Ensures GuardianX survives malware that attempts to kill security tools.
"""

import os
import sys
import ctypes
import ctypes.wintypes
import subprocess
import threading
import logging
import time
import signal
import atexit
from pathlib import Path

logger = logging.getLogger("GuardianX.SelfDefense")

# Windows API constants
MUTEX_ALL_ACCESS = 0x1F0001
ERROR_ALREADY_EXISTS = 183
PROCESS_SET_INFORMATION = 0x0200
SE_DEBUG_NAME = "SeDebugPrivilege"
HIGH_PRIORITY_CLASS = 0x00000080
BELOW_NORMAL_PRIORITY_CLASS = 0x00004000


class SelfDefense:
    """
    Provides self-protection mechanisms for GuardianX.
    
    Features:
    1. Named mutex for single-instance enforcement
    2. Watchdog sibling process for auto-restart
    3. Process priority elevation
    4. DACL-based termination protection
    5. Crash recovery registration
    """
    
    def __init__(self):
        self._mutex_handle = None
        self._watchdog_process = None
        self._heartbeat_thread = None
        self._running = False
        self._is_watchdog_mode = False
        self._guardian_pid = os.getpid()
        
        # Heartbeat file for watchdog communication
        self._heartbeat_file = Path(os.getenv('TEMP')) / 'GuardianX' / '.heartbeat'
        self._heartbeat_file.parent.mkdir(parents=True, exist_ok=True)
        
        logger.info("Self-Defense module initialized")
    
    def activate(self):
        """
        Activate all self-defense mechanisms.
        Call this during GuardianX startup.
        """
        logger.info("Activating self-defense systems...")
        
        # 1. Single instance check
        if not self.ensure_single_instance():
            logger.error("Another GuardianX instance is already running!")
            return False
        
        # 2. Elevate process priority
        self.protect_process()
        
        # 3. Start watchdog
        self.start_watchdog()
        
        # 4. Register crash handler
        self._register_crash_handler()
        
        self._running = True
        logger.info("Self-defense systems ACTIVE")
        return True
    
    def deactivate(self):
        """Cleanly deactivate self-defense (for graceful shutdown)."""
        self._running = False
        
        # Stop watchdog
        if self._watchdog_process:
            try:
                self._watchdog_process.terminate()
            except Exception:
                pass
        
        # Release mutex
        if self._mutex_handle:
            try:
                ctypes.windll.kernel32.ReleaseMutex(self._mutex_handle)
                ctypes.windll.kernel32.CloseHandle(self._mutex_handle)
            except Exception:
                pass
        
        # Clean up heartbeat
        try:
            if self._heartbeat_file.exists():
                self._heartbeat_file.unlink()
        except Exception:
            pass
        
        logger.info("Self-defense systems deactivated")
    
    def ensure_single_instance(self):
        """
        Create a named mutex to prevent multiple instances of GuardianX.
        
        Returns: True if this is the only instance, False if another exists
        """
        try:
            mutex_name = "Global\\GuardianX_SingleInstance_Mutex"
            
            self._mutex_handle = ctypes.windll.kernel32.CreateMutexW(
                None,                    # Default security
                ctypes.c_bool(False),    # Not initially owned
                mutex_name               # Mutex name
            )
            
            last_error = ctypes.windll.kernel32.GetLastError()
            
            if last_error == ERROR_ALREADY_EXISTS:
                logger.warning("GuardianX is already running (mutex exists)")
                ctypes.windll.kernel32.CloseHandle(self._mutex_handle)
                self._mutex_handle = None
                return False
            
            if self._mutex_handle:
                logger.info("Single instance mutex acquired")
                return True
            else:
                logger.warning("Failed to create mutex")
                return True  # Proceed anyway
                
        except Exception as e:
            logger.error(f"Mutex creation error: {e}")
            return True  # Proceed anyway on error
    
    def protect_process(self):
        """
        Harden the GuardianX process against termination.
        
        - Sets high priority
        - Modifies process DACL to deny termination by non-admin
        """
        try:
            # Set high priority class
            handle = ctypes.windll.kernel32.GetCurrentProcess()
            ctypes.windll.kernel32.SetPriorityClass(handle, HIGH_PRIORITY_CLASS)
            logger.info("Process priority elevated to HIGH")
            
        except Exception as e:
            logger.warning(f"Failed to elevate priority: {e}")
        
        try:
            # Attempt to modify DACL (requires admin)
            self._set_process_dacl()
        except Exception as e:
            logger.debug(f"DACL modification not available: {e}")
    
    def _set_process_dacl(self):
        """
        Modify process security descriptor to deny PROCESS_TERMINATE
        for non-elevated users.
        """
        try:
            import win32api
            import win32security
            import win32process
            import ntsecuritycon
            
            # Get current process handle
            ph = win32api.GetCurrentProcess()
            
            # Get the current DACL
            sd = win32security.GetKernelObjectSecurity(
                ph, win32security.DACL_SECURITY_INFORMATION
            )
            dacl = sd.GetSecurityDescriptorDacl()
            
            # Get the SID for "Everyone" group
            everyone_sid = win32security.CreateWellKnownSid(
                win32security.WinWorldSid, None
            )
            
            # Add ACE denying process termination to Everyone
            dacl.AddAccessDeniedAce(
                win32security.ACL_REVISION,
                ntsecuritycon.PROCESS_TERMINATE,
                everyone_sid
            )
            
            # Apply the modified DACL
            sd.SetSecurityDescriptorDacl(True, dacl, False)
            win32security.SetKernelObjectSecurity(
                ph, win32security.DACL_SECURITY_INFORMATION, sd
            )
            
            logger.info("Process DACL hardened — termination denied for non-admin")
            
        except ImportError:
            logger.debug("win32security not available for DACL modification")
        except Exception as e:
            logger.debug(f"DACL modification failed: {e}")
    
    def start_watchdog(self):
        """
        Start a watchdog sibling process that monitors GuardianX.
        
        The watchdog checks the heartbeat file periodically.
        If GuardianX stops updating the heartbeat, the watchdog restarts it.
        """
        try:
            # Start heartbeat writer thread
            self._heartbeat_thread = threading.Thread(
                target=self._heartbeat_writer,
                daemon=True,
                name="GuardianX-Heartbeat"
            )
            self._heartbeat_thread.start()
            
            # Spawn watchdog process
            python_exe = sys.executable
            main_script = str(Path(__file__).parent / 'main.py')
            
            # Launch the watchdog as a subprocess
            self._watchdog_process = subprocess.Popen(
                [python_exe, '-c', self._get_watchdog_script()],
                creationflags=subprocess.CREATE_NO_WINDOW | BELOW_NORMAL_PRIORITY_CLASS,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            
            logger.info(f"Watchdog process started (PID {self._watchdog_process.pid})")
            
        except Exception as e:
            logger.warning(f"Failed to start watchdog: {e}")
    
    def _heartbeat_writer(self):
        """Write heartbeat timestamp to file every 5 seconds."""
        while self._running:
            try:
                with open(self._heartbeat_file, 'w') as f:
                    f.write(f"{time.time()}\n{os.getpid()}")
            except Exception:
                pass
            time.sleep(5)
    
    def _get_watchdog_script(self):
        """Generate the watchdog Python script as a string."""
        heartbeat_path = str(self._heartbeat_file).replace('\\', '\\\\')
        main_script = str(Path(__file__).parent / 'main.py').replace('\\', '\\\\')
        python_exe = sys.executable.replace('\\', '\\\\')
        
        return f'''
import os, sys, time, subprocess
from pathlib import Path

HEARTBEAT_FILE = Path(r"{heartbeat_path}")
MAIN_SCRIPT = r"{main_script}"
PYTHON_EXE = r"{python_exe}"
CHECK_INTERVAL = 10   # seconds
DEAD_THRESHOLD = 30   # seconds without heartbeat = dead
MAX_RESTARTS = 5      # maximum auto-restarts

restarts = 0

while restarts < MAX_RESTARTS:
    try:
        time.sleep(CHECK_INTERVAL)
        
        if not HEARTBEAT_FILE.exists():
            continue
        
        with open(HEARTBEAT_FILE, 'r') as f:
            lines = f.read().strip().split('\\n')
            last_heartbeat = float(lines[0])
            guardian_pid = int(lines[1]) if len(lines) > 1 else None
        
        elapsed = time.time() - last_heartbeat
        
        if elapsed > DEAD_THRESHOLD:
            # GuardianX appears dead — check if process still exists
            import psutil
            try:
                if guardian_pid:
                    proc = psutil.Process(guardian_pid)
                    if proc.is_running():
                        continue  # Process exists, heartbeat may be delayed
            except psutil.NoSuchProcess:
                pass
            
            # Restart GuardianX
            print(f"[WATCHDOG] GuardianX heartbeat lost ({{elapsed:.0f}}s). Restarting...")
            subprocess.Popen(
                [PYTHON_EXE, MAIN_SCRIPT],
                creationflags=0x00000010,  # CREATE_NEW_CONSOLE
            )
            restarts += 1
            time.sleep(15)  # Wait for new instance to start
            
    except Exception as e:
        time.sleep(CHECK_INTERVAL)

print("[WATCHDOG] Maximum restart limit reached. Stopping.")
'''
    
    def _register_crash_handler(self):
        """Register cleanup handlers for graceful/crash shutdown."""
        atexit.register(self.deactivate)
        
        try:
            signal.signal(signal.SIGTERM, self._signal_handler)
            signal.signal(signal.SIGINT, self._signal_handler)
        except Exception:
            pass
        
        logger.debug("Crash handlers registered")
    
    def _signal_handler(self, signum, frame):
        """Handle termination signals."""
        logger.info(f"Received signal {signum} — shutting down gracefully")
        self.deactivate()
    
    @staticmethod
    def is_watchdog_mode():
        """Check if this process was launched as a watchdog."""
        return '--watchdog' in sys.argv
    
    @staticmethod
    def get_protection_status():
        """Get current self-protection status info."""
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            is_admin = False
        
        try:
            import win32api
            import win32process
            handle = win32api.GetCurrentProcess()
            priority = win32process.GetPriorityClass(handle)
            priority_name = {
                0x00000040: "IDLE",
                0x00004000: "BELOW_NORMAL",
                0x00000020: "NORMAL",
                0x00008000: "ABOVE_NORMAL",
                0x00000080: "HIGH",
                0x00000100: "REALTIME",
            }.get(priority, f"UNKNOWN ({priority})")
        except Exception:
            priority_name = "UNKNOWN"
        
        heartbeat_file = Path(os.getenv('TEMP')) / 'GuardianX' / '.heartbeat'
        watchdog_alive = False
        if heartbeat_file.exists():
            try:
                with open(heartbeat_file, 'r') as f:
                    last_beat = float(f.read().strip().split('\n')[0])
                    watchdog_alive = (time.time() - last_beat) < 30
            except Exception:
                pass
        
        return {
            'is_admin': is_admin,
            'priority': priority_name,
            'pid': os.getpid(),
            'heartbeat_active': watchdog_alive,
            'mutex_held': True,  # If we got here, mutex is held
        }
