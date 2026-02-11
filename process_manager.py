"""
GuardianX Process Manager
Handles the decision tree: Kill vs Suspend vs Allow
Manages process termination and suspension with undo capability
"""

import psutil
import win32api
import win32con
import win32security
import win32process
import pywintypes
from pathlib import Path
from datetime import datetime
import json

from config import *


class ProcessManager:
    """
    Manages process actions: analyze, suspend, resume, terminate.
    Implements the decision tree with whitelist checking.
    """
    
    def __init__(self):
        self.suspended_processes = {}  # pid -> {info, reason, timestamp}
        self.killed_processes = []     # List of killed process info
        
    def get_process_info(self, pid):
        """
        Get comprehensive information about a process.
        Returns dict with: name, path, signature, has_window, user
        """
        try:
            proc = psutil.Process(pid)
            
            info = {
                'pid': pid,
                'name': proc.name(),
                'exe': proc.exe(),
                'cmdline': ' '.join(proc.cmdline()),
                'create_time': proc.create_time(),
                'username': proc.username(),
            }
            
            # Check digital signature (Windows-specific)
            info['is_signed'], info['signer'] = self._check_digital_signature(info['exe'])
            
            # Check if process has visible window
            info['has_window'] = self._has_visible_window(pid)
            
            # Check if in whitelist
            info['is_whitelisted'] = self._is_whitelisted(info['name'], info['signer'])
            
            return info
            
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            return None
    
    def _check_digital_signature(self, exe_path):
        """
        Check if executable is digitally signed and by whom.
        Returns (is_signed, signer_name)
        """
        try:
            # This is a simplified check - full implementation needs wintrust.dll
            # For now, we'll check if it's in System32 or Program Files
            path_lower = exe_path.lower()
            
            # Windows system files are always trusted
            if 'windows\\system32' in path_lower or 'windows\\syswow64' in path_lower:
                return True, 'Microsoft Windows'
            
            # TODO: Implement proper Authenticode signature verification
            # Would use: win32api.GetFileVersionInfo() or ctypes + wintrust.dll
            
            return False, None
            
        except Exception:
            return False, None
    
    def _has_visible_window(self, pid):
        """
        Check if process has a visible GUI window.
        Malware typically runs headless.
        """
        try:
            import win32gui
            
            def callback(hwnd, windows):
                if win32gui.IsWindowVisible(hwnd):
                    _, found_pid = win32process.GetWindowThreadProcessId(hwnd)
                    if found_pid == pid:
                        windows.append(hwnd)
                return True
            
            windows = []
            win32gui.EnumWindows(callback, windows)
            
            return len(windows) > 0
            
        except Exception:
            return False
    
    def _is_whitelisted(self, process_name, signer_name):
        """Check if process is on whitelist"""
        # Check process name whitelist
        if process_name in WHITELISTED_PROCESSES:
            return True
        
        # Check trusted signers
        if signer_name and signer_name in TRUSTED_SIGNERS:
            return True
        
        return False
    
    def decide_action(self, pid, threat_indicators):
        """
        Main decision tree: Determine if process should be allowed, suspended, or killed.
        
        threat_indicators = {
            'is_known_ransomware': bool,
            'has_corrupted_files': bool,
            'high_file_rate': bool,
            'is_user_idle': bool,
            'ransom_notes_found': list,
            'suspicious_extensions': list,
        }
        
        Returns (action, reason)
        """
        info = self.get_process_info(pid)
        
        if not info:
            return ThreatLevel.ALLOW, "Process no longer exists"
        
        # === STEP 1: Check Whitelist ===
        if info['is_whitelisted']:
            return ThreatLevel.ALLOW, f"Whitelisted: {info['signer'] or info['name']}"
        
        # === STEP 2: Check for Known Ransomware Signature ===
        if threat_indicators.get('is_known_ransomware'):
            return ThreatLevel.KILL, f"KNOWN RANSOMWARE: {info['name']}"
        
        if threat_indicators.get('ransom_notes_found'):
            notes = ', '.join(threat_indicators['ransom_notes_found'])
            return ThreatLevel.KILL, f"Ransom notes detected: {notes}"
        
        # === STEP 3: Check if Process Has Visible Window ===
        if info['has_window']:
            # User is likely aware of this process
            if threat_indicators.get('has_corrupted_files'):
                return ThreatLevel.SUSPEND, "GUI process corrupting files (likely false positive)"
            else:
                return ThreatLevel.ALLOW, "Interactive process with visible window"
        
        # === STEP 4: Check Magic Bytes (File Corruption) ===
        if threat_indicators.get('has_corrupted_files'):
            # File corruption detected, but not known ransomware
            if threat_indicators.get('is_user_idle'):
                return ThreatLevel.KILL, "File corruption detected while user is IDLE"
            else:
                return ThreatLevel.SUSPEND, "File corruption detected (investigate further)"
        
        # === STEP 5: Check File Modification Rate ===
        if threat_indicators.get('high_file_rate'):
            if threat_indicators.get('is_user_idle'):
                return ThreatLevel.KILL, "High file activity while user is IDLE"
            else:
                return ThreatLevel.SUSPEND, "Unusually high file modification rate"
        
        # === STEP 6: Suspicious Extensions ===
        if threat_indicators.get('suspicious_extensions'):
            exts = ', '.join(threat_indicators['suspicious_extensions'])
            return ThreatLevel.SUSPEND, f"Suspicious file extensions: {exts}"
        
        # === Default: Allow ===
        return ThreatLevel.ALLOW, "No suspicious activity detected"
    
    def suspend_process(self, pid, reason):
        """
        Suspend a process (freeze execution without killing).
        Allows for later resumption if false positive.
        """
        try:
            proc = psutil.Process(pid)
            
            # Store state before suspending
            self.suspended_processes[pid] = {
                'info': self.get_process_info(pid),
                'reason': reason,
                'timestamp': datetime.now().isoformat(),
                'can_undo': True,
            }
            
            # Suspend the process
            proc.suspend()
            
            self._log_action('SUSPEND', pid, reason)
            
            return True, f"Process {pid} suspended: {reason}"
            
        except Exception as e:
            return False, f"Failed to suspend {pid}: {e}"
    
    def resume_process(self, pid):
        """Resume a previously suspended process (undo false positive)"""
        try:
            if pid not in self.suspended_processes:
                return False, f"Process {pid} was not suspended by GuardianX"
            
            proc = psutil.Process(pid)
            proc.resume()
            
            # Remove from suspended list
            info = self.suspended_processes.pop(pid)
            
            self._log_action('RESUME', pid, f"User undo: {info['reason']}")
            
            return True, f"Process {pid} resumed successfully"
            
        except Exception as e:
            return False, f"Failed to resume {pid}: {e}"
    
    def kill_process(self, pid, reason):
        """
        Terminate a process immediately.
        This is irreversible - use only for confirmed threats.
        """
        try:
            proc = psutil.Process(pid)
            
            # Store information before killing
            kill_info = {
                'info': self.get_process_info(pid),
                'reason': reason,
                'timestamp': datetime.now().isoformat(),
            }
            
            self.killed_processes.append(kill_info)
            
            # Terminate the process
            proc.kill()
            
            self._log_action('KILL', pid, reason)
            
            return True, f"Process {pid} TERMINATED: {reason}"
            
        except Exception as e:
            return False, f"Failed to kill {pid}: {e}"
    
    def _log_action(self, action, pid, reason):
        """Log action to JSON file"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'pid': pid,
            'reason': reason,
        }
        
        # Append to appropriate log file
        if action == 'KILL':
            log_file = THREAT_LOG
        elif action in ['SUSPEND', 'RESUME']:
            log_file = SUSPEND_LOG
        else:
            log_file = ACTIVITY_LOG
        
        # Read existing logs
        try:
            if log_file.exists():
                with open(log_file, 'r') as f:
                    logs = json.load(f)
            else:
                logs = []
        except Exception:
            logs = []
        
        # Append new entry
        logs.append(log_entry)
        
        # Write back
        with open(log_file, 'w') as f:
            json.dump(logs, f, indent=2)
    
    def get_suspended_processes(self):
        """Get list of currently suspended processes for UI/undo"""
        return list(self.suspended_processes.items())
    
    def get_threat_log(self, limit=50):
        """Retrieve recent threat detections"""
        try:
            if THREAT_LOG.exists():
                with open(THREAT_LOG, 'r') as f:
                    logs = json.load(f)
                    return logs[-limit:]  # Return last N entries
        except Exception:
            pass
        
        return []
