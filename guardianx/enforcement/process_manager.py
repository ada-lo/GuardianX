"""
GuardianX Process Manager
Handles the decision tree: Kill vs Suspend vs Allow.
Manages process termination and suspension with undo capability.

Delegates trust-checking to WhitelistManager and introspection to ProcessInspector.
"""

import psutil
from datetime import datetime
import json

from guardianx.config import (
    ThreatLevel,
    THREAT_LOG,
    SUSPEND_LOG,
    ACTIVITY_LOG,
)
from guardianx.enforcement.diagnostics import log_enforcement_result
from guardianx.enforcement.whitelist import WhitelistManager
from guardianx.enforcement.inspector import ProcessInspector


class ProcessManager:
    """
    Process control: decide action, kill, suspend, resume.
    All introspection is delegated to ProcessInspector.
    """

    def __init__(self, whitelist_manager=None, inspector=None):
        self.whitelist = whitelist_manager or WhitelistManager()
        self.inspector = inspector or ProcessInspector(self.whitelist)
        self.suspended_processes = {}  # pid -> {info, reason, timestamp}
        self.killed_processes = []     # List of killed process info
        
        # Restore suspended state from disk (Fix 2: persistent across processes)
        self._load_suspended_from_disk()

    def _load_suspended_from_disk(self):
        """Load suspended process state from SUSPEND_LOG (JSONL).
        
        Builds net state: SUSPEND entries add PIDs, RESUME entries remove them.
        Then verifies each PID is still alive and suspended via psutil.
        """
        if not SUSPEND_LOG.exists():
            return
        
        # Build net suspended set from log
        suspended_map = {}  # pid -> last entry
        try:
            with open(SUSPEND_LOG, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        pid = entry.get('pid')
                        action = entry.get('action')
                        if pid is None:
                            continue
                        if action == 'SUSPEND':
                            suspended_map[pid] = entry
                        elif action == 'RESUME':
                            suspended_map.pop(pid, None)
                    except (json.JSONDecodeError, KeyError):
                        continue
        except Exception:
            return
        
        # Verify each PID is still alive and suspended
        for pid, entry in suspended_map.items():
            try:
                proc = psutil.Process(pid)
                if proc.status() == psutil.STATUS_STOPPED:
                    self.suspended_processes[pid] = {
                        'info': {'name': proc.name(), 'pid': pid},
                        'reason': entry.get('reason', 'Loaded from disk'),
                        'timestamp': entry.get('timestamp', ''),
                    }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def get_process_info(self, pid):
        """Delegate to ProcessInspector."""
        return self.inspector.get_process_info(pid)

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
            'evasion_score': float,
            'evasion_indicators': list,
            'evasion_override_whitelist': bool
        }

        Returns (action, reason)
        """
        info = self.get_process_info(pid) if pid is not None else None

        if not info:
            # No process info — use CONTAIN (quarantine + restore) instead of KILL
            if threat_indicators.get('ransom_notes_found'):
                notes = ', '.join(threat_indicators['ransom_notes_found'])
                return ThreatLevel.CONTAIN, f"Ransom notes detected (PID unknown): {notes}"
            if threat_indicators.get('has_corrupted_files'):
                return ThreatLevel.CONTAIN, "File corruption detected (PID unknown)"
            if threat_indicators.get('suspicious_extensions'):
                exts = ', '.join(threat_indicators['suspicious_extensions'])
                return ThreatLevel.CONTAIN, f"Suspicious extensions (PID unknown): {exts}"
            return ThreatLevel.ALLOW, "Unknown process — no file-based threats"

        # ─── Check evasion BEFORE whitelist ───
        evasion_score = threat_indicators.get('evasion_score', 0.0)
        evasion_override = threat_indicators.get('evasion_override_whitelist', False)

        # Critical evasion detected (shadow copy deletion, process masquerade)
        if evasion_score >= 0.8:
            indicators = threat_indicators.get('evasion_indicators', [])
            reason = f"CRITICAL EVASION (score={evasion_score:.2f}): {'; '.join(indicators[:3])}"
            return ThreatLevel.KILL, reason

        # === STEP 1: Check Whitelist (can be overridden by evasion) ===
        if info['is_whitelisted'] and not evasion_override:
            return ThreatLevel.ALLOW, f"Whitelisted: {info['signer'] or info['name']}"
        elif info['is_whitelisted'] and evasion_override:
            # Whitelist bypassed by evasion detector
            indicators = threat_indicators.get('evasion_indicators', [])
            return ThreatLevel.SUSPEND, f"WHITELIST OVERRIDE — evasion detected: {'; '.join(indicators[:2])}"

        # === STEP 2: Check for Known Ransomware Signature ===
        if threat_indicators.get('is_known_ransomware'):
            return ThreatLevel.KILL, f"KNOWN RANSOMWARE: {info['name']}"

        if threat_indicators.get('ransom_notes_found'):
            notes = ', '.join(threat_indicators['ransom_notes_found'])
            return ThreatLevel.KILL, f"Ransom notes detected: {notes}"

        # === STEP 3: Check if Process Has Visible Window ===
        if info['has_window']:
            # User is likely aware of this process — but evasion can override
            if evasion_score >= 0.5:
                return ThreatLevel.SUSPEND, f"GUI process with evasion (score={evasion_score:.2f})"
            if threat_indicators.get('has_corrupted_files'):
                return ThreatLevel.SUSPEND, "GUI process corrupting files (likely false positive)"
            else:
                return ThreatLevel.ALLOW, "Interactive process with visible window"

        # === STEP 4: Check Magic Bytes (File Corruption) ===
        if threat_indicators.get('has_corrupted_files'):
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

        # === STEP 7: Moderate Evasion Score ===
        if evasion_score >= 0.4:
            indicators = threat_indicators.get('evasion_indicators', [])
            return ThreatLevel.SUSPEND, f"Evasion behavior (score={evasion_score:.2f}): {'; '.join(indicators[:2])}"

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
            log_enforcement_result(pid, 'SUSPEND', success=True)

            return True, f"Process {pid} suspended: {reason}"

        except psutil.AccessDenied as e:
            log_enforcement_result(pid, 'SUSPEND', success=False, error=str(e), error_type='AccessDenied')
            return False, f"Failed to suspend {pid}: Access Denied — run GuardianX as Administrator"
        except psutil.NoSuchProcess as e:
            log_enforcement_result(pid, 'SUSPEND', success=False, error=str(e), error_type='NoSuchProcess')
            return False, f"Failed to suspend {pid}: Process no longer exists"
        except Exception as e:
            log_enforcement_result(pid, 'SUSPEND', success=False, error=str(e), error_type=type(e).__name__)
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
            log_enforcement_result(pid, 'KILL', success=True)

            return True, f"Process {pid} TERMINATED: {reason}"

        except psutil.AccessDenied as e:
            log_enforcement_result(pid, 'KILL', success=False, error=str(e), error_type='AccessDenied')
            return False, f"Failed to kill {pid}: Access Denied — run GuardianX as Administrator"
        except psutil.NoSuchProcess as e:
            log_enforcement_result(pid, 'KILL', success=False, error=str(e), error_type='NoSuchProcess')
            return False, f"Failed to kill {pid}: Process no longer exists (exited before enforcement)"
        except Exception as e:
            log_enforcement_result(pid, 'KILL', success=False, error=str(e), error_type=type(e).__name__)
            return False, f"Failed to kill {pid}: {e}"

    def _log_action(self, action, pid, reason):
        """Log action to JSONL file (one JSON object per line — append-safe)."""
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

        # Atomic append — no read-modify-write race
        try:
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            import logging
            logging.getLogger("GuardianX").debug(f"Log write failed: {e}")

    def get_suspended_processes(self):
        """Get list of currently suspended processes for UI/undo"""
        return list(self.suspended_processes.items())

    def get_threat_log(self, limit=50):
        """Retrieve recent threat detections from JSONL log."""
        try:
            if THREAT_LOG.exists():
                logs = []
                with open(THREAT_LOG, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                logs.append(json.loads(line))
                            except json.JSONDecodeError:
                                continue
                return logs[-limit:]
        except Exception:
            pass

        return []
