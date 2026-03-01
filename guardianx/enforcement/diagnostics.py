"""
GuardianX Enforcement Diagnostics
Detailed logging for debugging why detected threats are not being terminated/suspended.

Logs to both console and enforcement_debug.log.
Does NOT modify detection thresholds or logic.
"""

import os
import sys
import time
import logging
import psutil
from datetime import datetime
from pathlib import Path

# ─── Set up dual logging (console + file) ─────────────────────────────────────

_diag_logger = logging.getLogger("ENFORCEMENT_DEBUG")
_diag_logger.setLevel(logging.DEBUG)
_diag_logger.propagate = False  # Don't double-print via root logger

# Console handler
_console_handler = logging.StreamHandler(sys.stdout)
_console_handler.setLevel(logging.DEBUG)
_console_handler.setFormatter(logging.Formatter(
    '[ENFORCEMENT_DEBUG] %(levelname)s: %(message)s'
))
_diag_logger.addHandler(_console_handler)

# File handler — enforcement_debug.log in the project directory
_log_file = Path(__file__).parent / "enforcement_debug.log"
_file_handler = logging.FileHandler(str(_log_file), mode='a', encoding='utf-8')
_file_handler.setLevel(logging.DEBUG)
_file_handler.setFormatter(logging.Formatter(
    '%(asctime)s [ENFORCEMENT_DEBUG] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
))
_diag_logger.addHandler(_file_handler)


def check_admin():
    """Check and log whether GuardianX is running with administrator privileges."""
    try:
        import ctypes
        is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        is_admin = False
    _diag_logger.info(f"Admin privileges: {is_admin}")
    return is_admin


def log_etw_attribution(filepath):
    """Log when ETW/legacy attribution fails to find a PID for a file event."""
    _diag_logger.warning(
        f"Attribution failed: No PID found for file event — {filepath}"
    )


def log_detection_context(filepath, pid, threat_indicators, action, reason):
    """
    Log comprehensive detection context when a threat action (KILL/SUSPEND) is decided.

    Includes: timestamp, filepath, PID, process name, parent info, PID existence,
    threat score, admin status, and whether process is still running.
    """
    timestamp = datetime.now().isoformat()
    is_admin = check_admin()

    proc_name = "<unknown>"
    parent_pid = None
    parent_name = "<unknown>"
    pid_exists = False
    process_running = False

    if pid is not None:
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            pid_exists = True
            process_running = proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE
            try:
                parent = proc.parent()
                if parent:
                    parent_pid = parent.pid
                    parent_name = parent.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        except psutil.NoSuchProcess:
            pid_exists = False
        except psutil.AccessDenied:
            pid_exists = True  # Exists but can't read details
            proc_name = "<access denied>"

    # Compute an aggregate threat score from indicators
    threat_score = _compute_threat_score(threat_indicators)

    _diag_logger.info("=" * 70)
    _diag_logger.info("DETECTION CONTEXT")
    _diag_logger.info(f"  Timestamp           : {timestamp}")
    _diag_logger.info(f"  File path           : {filepath}")
    _diag_logger.info(f"  Detected PID        : {pid}")
    _diag_logger.info(f"  Process name        : {proc_name}")
    _diag_logger.info(f"  Parent PID          : {parent_pid}")
    _diag_logger.info(f"  Parent process name : {parent_name}")
    _diag_logger.info(f"  PID exists now      : {pid_exists}")
    _diag_logger.info(f"  Process still running: {process_running}")
    _diag_logger.info(f"  Threat score        : {threat_score:.2f}")
    _diag_logger.info(f"  Admin privileges    : {is_admin}")
    _diag_logger.info(f"  Decision            : {action}")
    _diag_logger.info(f"  Reason              : {reason}")
    _diag_logger.info(f"  Indicators          : {threat_indicators}")
    _diag_logger.info("=" * 70)


def log_pre_enforcement(pid, action_type):
    """Log immediately before calling terminate() or suspend()."""
    _diag_logger.info(f"Attempting enforcement ({action_type}) on PID {pid}")
    _diag_logger.info(f"  Admin privileges: {check_admin()}")


def log_enforcement_result(pid, action_type, success, error=None, error_type=None):
    """Log the result of a terminate()/suspend() call."""
    if success:
        _diag_logger.info(f"Enforcement SUCCESS: {action_type} on PID {pid} returned successfully")
    else:
        _diag_logger.error(
            f"Enforcement FAILED: {action_type} on PID {pid} — "
            f"error_type={error_type}, error={error}"
        )

    # Post-enforcement existence check
    try:
        proc = psutil.Process(pid)
        still_running = proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE
        _diag_logger.info(
            f"  Post-enforcement check: PID {pid} still exists={True}, "
            f"still running={still_running}, status={proc.status()}"
        )
    except psutil.NoSuchProcess:
        _diag_logger.info(f"  Post-enforcement check: PID {pid} no longer exists (confirmed terminated)")
    except psutil.AccessDenied:
        _diag_logger.info(f"  Post-enforcement check: PID {pid} exists but access denied")


def log_race_condition_check(pid):
    """
    Add a 500ms delay before enforcement, then re-check if PID still exists.
    Returns True if process is still alive, False if it exited.
    """
    _diag_logger.info(f"Race condition check: sleeping 500ms before enforcement on PID {pid}...")
    time.sleep(0.5)

    if pid is None:
        _diag_logger.warning(f"Race condition check: PID is None, cannot re-check")
        return False

    try:
        proc = psutil.Process(pid)
        is_running = proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE
        if is_running:
            _diag_logger.info(
                f"Race condition check: PID {pid} is STILL RUNNING "
                f"(name={proc.name()}, status={proc.status()})"
            )
            return True
        else:
            _diag_logger.warning(
                f"Process exited before enforcement — PID {pid} "
                f"has status={proc.status()}"
            )
            return False
    except psutil.NoSuchProcess:
        _diag_logger.warning(f"Process exited before enforcement — PID {pid} no longer exists")
        return False
    except psutil.AccessDenied:
        _diag_logger.info(f"Race condition check: PID {pid} exists but access denied (assuming alive)")
        return True


def _compute_threat_score(indicators):
    """Compute an aggregate threat score from threat indicators (0.0 – 1.0)."""
    score = 0.0
    weights = {
        'is_known_ransomware': 1.0,
        'has_corrupted_files': 0.7,
        'high_file_rate': 0.5,
        'is_user_idle': 0.2,
        'evasion_score': 0.0,  # Use raw value
    }

    if indicators.get('is_known_ransomware'):
        score += weights['is_known_ransomware']
    if indicators.get('has_corrupted_files'):
        score += weights['has_corrupted_files']
    if indicators.get('high_file_rate'):
        score += weights['high_file_rate']
    if indicators.get('is_user_idle'):
        score += weights['is_user_idle']
    if indicators.get('ransom_notes_found'):
        score += 0.9
    if indicators.get('suspicious_extensions'):
        score += 0.4

    # Add raw evasion score
    score += indicators.get('evasion_score', 0.0)

    # Clamp to [0, 1]
    return min(score, 1.0)
