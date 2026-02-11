"""
GuardianX Core Detectors
Implements the Trinity Architecture:
1. Slow-Burn Detector (Time-based)
2. Magic-Byte Sentry (Content-based)
3. Idle-State Hyper-Visor (Context-based)
"""

import os
import math
from collections import deque, Counter
from time import time
from pathlib import Path
import hashlib

from config import *


class SlowBurnDetector:
    """
    Tracks file modification frequency per process.
    Flags processes that touch too many files in a sliding time window.
    """
    
    def __init__(self):
        self.process_events = {}  # pid -> deque of (timestamp, filepath)
        
    def record_event(self, pid, filepath):
        """Record a file modification event"""
        now = time()
        
        if pid not in self.process_events:
            self.process_events[pid] = deque()
        
        self.process_events[pid].append((now, filepath))
        
    def check_threshold(self, pid, is_user_idle=False):
        """
        Check if process exceeds modification threshold.
        Returns (is_suspicious, count, window_size)
        """
        if pid not in self.process_events:
            return False, 0, SLOW_BURN_WINDOW
        
        now = time()
        events = self.process_events[pid]
        
        # Remove events outside the sliding window
        while events and events[0][0] < now - SLOW_BURN_WINDOW:
            events.popleft()
        
        count = len(events)
        
        # Adjust threshold based on user activity
        threshold = SLOW_BURN_THRESHOLD
        if is_user_idle:
            threshold = int(SLOW_BURN_THRESHOLD * IDLE_PARANOIA_MULTIPLIER)
        
        return count >= threshold, count, SLOW_BURN_WINDOW
    
    def get_unique_files(self, pid):
        """Get count of unique files modified (not just events)"""
        if pid not in self.process_events:
            return 0
        
        filepaths = [fp for _, fp in self.process_events[pid]]
        return len(set(filepaths))
    
    def cleanup_old_processes(self, active_pids):
        """Remove tracking data for processes that no longer exist"""
        dead_pids = set(self.process_events.keys()) - set(active_pids)
        for pid in dead_pids:
            del self.process_events[pid]


class MagicByteSentry:
    """
    Validates file integrity by checking magic bytes (file headers).
    Detects when a file's content doesn't match its extension.
    """
    
    @staticmethod
    def check_file_integrity(filepath):
        """
        Check if file header matches expected signature.
        Returns (is_valid, reason)
        """
        path = Path(filepath)
        
        if not path.exists():
            return True, "File doesn't exist yet (creation in progress)"
        
        if not path.is_file():
            return True, "Not a regular file"
        
        if path.stat().st_size == 0:
            return True, "Empty file (legitimate)"
        
        extension = path.suffix.lower()
        
        # If we don't track this extension, assume it's okay
        if extension not in FILE_SIGNATURES:
            return True, f"Unknown extension {extension} (not tracked)"
        
        # If extension has no signature (like .txt), skip magic byte check
        expected_signatures = FILE_SIGNATURES[extension]
        if expected_signatures is None:
            return True, f"No magic bytes defined for {extension}"
        
        # Read the file header
        try:
            with open(filepath, 'rb') as f:
                header = f.read(16)  # Read first 16 bytes
        except (PermissionError, IOError) as e:
            return True, f"Cannot read file: {e}"
        
        # Check if header matches any expected signature
        for signature in expected_signatures:
            if header.startswith(signature):
                return True, f"Valid {extension} signature"
        
        # Header doesn't match - file is corrupted or encrypted
        return False, f"CORRUPTED: Expected {extension} signature, got {header[:8].hex()}"
    
    @staticmethod
    def calculate_entropy(filepath, sample_size=8192):
        """
        Calculate Shannon entropy of file content.
        High entropy (>7.5) suggests encryption/compression.
        Returns (entropy, reason)
        """
        try:
            with open(filepath, 'rb') as f:
                data = f.read(sample_size)
            
            if not data:
                return 0.0, "Empty file"
            
            # Count byte frequencies
            byte_counts = Counter(data)
            
            # Calculate Shannon entropy
            entropy = 0.0
            for count in byte_counts.values():
                probability = count / len(data)
                entropy -= probability * math.log2(probability)
            
            if entropy > HIGH_ENTROPY_THRESHOLD:
                return entropy, f"HIGH ENTROPY ({entropy:.2f}) - likely encrypted"
            else:
                return entropy, f"Normal entropy ({entropy:.2f})"
                
        except Exception as e:
            return 0.0, f"Error calculating entropy: {e}"


class RansomwareSignatureChecker:
    """
    Checks for known ransomware indicators:
    - Process names matching known ransomware
    - Ransom note creation
    - Suspicious file extensions
    """
    
    @staticmethod
    def check_process_name(process_name):
        """
        Check if process name matches known ransomware.
        Returns (is_known_threat, threat_name)
        """
        process_name_lower = process_name.lower()
        
        for known_name in KNOWN_RANSOMWARE_SIGNATURES['process_names']:
            if known_name.lower() in process_name_lower:
                return True, known_name
        
        return False, None
    
    @staticmethod
    def check_ransom_note(filepath):
        """
        Check if file is a known ransom note filename.
        Returns (is_ransom_note, note_type)
        """
        filename = Path(filepath).name
        
        for note_name in KNOWN_RANSOMWARE_SIGNATURES['ransom_note_filenames']:
            if note_name.lower() == filename.lower():
                return True, note_name
        
        return False, None
    
    @staticmethod
    def check_suspicious_extension(filepath):
        """
        Check if file has a suspicious ransomware extension.
        Returns (is_suspicious, extension)
        """
        extension = Path(filepath).suffix.lower()
        
        if extension in KNOWN_RANSOMWARE_SIGNATURES['file_extensions']:
            return True, extension
        
        return False, None
    
    @staticmethod
    def scan_directory_for_ransom_notes(directory):
        """
        Quick scan of directory for ransom notes.
        Returns list of found ransom notes.
        """
        ransom_notes = []
        
        try:
            for item in Path(directory).iterdir():
                if item.is_file():
                    is_note, _ = RansomwareSignatureChecker.check_ransom_note(str(item))
                    if is_note:
                        ransom_notes.append(str(item))
        except Exception:
            pass
        
        return ransom_notes


class IdleMonitor:
    """
    Tracks user activity (keyboard/mouse) to determine idle state.
    Uses platform-specific APIs.
    """
    
    def __init__(self):
        self.last_activity_time = time()
        self.is_idle = False
        
    def update_activity(self):
        """Mark that user is active (called by input listener)"""
        self.last_activity_time = time()
        self.is_idle = False
    
    def check_idle_state(self):
        """
        Check if user is currently idle.
        Returns (is_idle, idle_duration_seconds)
        """
        now = time()
        idle_duration = now - self.last_activity_time
        
        self.is_idle = idle_duration > IDLE_TIMEOUT
        
        return self.is_idle, idle_duration
    
    def get_idle_level(self):
        """
        Get paranoia level based on idle duration.
        Returns string: 'active', 'idle_short', 'idle_long'
        """
        is_idle, duration = self.check_idle_state()
        
        if not is_idle:
            return 'active'
        elif duration < IDLE_TIMEOUT * 3:  # < 15 minutes
            return 'idle_short'
        else:
            return 'idle_long'  # > 15 minutes - maximum paranoia
