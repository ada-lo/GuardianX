"""
GuardianX Slow-Burn Detector (Time-based)
Tracks file modification frequency per process.
Flags processes that touch too many files in a sliding time window.
"""

from collections import deque
from time import time

from guardianx.config import (
    SLOW_BURN_THRESHOLD,
    SLOW_BURN_WINDOW,
    IDLE_PARANOIA_MULTIPLIER,
)


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

    def check_threshold(self, pid, is_user_idle=False, dynamic_threshold=None):
        """
        Check if process exceeds modification threshold.

        dynamic_threshold: If provided (from AdaptiveBaseline), overrides
                          the static SLOW_BURN_THRESHOLD from config.

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

        # Use adaptive threshold if provided, else static
        base_threshold = dynamic_threshold if dynamic_threshold is not None else SLOW_BURN_THRESHOLD

        # Adjust threshold based on user activity
        threshold = base_threshold
        if is_user_idle:
            threshold = int(base_threshold * IDLE_PARANOIA_MULTIPLIER)

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
