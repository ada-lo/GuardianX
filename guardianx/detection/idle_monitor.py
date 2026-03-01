"""
GuardianX Idle-State Hyper-Visor (Context-based)
Tracks user activity (keyboard/mouse) to determine idle state.
Uses platform-specific APIs.
"""

from time import time

from guardianx.config import IDLE_TIMEOUT


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
