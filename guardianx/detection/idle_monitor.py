"""
GuardianX Idle-State Hyper-Visor (Context-based)
Tracks user activity using Win32 GetLastInputInfo API.
Uses real keyboard/mouse idle time from the OS.
"""

import ctypes
import ctypes.wintypes
import logging

from guardianx.config import IDLE_TIMEOUT

logger = logging.getLogger("GuardianX.IdleMonitor")


class LASTINPUTINFO(ctypes.Structure):
    """Win32 LASTINPUTINFO structure for GetLastInputInfo()."""
    _fields_ = [
        ('cbSize', ctypes.wintypes.UINT),
        ('dwTime', ctypes.wintypes.DWORD),
    ]


class IdleMonitor:
    """
    Tracks real user activity (keyboard/mouse) via Win32 API.
    
    Previous implementation used a manual timer that was never updated,
    causing the system to always think the user was idle after 5 minutes.
    
    Now uses GetLastInputInfo() which returns the OS-tracked last input time.
    """

    def __init__(self):
        self.is_idle = False
        self._api_available = True
        
        # Test the API on init
        try:
            lii = LASTINPUTINFO()
            lii.cbSize = ctypes.sizeof(LASTINPUTINFO)
            result = ctypes.windll.user32.GetLastInputInfo(ctypes.byref(lii))
            if not result:
                logger.warning("GetLastInputInfo returned False — falling back to timer")
                self._api_available = False
        except Exception as e:
            logger.warning(f"GetLastInputInfo not available: {e}")
            self._api_available = False

    def check_idle_state(self):
        """
        Check if user is currently idle using real OS input tracking.
        
        Uses Win32 GetLastInputInfo() which tracks the last keyboard/mouse
        event at kernel level — no manual update_activity() calls needed.
        
        Returns (is_idle, idle_duration_seconds)
        """
        if not self._api_available:
            # Fallback: assume user is active (safe default — avoids over-escalation)
            self.is_idle = False
            return False, 0.0
        
        try:
            lii = LASTINPUTINFO()
            lii.cbSize = ctypes.sizeof(LASTINPUTINFO)
            ctypes.windll.user32.GetLastInputInfo(ctypes.byref(lii))
            
            # GetTickCount and dwTime are both in milliseconds since boot
            current_tick = ctypes.windll.kernel32.GetTickCount()
            idle_millis = current_tick - lii.dwTime
            
            # Handle tick count wraparound (every ~49 days)
            if idle_millis < 0:
                idle_millis += 0xFFFFFFFF
            
            idle_duration = idle_millis / 1000.0
            self.is_idle = idle_duration > IDLE_TIMEOUT
            
            return self.is_idle, idle_duration
            
        except Exception:
            # On error, assume active (safe default)
            self.is_idle = False
            return False, 0.0

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

    def update_activity(self):
        """Legacy method — no longer needed with GetLastInputInfo().
        Kept for API compatibility but does nothing."""
        pass
