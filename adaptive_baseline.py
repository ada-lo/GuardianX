"""
GuardianX Adaptive Baseline Engine
Dynamic threshold learning using Exponential Moving Averages (EMA).

Replaces hardcoded SLOW_BURN_THRESHOLD with per-process baselines
that adapt to normal system behavior, reducing false positives and
catching subtle slow-burn attacks that stay under static thresholds.
"""

import json
import math
import logging
from time import time
from pathlib import Path
from collections import defaultdict

from config import LOG_DIR, SLOW_BURN_THRESHOLD, SLOW_BURN_WINDOW

logger = logging.getLogger("GuardianX.Baseline")

BASELINE_FILE = LOG_DIR / 'baselines.json'
BASELINE_LEARNING_HOURS = 24  # Hours of learning before baselines are trusted


class ProcessBaseline:
    """Per-process activity baseline using EMA."""
    
    __slots__ = ['ema_rate', 'ema_variance', 'sample_count', 'last_update', 'process_name']
    
    def __init__(self, process_name=None):
        self.ema_rate = 0.0       # Exponential moving average of file ops/hour
        self.ema_variance = 0.0   # EMA of squared deviation (for stddev)
        self.sample_count = 0     # Number of observations
        self.last_update = time()
        self.process_name = process_name
    
    def update(self, current_rate, alpha=0.1):
        """
        Update the EMA with a new observation.
        
        alpha: smoothing factor (0.1 = slow adaptation, 0.3 = fast)
        """
        if self.sample_count == 0:
            self.ema_rate = current_rate
            self.ema_variance = 0.0
        else:
            deviation = current_rate - self.ema_rate
            self.ema_rate = self.ema_rate + alpha * deviation
            self.ema_variance = (1 - alpha) * (self.ema_variance + alpha * deviation * deviation)
        
        self.sample_count += 1
        self.last_update = time()
    
    @property
    def stddev(self):
        """Standard deviation of the rate."""
        return math.sqrt(max(0, self.ema_variance))
    
    @property
    def dynamic_threshold(self):
        """
        Dynamic threshold = mean + 3 * stddev.
        
        But never lower than a minimum safety threshold 
        and never higher than the static fallback.
        """
        if self.sample_count < 10:
            # Not enough data — use static threshold
            return SLOW_BURN_THRESHOLD
        
        # 3-sigma threshold (catches 99.7% of normal variation)
        threshold = self.ema_rate + 3 * self.stddev
        
        # Apply safety bounds
        min_threshold = max(5, self.ema_rate * 1.5)  # At least 1.5x the average
        max_threshold = SLOW_BURN_THRESHOLD * 2       # Never above 2x static
        
        return max(min_threshold, min(threshold, max_threshold))
    
    @property
    def is_mature(self):
        """Has this baseline collected enough data to be trusted?"""
        return self.sample_count >= 30
    
    def to_dict(self):
        return {
            'ema_rate': self.ema_rate,
            'ema_variance': self.ema_variance,
            'sample_count': self.sample_count,
            'last_update': self.last_update,
            'process_name': self.process_name,
        }
    
    @classmethod
    def from_dict(cls, data):
        baseline = cls(process_name=data.get('process_name'))
        baseline.ema_rate = data.get('ema_rate', 0.0)
        baseline.ema_variance = data.get('ema_variance', 0.0)
        baseline.sample_count = data.get('sample_count', 0)
        baseline.last_update = data.get('last_update', time())
        return baseline


class AdaptiveBaseline:
    """
    Machine-level adaptive threshold engine.
    
    Tracks per-process file modification rates and builds dynamic
    thresholds based on observed normal behavior. During the learning
    period, uses generous thresholds while collecting data.
    """
    
    def __init__(self):
        self._baselines = {}         # pid → ProcessBaseline
        self._name_baselines = {}    # process_name → ProcessBaseline (persistent)
        self._start_time = time()
        self._update_interval = 60   # Update baselines every 60 seconds
        self._last_save = time()
        self._save_interval = 300    # Save to disk every 5 minutes
        
        # Global machine baseline (for unknown processes)
        self._global_baseline = ProcessBaseline(process_name="__global__")
        
        # Load persisted baselines
        self._load_profiles()
        
        logger.info(f"Adaptive Baseline engine initialized. "
                     f"{len(self._name_baselines)} persisted process profiles loaded.")
    
    def record_activity(self, pid, event_count, process_name=None):
        """
        Record file modification activity for a process.
        
        pid: Process ID
        event_count: Number of file events in the current window
        process_name: Name of the process (for persistent baseline)
        """
        # Normalize rate to events per hour
        rate_per_hour = event_count * (3600 / SLOW_BURN_WINDOW)
        
        # Update PID-level baseline
        if pid not in self._baselines:
            self._baselines[pid] = ProcessBaseline(process_name=process_name)
        self._baselines[pid].update(rate_per_hour)
        
        # Update name-level baseline (persisted across sessions)
        if process_name:
            name_key = process_name.lower()
            if name_key not in self._name_baselines:
                self._name_baselines[name_key] = ProcessBaseline(process_name=process_name)
            self._name_baselines[name_key].update(rate_per_hour)
        
        # Update global baseline
        self._global_baseline.update(rate_per_hour)
        
        # Periodic save
        if time() - self._last_save > self._save_interval:
            self.save_profiles()
            self._last_save = time()
    
    def get_threshold(self, pid, process_name=None):
        """
        Get the dynamic threshold for a process.
        
        Priority:
        1. PID-specific baseline (if mature)
        2. Process-name baseline (if mature)  
        3. Global machine baseline (if mature)
        4. Static fallback from config
        
        Returns: threshold (int)
        """
        # Check if we're still in learning mode
        if self.is_learning:
            # During learning, use 2x the static threshold to avoid false positives
            return int(SLOW_BURN_THRESHOLD * 2)
        
        # Try PID baseline
        if pid in self._baselines and self._baselines[pid].is_mature:
            return int(self._baselines[pid].dynamic_threshold)
        
        # Try name baseline
        if process_name:
            name_key = process_name.lower()
            if name_key in self._name_baselines and self._name_baselines[name_key].is_mature:
                return int(self._name_baselines[name_key].dynamic_threshold)
        
        # Try global baseline
        if self._global_baseline.is_mature:
            return int(self._global_baseline.dynamic_threshold)
        
        # Final fallback: static threshold
        return SLOW_BURN_THRESHOLD
    
    def get_baseline_info(self, pid=None, process_name=None):
        """Get human-readable baseline information for a process."""
        info = {
            'mode': 'learning' if self.is_learning else 'enforcing',
            'global_ema': round(self._global_baseline.ema_rate, 2),
            'global_stddev': round(self._global_baseline.stddev, 2),
            'global_samples': self._global_baseline.sample_count,
            'total_profiled_processes': len(self._name_baselines),
        }
        
        if pid and pid in self._baselines:
            b = self._baselines[pid]
            info['pid_ema'] = round(b.ema_rate, 2)
            info['pid_stddev'] = round(b.stddev, 2)
            info['pid_threshold'] = int(b.dynamic_threshold)
            info['pid_samples'] = b.sample_count
        
        if process_name:
            name_key = process_name.lower()
            if name_key in self._name_baselines:
                b = self._name_baselines[name_key]
                info['name_ema'] = round(b.ema_rate, 2)
                info['name_threshold'] = int(b.dynamic_threshold)
                info['name_samples'] = b.sample_count
        
        return info
    
    @property
    def is_learning(self):
        """Are we still in the learning period?"""
        hours_running = (time() - self._start_time) / 3600
        return hours_running < BASELINE_LEARNING_HOURS and self._global_baseline.sample_count < 100
    
    def save_profiles(self):
        """Persist name-level baselines to disk."""
        try:
            data = {
                'global': self._global_baseline.to_dict(),
                'processes': {
                    name: baseline.to_dict()
                    for name, baseline in self._name_baselines.items()
                },
                'saved_at': time(),
            }
            
            with open(BASELINE_FILE, 'w') as f:
                json.dump(data, f, indent=2)
            
            logger.debug(f"Saved {len(self._name_baselines)} process baselines")
            
        except Exception as e:
            logger.error(f"Failed to save baselines: {e}")
    
    def _load_profiles(self):
        """Load persisted baselines from disk."""
        try:
            if BASELINE_FILE.exists():
                with open(BASELINE_FILE, 'r') as f:
                    data = json.load(f)
                
                # Load global baseline
                if 'global' in data:
                    self._global_baseline = ProcessBaseline.from_dict(data['global'])
                
                # Load process baselines
                for name, baseline_data in data.get('processes', {}).items():
                    self._name_baselines[name] = ProcessBaseline.from_dict(baseline_data)
                
                logger.info(f"Loaded baselines from {BASELINE_FILE}")
                
        except Exception as e:
            logger.warning(f"Failed to load baselines: {e}")
    
    def cleanup_pid_baselines(self, active_pids):
        """Remove baselines for processes that no longer exist."""
        dead_pids = set(self._baselines.keys()) - set(active_pids)
        for pid in dead_pids:
            del self._baselines[pid]
