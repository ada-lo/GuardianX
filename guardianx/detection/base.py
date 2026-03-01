"""
GuardianX Detector ABC
Common interface for all threat detection modules.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional


class Detector(ABC):
    """
    Abstract base class for all GuardianX detectors.

    Every detector must implement `analyze()` which receives
    file event context and returns a dict of threat indicators
    to merge into the overall assessment.
    """

    @abstractmethod
    def analyze(
        self,
        filepath: str,
        event_type: str,
        pid: Optional[int],
        proc_info: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Analyze a file event and return threat indicators.

        Args:
            filepath:   Path of the affected file.
            event_type: One of 'created', 'modified', 'deleted'.
            pid:        Process ID (may be None if attribution failed).
            proc_info:  Dict from ProcessManager.get_process_info (may be None).

        Returns:
            Dict of indicator_name → value to merge into the threat assessment.
        """
        ...
