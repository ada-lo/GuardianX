"""
GuardianX Detection Package
Contains the Trinity Architecture detectors, evasion detection,
adaptive baselines, and the threat assessment pipeline.
"""

from guardianx.detection.slow_burn import SlowBurnDetector
from guardianx.detection.magic_byte import MagicByteSentry
from guardianx.detection.signature import RansomwareSignatureChecker
from guardianx.detection.idle_monitor import IdleMonitor
from guardianx.detection.evasion import EvasionDetector
from guardianx.detection.adaptive_baseline import AdaptiveBaseline
from guardianx.detection.pipeline import ThreatPipeline

__all__ = [
    "SlowBurnDetector",
    "MagicByteSentry",
    "RansomwareSignatureChecker",
    "IdleMonitor",
    "EvasionDetector",
    "AdaptiveBaseline",
    "ThreatPipeline",
]
