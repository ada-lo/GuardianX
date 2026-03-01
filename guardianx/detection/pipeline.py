"""
GuardianX Threat Assessment Pipeline
Extracted from the monolithic GuardianX._assess_threat() method.

Runs all threat detectors in sequence, merges indicators into
a single dict that the ProcessManager decision tree consumes.
"""

import logging
from pathlib import Path

from guardianx.config import KNOWN_RANSOMWARE_SIGNATURES

logger = logging.getLogger("GuardianX.Pipeline")


class ThreatPipeline:
    """
    Runs every detector on a file event and returns merged threat indicators.

    Accepts subsystem instances via constructor (dependency injection)
    so the pipeline can be tested with mocks.
    """

    def __init__(self, slow_burn, magic_sentry, signature_checker,
                 idle_monitor, adaptive_baseline, evasion_detector):
        self.slow_burn = slow_burn
        self.magic_sentry = magic_sentry
        self.signature_checker = signature_checker
        self.idle_monitor = idle_monitor
        self.adaptive_baseline = adaptive_baseline
        self.evasion_detector = evasion_detector

    def assess(self, pid, filepath, event_type, proc_info=None):
        """
        Run all threat detectors and compile indicators.

        Args:
            pid:        Process ID (may be None).
            filepath:   Path to the affected file.
            event_type: 'created', 'modified', or 'deleted'.
            proc_info:  Dict from ProcessManager.get_process_info (may be None).
                        Passed through to avoid duplicate lookups.

        Returns:
            Dict of threat indicators consumed by ProcessManager.decide_action().
        """
        indicators = {}

        # 1. Check for known ransomware signature
        if proc_info:
            is_known, threat_name = self.signature_checker.check_process_name(proc_info['name'])
            indicators['is_known_ransomware'] = is_known
        else:
            indicators['is_known_ransomware'] = False

        # 2. Check for ransom notes
        parent_dir = Path(filepath).parent
        ransom_notes = self.signature_checker.scan_directory_for_ransom_notes(parent_dir)
        indicators['ransom_notes_found'] = ransom_notes

        # 3. Check magic bytes (file corruption)
        if event_type in ['modified', 'created']:
            is_valid, reason = self.magic_sentry.check_file_integrity(filepath)
            indicators['has_corrupted_files'] = not is_valid

            if not is_valid:
                # Also check entropy
                entropy, entropy_reason = self.magic_sentry.calculate_entropy(filepath)
                indicators['file_entropy'] = entropy
        else:
            indicators['has_corrupted_files'] = False

        # 4. Check file modification rate (slow-burn) — with ADAPTIVE THRESHOLD
        is_user_idle, idle_duration = self.idle_monitor.check_idle_state()

        if pid is not None:
            proc_name = proc_info['name'] if proc_info else None
            dynamic_threshold = self.adaptive_baseline.get_threshold(pid, proc_name)
            is_suspicious, count, window = self.slow_burn.check_threshold(
                pid, is_user_idle, dynamic_threshold=dynamic_threshold
            )
            indicators['high_file_rate'] = is_suspicious
            indicators['file_count'] = count
            indicators['dynamic_threshold'] = dynamic_threshold
        else:
            indicators['high_file_rate'] = False
            indicators['file_count'] = 0
            indicators['dynamic_threshold'] = 0

        # 5. Check for suspicious extensions
        is_sus_ext, ext = self.signature_checker.check_suspicious_extension(filepath)
        indicators['suspicious_extensions'] = [ext] if is_sus_ext else []

        # 6. User idle state
        indicators['is_user_idle'] = is_user_idle
        indicators['idle_duration'] = idle_duration

        # 7. Evasion detection
        if pid is not None:
            evasion_result = self.evasion_detector.get_evasion_score(pid)
            indicators['evasion_score'] = evasion_result.get('score', 0.0)
            indicators['evasion_indicators'] = evasion_result.get('indicators', [])
            indicators['evasion_override_whitelist'] = evasion_result.get('should_override_whitelist', False)
        else:
            indicators['evasion_score'] = 0.0
            indicators['evasion_indicators'] = []
            indicators['evasion_override_whitelist'] = False

        return indicators
