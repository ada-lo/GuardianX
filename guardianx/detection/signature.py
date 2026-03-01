"""
GuardianX Ransomware Signature Checker
Checks for known ransomware indicators:
- Process names matching known ransomware
- Ransom note creation
- Suspicious file extensions
"""

from pathlib import Path

from guardianx.config import KNOWN_RANSOMWARE_SIGNATURES


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
