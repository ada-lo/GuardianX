"""
GuardianX Magic-Byte Sentry (Content-based)
Validates file integrity by checking magic bytes (file headers).
Detects when a file's content doesn't match its extension.
"""

import math
from collections import Counter
from pathlib import Path

from guardianx.config import FILE_SIGNATURES, HIGH_ENTROPY_THRESHOLD


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
