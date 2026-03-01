"""
GuardianX Whitelist Manager
Handles trust-checking: process whitelist, digital signature verification,
and visible-window heuristic.
"""

from guardianx.config import WHITELISTED_PROCESSES, TRUSTED_SIGNERS


class WhitelistManager:
    """
    Determines whether a process should be trusted based on:
    - Process name whitelist
    - Digital signature / trusted signer
    - Visible GUI window (heuristic: malware typically runs headless)
    """

    def is_whitelisted(self, process_name, signer_name):
        """Check if process is on the whitelist or has a trusted signer."""
        if process_name in WHITELISTED_PROCESSES:
            return True

        if signer_name and signer_name in TRUSTED_SIGNERS:
            return True

        return False

    def check_digital_signature(self, exe_path):
        """
        Check if executable is digitally signed and by whom.
        Returns (is_signed, signer_name).

        NOTE: This is a simplified check — a full implementation would use
        wintrust.dll / Authenticode verification.
        """
        try:
            path_lower = exe_path.lower()

            # Windows system files are always trusted
            if 'windows\\system32' in path_lower or 'windows\\syswow64' in path_lower:
                return True, 'Microsoft Windows'

            # TODO: Implement proper Authenticode signature verification
            # Would use: win32api.GetFileVersionInfo() or ctypes + wintrust.dll

            return False, None

        except Exception:
            return False, None

    def has_visible_window(self, pid):
        """
        Check if process has a visible GUI window.
        Malware typically runs headless.
        """
        try:
            import win32gui
            import win32process

            def callback(hwnd, windows):
                if win32gui.IsWindowVisible(hwnd):
                    _, found_pid = win32process.GetWindowThreadProcessId(hwnd)
                    if found_pid == pid:
                        windows.append(hwnd)
                return True

            windows = []
            win32gui.EnumWindows(callback, windows)

            return len(windows) > 0

        except Exception:
            return False
