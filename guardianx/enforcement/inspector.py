"""
GuardianX Process Inspector
Gathers comprehensive process information without performing any control actions.
"""

import psutil
from guardianx.enforcement.whitelist import WhitelistManager


class ProcessInspector:
    """
    Read-only process introspection.
    Gathers name, exe, cmdline, user, signature, window, and whitelist status.
    """

    def __init__(self, whitelist_manager=None):
        self.whitelist = whitelist_manager or WhitelistManager()

    def get_process_info(self, pid):
        """
        Get comprehensive information about a process.
        Returns dict with: pid, name, exe, cmdline, create_time, username,
        is_signed, signer, has_window, is_whitelisted.
        Returns None if process doesn't exist or is inaccessible.
        """
        try:
            proc = psutil.Process(pid)

            info = {
                'pid': pid,
                'name': proc.name(),
                'exe': proc.exe(),
                'cmdline': ' '.join(proc.cmdline()),
                'create_time': proc.create_time(),
                'username': proc.username(),
            }

            # Check digital signature (Windows-specific)
            info['is_signed'], info['signer'] = self.whitelist.check_digital_signature(info['exe'])

            # Check if process has visible window
            info['has_window'] = self.whitelist.has_visible_window(pid)

            # Check if in whitelist
            info['is_whitelisted'] = self.whitelist.is_whitelisted(info['name'], info['signer'])

            return info

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None
