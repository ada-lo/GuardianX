"""
GuardianX Whitelist Manager
Handles trust-checking: process whitelist, digital signature verification,
and visible-window heuristic.
"""

import ctypes
import logging
import os

from guardianx.config import WHITELISTED_PROCESSES, TRUSTED_SIGNERS

logger = logging.getLogger("GuardianX.Whitelist")

# ─── Authenticode Verification via wintrust.dll ──────────────────────────────
# WinVerifyTrust constants
WINTRUST_ACTION_GENERIC_VERIFY_V2 = (0xAAC56B, 0xCD44, 0x11D0, 
    (0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))
WTD_UI_NONE = 2
WTD_CHOICE_FILE = 1
WTD_REVOKE_NONE = 0
WTD_STATEACTION_VERIFY = 1


class WhitelistManager:
    """
    Determines whether a process should be trusted based on:
    - Process name whitelist
    - Digital signature verification (Authenticode via wintrust.dll)
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
        Check if executable is digitally signed using Authenticode (wintrust.dll).
        Returns (is_signed, signer_name).
        
        Uses WinVerifyTrust for actual cryptographic signature verification,
        not just path-prefix heuristics.
        """
        if not exe_path or not os.path.isfile(exe_path):
            return False, None

        # Method 1: Try Authenticode via wintrust.dll (ctypes)
        try:
            signed = self._verify_authenticode(exe_path)
            if signed:
                # Get signer name
                signer = self._get_signer_name(exe_path)
                return True, signer
        except Exception as e:
            logger.debug(f"Authenticode check failed for {exe_path}: {e}")

        # Method 2: Windows system files are trusted by path
        # (only after Authenticode is attempted)
        try:
            path_lower = exe_path.lower()
            if 'windows\\system32' in path_lower or 'windows\\syswow64' in path_lower:
                return True, 'Microsoft Windows'
        except Exception:
            pass

        return False, None

    def _verify_authenticode(self, filepath):
        """
        Verify Authenticode signature using WinVerifyTrust.
        Returns True if the file has a valid signature.
        """
        try:
            # Define WINTRUST_FILE_INFO
            class WINTRUST_FILE_INFO(ctypes.Structure):
                _fields_ = [
                    ('cbStruct', ctypes.c_uint),
                    ('pcwszFilePath', ctypes.c_wchar_p),
                    ('hFile', ctypes.c_void_p),
                    ('pgKnownSubject', ctypes.c_void_p),
                ]

            # Define GUID
            class GUID(ctypes.Structure):
                _fields_ = [
                    ('Data1', ctypes.c_ulong),
                    ('Data2', ctypes.c_ushort),
                    ('Data3', ctypes.c_ushort),
                    ('Data4', ctypes.c_ubyte * 8),
                ]

            # Define WINTRUST_DATA
            class WINTRUST_DATA(ctypes.Structure):
                _fields_ = [
                    ('cbStruct', ctypes.c_uint),
                    ('pPolicyCallbackData', ctypes.c_void_p),
                    ('pSIPClientData', ctypes.c_void_p),
                    ('dwUIChoice', ctypes.c_uint),
                    ('fdwRevocationChecks', ctypes.c_uint),
                    ('dwUnionChoice', ctypes.c_uint),
                    ('pFile', ctypes.POINTER(WINTRUST_FILE_INFO)),
                    ('dwStateAction', ctypes.c_uint),
                    ('hWVTStateData', ctypes.c_void_p),
                    ('pwszURLReference', ctypes.c_wchar_p),
                    ('dwProvFlags', ctypes.c_uint),
                    ('dwUIContext', ctypes.c_uint),
                ]

            # Set up the file info
            file_info = WINTRUST_FILE_INFO()
            file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
            file_info.pcwszFilePath = filepath

            # Set up the GUID for generic verify
            action_id = GUID()
            action_id.Data1 = 0x00AAC56B
            action_id.Data2 = 0xCD44
            action_id.Data3 = 0x11D0
            action_id.Data4 = (ctypes.c_ubyte * 8)(
                0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE
            )

            # Set up trust data
            trust_data = WINTRUST_DATA()
            trust_data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
            trust_data.dwUIChoice = WTD_UI_NONE
            trust_data.fdwRevocationChecks = WTD_REVOKE_NONE
            trust_data.dwUnionChoice = WTD_CHOICE_FILE
            trust_data.pFile = ctypes.pointer(file_info)
            trust_data.dwStateAction = WTD_STATEACTION_VERIFY

            # Call WinVerifyTrust
            wintrust = ctypes.windll.wintrust
            result = wintrust.WinVerifyTrust(
                0,  # INVALID_HANDLE_VALUE for no UI
                ctypes.byref(action_id),
                ctypes.byref(trust_data),
            )

            # 0 = signature valid, non-zero = invalid or unsigned
            return result == 0

        except Exception:
            return False

    def _get_signer_name(self, filepath):
        """
        Get the signer name from a signed executable.
        Tries pywin32 first, falls back to path-based heuristic.
        """
        try:
            import win32api
            info = win32api.GetFileVersionInfo(filepath, '\\')
            # Try to get CompanyName from version info
            try:
                lang, codepage = win32api.GetFileVersionInfo(
                    filepath, '\\VarFileInfo\\Translation'
                )[0]
                company = win32api.GetFileVersionInfo(
                    filepath,
                    f'\\StringFileInfo\\{lang:04x}{codepage:04x}\\CompanyName'
                )
                if company:
                    return company
            except Exception:
                pass
        except Exception:
            pass

        # Fallback: infer from path
        path_lower = filepath.lower()
        if 'windows' in path_lower:
            return 'Microsoft Windows'
        if 'program files' in path_lower:
            # Use the first subfolder name as a rough signer
            try:
                parts = filepath.split(os.sep)
                for i, part in enumerate(parts):
                    if 'program files' in part.lower() and i + 1 < len(parts):
                        return parts[i + 1]
            except Exception:
                pass

        return None

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
