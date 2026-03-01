"""
GuardianX Configuration
Stores thresholds, known ransomware signatures, and trusted certificates
"""

import os
from pathlib import Path

# === DETECTION THRESHOLDS ===
SLOW_BURN_THRESHOLD = 50  # files modified
SLOW_BURN_WINDOW = 3600   # in 1 hour (seconds)

IDLE_TIMEOUT = 300  # 5 minutes of no keyboard/mouse activity
IDLE_PARANOIA_MULTIPLIER = 0.3  # When idle, reduce threshold to 30% (15 files/hour)

# === FILE SIGNATURES (Magic Bytes) ===
# First 4-8 bytes that identify legitimate file types
FILE_SIGNATURES = {
    '.pdf': [b'%PDF'],
    '.jpg': [b'\xFF\xD8\xFF'],
    '.jpeg': [b'\xFF\xD8\xFF'],
    '.png': [b'\x89PNG'],
    '.gif': [b'GIF87a', b'GIF89a'],
    '.zip': [b'PK\x03\x04', b'PK\x05\x06'],
    '.docx': [b'PK\x03\x04'],  # DOCX is a ZIP container
    '.xlsx': [b'PK\x03\x04'],
    '.pptx': [b'PK\x03\x04'],
    '.exe': [b'MZ'],
    '.dll': [b'MZ'],
    '.mp4': [b'\x00\x00\x00\x18ftypmp42', b'\x00\x00\x00\x1cftypmp42'],
    '.mp3': [b'ID3', b'\xFF\xFB'],
    '.avi': [b'RIFF'],
    '.txt': None,  # Text files have no magic bytes (too variable)
    '.log': None,
}

# === KNOWN RANSOMWARE SIGNATURES ===
# These are hashes/patterns of confirmed ransomware
# In production, this would be updated from a threat intelligence feed
KNOWN_RANSOMWARE_SIGNATURES = {
    'process_names': [
        'wannacry.exe',
        'cryptolocker.exe',
        'revil.exe',
        'ryuk.exe',
        'conti.exe',
        'lockbit.exe',
    ],
    'file_extensions': [
        '.locked',
        '.encrypted',
        '.crypt',
        '.wannacry',
        '.ryuk',
        '.conti',
        '.lockbit',
        '.revil',
        '.cerber',
        '.locky',
        '.zepto',
        '.odin',
        '.shit',
        '.fucked',
    ],
    'ransom_note_filenames': [
        'README.txt',
        'HOW_TO_DECRYPT.txt',
        'DECRYPT_INSTRUCTIONS.txt',
        'YOUR_FILES_ARE_ENCRYPTED.txt',
        'README_FOR_DECRYPT.txt',
        '!!!_IMPORTANT_!!!.txt',
        'HELP_DECRYPT.txt',
    ]
}

# === TRUSTED DIGITAL SIGNATURES ===
# Processes signed by these entities are trusted
TRUSTED_SIGNERS = [
    'Microsoft Corporation',
    'Microsoft Windows',
    'Google LLC',
    'Apple Inc.',
    'Adobe Inc.',
    'Mozilla Corporation',
    'Dropbox, Inc.',
    'NVIDIA Corporation',
    'Intel Corporation',
    'Valve Corp.',
]

# === PROCESS WHITELIST ===
# Known safe processes that may modify many files
WHITELISTED_PROCESSES = [
    'explorer.exe',
    'MsMpEng.exe',      # Windows Defender
    'OneDrive.exe',
    'Dropbox.exe',
    'Google Drive.exe',
    'steam.exe',
    'chrome.exe',
    'firefox.exe',
    'notepad.exe',
    'Code.exe',         # VS Code
    'devenv.exe',       # Visual Studio   
    'powershell.exe',   # Be careful with this!
]

# === LOGGING ===
LOG_DIR = Path(os.getenv('TEMP')) / 'GuardianX' / 'logs'
LOG_DIR.mkdir(parents=True, exist_ok=True)

THREAT_LOG = LOG_DIR / 'threats.json'
SUSPEND_LOG = LOG_DIR / 'suspended.json'
ACTIVITY_LOG = LOG_DIR / 'activity.json'

# === ACTIONS ===
class ThreatLevel:
    ALLOW = 0
    SUSPEND = 1
    KILL = 2

# === ENTROPY THRESHOLD ===
# Files with very high entropy (randomness) are likely encrypted
# Scale: 0 (all same byte) to 8 (perfect randomness)
HIGH_ENTROPY_THRESHOLD = 7.5

# === ADAPTIVE BASELINE (Gap 4) ===
BASELINE_LEARNING_HOURS = 24       # Hours to learn normal patterns before enforcing
BASELINE_EMA_ALPHA = 0.1           # EMA smoothing factor (lower = smoother)
BASELINE_SIGMA_MULTIPLIER = 3.0    # Standard deviations above mean for threshold
BASELINE_MIN_SAMPLES = 20          # Minimum samples before baseline is "mature"
BASELINE_FILE = LOG_DIR / 'baselines.json'

# === FILE BACKUP & RECOVERY (Gap 2) ===
BACKUP_DIR = Path(os.getenv('TEMP')) / 'GuardianX' / 'backups'
BACKUP_DIR.mkdir(parents=True, exist_ok=True)
MAX_BACKUP_SIZE_MB = 500           # Maximum total backup storage
BACKUP_RETENTION_HOURS = 72        # Keep backups for 3 days

# === DASHBOARD (Gap 3) ===
DASHBOARD_HOST = "0.0.0.0"
DASHBOARD_PORT = 9090
