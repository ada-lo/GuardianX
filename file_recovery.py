"""
GuardianX File Recovery Manager
Automatic file backup before modification and Volume Shadow Copy restore.

Provides the critical capability to UNDO ransomware damage:
- Pre-modification backup of files being modified
- Restore from local backup cache
- Volume Shadow Copy (VSS) integration for system-level restore
"""

import os
import shutil
import hashlib
import json
import subprocess
import logging
from pathlib import Path
from datetime import datetime
from collections import OrderedDict

from config import LOG_DIR

logger = logging.getLogger("GuardianX.Recovery")

# Backup configuration
BACKUP_DIR = Path(os.getenv('TEMP')) / 'GuardianX' / 'backups'
BACKUP_DIR.mkdir(parents=True, exist_ok=True)

BACKUP_INDEX = LOG_DIR / 'backup_index.json'
MAX_BACKUP_SIZE_MB = 500  # Maximum total backup size in MB
MAX_FILE_SIZE_MB = 50     # Skip files larger than this


class FileRecoveryManager:
    """
    Manages file backup and recovery operations.
    
    Workflow:
    1. Before a file modification is analyzed, backup_file() creates
       a timestamped copy in the backup directory.
    2. If a threat is detected and the process is killed, restore_file()
       can recover the original content.
    3. For files not in the backup cache, restore_from_vss() attempts
       to use Windows Volume Shadow Copy.
    """
    
    def __init__(self):
        self._backup_index = self._load_index()
        self._total_size = self._calculate_total_size()
        logger.info(f"File Recovery Manager initialized. Backups: {len(self._backup_index)} files, "
                     f"{self._total_size / (1024*1024):.1f}MB used")
    
    def backup_file(self, filepath):
        """
        Create a backup copy of a file before it's potentially corrupted.
        
        Returns: (success: bool, backup_path: str or None)
        """
        try:
            filepath = Path(filepath)
            
            if not filepath.exists() or not filepath.is_file():
                return False, None
            
            # Skip very large files
            file_size = filepath.stat().st_size
            if file_size > MAX_FILE_SIZE_MB * 1024 * 1024:
                logger.debug(f"Skipping backup of {filepath.name} ({file_size/(1024*1024):.1f}MB > {MAX_FILE_SIZE_MB}MB limit)")
                return False, None
            
            # Skip empty files
            if file_size == 0:
                return False, None
            
            # Generate backup filename using content hash + timestamp
            file_hash = self._quick_hash(filepath)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Check if we already have an identical backup
            filepath_key = str(filepath).lower()
            if filepath_key in self._backup_index:
                existing = self._backup_index[filepath_key]
                if existing.get('hash') == file_hash:
                    # File hasn't changed since last backup
                    return True, existing['backup_path']
            
            # Create backup subdirectory based on hash prefix
            backup_subdir = BACKUP_DIR / file_hash[:2]
            backup_subdir.mkdir(parents=True, exist_ok=True)
            
            backup_filename = f"{file_hash}_{timestamp}{filepath.suffix}"
            backup_path = backup_subdir / backup_filename
            
            # Enforce size limit — rotate old backups if needed
            self._enforce_size_limit(file_size)
            
            # Copy file preserving metadata
            shutil.copy2(str(filepath), str(backup_path))
            
            # Update index
            self._backup_index[filepath_key] = {
                'original_path': str(filepath),
                'backup_path': str(backup_path),
                'hash': file_hash,
                'size': file_size,
                'timestamp': datetime.now().isoformat(),
                'original_name': filepath.name,
            }
            
            self._total_size += file_size
            self._save_index()
            
            logger.debug(f"Backed up: {filepath.name} → {backup_path.name}")
            return True, str(backup_path)
            
        except PermissionError:
            logger.debug(f"Permission denied backing up {filepath}")
            return False, None
        except Exception as e:
            logger.error(f"Backup failed for {filepath}: {e}")
            return False, None
    
    def restore_file(self, filepath):
        """
        Restore a file from the local backup cache.
        
        Returns: (success: bool, message: str)
        """
        try:
            filepath_key = str(Path(filepath)).lower()
            
            if filepath_key not in self._backup_index:
                return False, f"No backup found for {filepath}"
            
            backup_info = self._backup_index[filepath_key]
            backup_path = Path(backup_info['backup_path'])
            
            if not backup_path.exists():
                # Backup file was deleted — try VSS
                del self._backup_index[filepath_key]
                self._save_index()
                return False, f"Backup file missing, try VSS restore"
            
            # Restore the file
            original_path = Path(backup_info['original_path'])
            original_path.parent.mkdir(parents=True, exist_ok=True)
            
            shutil.copy2(str(backup_path), str(original_path))
            
            logger.info(f"Restored: {original_path.name} from backup ({backup_info['timestamp']})")
            return True, f"Restored {original_path.name} from backup ({backup_info['timestamp']})"
            
        except Exception as e:
            return False, f"Restore failed: {e}"
    
    def restore_from_vss(self, filepath):
        """
        Attempt to restore a file from Windows Volume Shadow Copy (VSS).
        
        Uses vssadmin to query shadow copies and restore the latest version.
        Requires administrator privileges.
        
        Returns: (success: bool, message: str)
        """
        try:
            filepath = Path(filepath)
            drive = filepath.drive  # e.g., "C:"
            
            # Query available shadow copies
            result = subprocess.run(
                ['vssadmin', 'list', 'shadows', f'/for={drive}\\'],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode != 0:
                return False, f"VSS query failed: {result.stderr.strip()}"
            
            # Parse shadow copy paths
            shadow_copies = self._parse_vss_output(result.stdout)
            
            if not shadow_copies:
                return False, "No shadow copies available for this volume"
            
            # Try each shadow copy (newest first) to find the file
            relative_path = str(filepath)[len(drive):]  # e.g., \Users\...\file.txt
            
            for shadow_path in reversed(shadow_copies):
                shadow_file = shadow_path + relative_path
                
                if os.path.exists(shadow_file):
                    # Found it — restore
                    filepath.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(shadow_file, str(filepath))
                    
                    logger.info(f"VSS Restored: {filepath.name} from {shadow_path}")
                    return True, f"Restored {filepath.name} from Volume Shadow Copy"
            
            return False, "File not found in any shadow copy"
            
        except subprocess.TimeoutExpired:
            return False, "VSS query timed out"
        except FileNotFoundError:
            return False, "vssadmin not found — requires Windows and admin privileges"
        except Exception as e:
            return False, f"VSS restore failed: {e}"
    
    def restore_all_affected(self, pid=None):
        """
        Restore all files that were backed up (optionally filtered by PID).
        Used after a ransomware process is killed.
        
        Returns: (restored_count: int, failed_count: int)
        """
        restored = 0
        failed = 0
        
        for filepath_key, backup_info in list(self._backup_index.items()):
            success, message = self.restore_file(backup_info['original_path'])
            if success:
                restored += 1
            else:
                failed += 1
        
        logger.info(f"Bulk restore complete: {restored} restored, {failed} failed")
        return restored, failed
    
    def list_backups(self, limit=50):
        """
        List all available backups.
        
        Returns: list of dicts with backup info
        """
        backups = []
        for filepath_key, info in list(self._backup_index.items())[-limit:]:
            backup_exists = Path(info['backup_path']).exists()
            backups.append({
                'original_path': info['original_path'],
                'original_name': info['original_name'],
                'backup_path': info['backup_path'],
                'size': info['size'],
                'timestamp': info['timestamp'],
                'available': backup_exists,
            })
        
        return backups
    
    def get_backup_stats(self):
        """Get backup storage statistics."""
        return {
            'total_files': len(self._backup_index),
            'total_size_mb': round(self._total_size / (1024 * 1024), 2),
            'max_size_mb': MAX_BACKUP_SIZE_MB,
            'backup_dir': str(BACKUP_DIR),
            'usage_percent': round((self._total_size / (MAX_BACKUP_SIZE_MB * 1024 * 1024)) * 100, 1),
        }
    
    # ─── Private Methods ──────────────────────────────────────────────────
    
    def _quick_hash(self, filepath, block_size=8192):
        """Quick hash of first 8KB of file for dedup."""
        hasher = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                data = f.read(block_size)
                hasher.update(data)
        except Exception:
            hasher.update(str(filepath).encode())
        return hasher.hexdigest()[:16]
    
    def _enforce_size_limit(self, incoming_size):
        """Remove oldest backups if total size exceeds limit."""
        max_bytes = MAX_BACKUP_SIZE_MB * 1024 * 1024
        
        while self._total_size + incoming_size > max_bytes and self._backup_index:
            # Remove oldest backup (FIFO)
            oldest_key = next(iter(self._backup_index))
            oldest_info = self._backup_index.pop(oldest_key)
            
            try:
                backup_path = Path(oldest_info['backup_path'])
                if backup_path.exists():
                    file_size = backup_path.stat().st_size
                    backup_path.unlink()
                    self._total_size -= file_size
                    logger.debug(f"Rotated out backup: {oldest_info['original_name']}")
            except Exception:
                pass
    
    def _calculate_total_size(self):
        """Calculate total size of all backup files."""
        total = 0
        for info in self._backup_index.values():
            try:
                backup_path = Path(info['backup_path'])
                if backup_path.exists():
                    total += backup_path.stat().st_size
            except Exception:
                pass
        return total
    
    def _load_index(self):
        """Load backup index from disk."""
        try:
            if BACKUP_INDEX.exists():
                with open(BACKUP_INDEX, 'r') as f:
                    data = json.load(f)
                    return OrderedDict(data)
        except Exception as e:
            logger.warning(f"Failed to load backup index: {e}")
        return OrderedDict()
    
    def _save_index(self):
        """Save backup index to disk."""
        try:
            with open(BACKUP_INDEX, 'w') as f:
                json.dump(dict(self._backup_index), f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save backup index: {e}")
    
    def _parse_vss_output(self, output):
        """Parse vssadmin output to extract shadow copy device paths."""
        shadows = []
        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('Shadow Copy Volume:'):
                # Extract the \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy path
                path = line.split(':', 1)[1].strip()
                if path:
                    shadows.append(path)
        return shadows
