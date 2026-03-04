"""
GuardianX ETW Monitor v3.0
Kernel-level file I/O monitoring using a real-time ETW trace session.

Architecture (EDR-grade):
    NT Kernel Logger  →  EVENT_TRACE_FLAG_FILE_IO  →  callback  →  PID cache
    (real-time)          EVENT_TRACE_FLAG_PROCESS      (zero-poll)   (15s TTL)

Tier 1: pywintrace-based real-time kernel trace session
        Uses StartTrace / EnableTraceEx2 / ProcessTrace (callback model)
        Delivers events with PID, TID, and FileName at microsecond latency.

Tier 2: Sysmon fallback (EvtSubscribe on Sysmon/Operational channel)

Tier 3: Enhanced psutil polling (user-mode, last resort)
"""

import sys
import ctypes
import ctypes.wintypes
import threading
import queue
import os
import time
import logging
import subprocess
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional, DefaultDict, Dict, Tuple, Set, Any

if sys.platform == 'win32':
    try:
        import win32evtlog  # type: ignore[import-untyped]
        import win32event   # type: ignore[import-untyped]
        import win32api     # type: ignore[import-untyped]
        import pywintypes    # type: ignore[import-untyped]
        import psutil        # type: ignore[import-untyped]
    except ImportError:
        pass

logger = logging.getLogger("GuardianX.ETW")


# ─── Kernel Trace Flags ───────────────────────────────────────────────────────
# These flags tell the NT Kernel Logger which events to deliver.
EVENT_TRACE_FLAG_PROCESS       = 0x00000001
EVENT_TRACE_FLAG_THREAD        = 0x00000002
EVENT_TRACE_FLAG_IMAGE_LOAD    = 0x00000004
EVENT_TRACE_FLAG_DISK_IO       = 0x00000100
EVENT_TRACE_FLAG_DISK_FILE_IO  = 0x00000200
EVENT_TRACE_FLAG_FILE_IO       = 0x02000000
EVENT_TRACE_FLAG_FILE_IO_INIT  = 0x04000000

# Sysmon event IDs
SYSMON_FILE_CREATE = 11
SYSMON_FILE_DELETE = 23
SYSMON_FILE_DELETE_DETECTED = 26

# File I/O opcode IDs (kernel trace opcodes, NOT the Analytic channel EventIDs)
FILEIO_CREATE     = 64    # FileIo_Create
FILEIO_CLEANUP    = 65    # FileIo_Cleanup
FILEIO_CLOSE      = 66    # FileIo_Close
FILEIO_READ       = 67    # FileIo_Read
FILEIO_WRITE      = 68    # FileIo_Write
FILEIO_SETINFO    = 69    # FileIo_SetInfo
FILEIO_DELETE     = 70    # FileIo_Delete
FILEIO_RENAME     = 71    # FileIo_Rename
FILEIO_QUERYINFO  = 74    # FileIo_QueryInfo
FILEIO_NAME       = 0     # FileIo_Name (name event, provides filename mapping)
FILEIO_FILECREATE = 32    # FileIo_FileCreate
FILEIO_FILEDELETE = 35    # FileIo_FileDelete
FILEIO_FILERUNDOWN = 36   # FileIo_FileRundown


class FileIOEvent:
    """Represents a file I/O event captured via ETW or Sysmon."""
    
    __slots__ = ['pid', 'filepath', 'event_type', 'timestamp', 'process_name', 'image_path']
    
    def __init__(self, pid, filepath, event_type, timestamp=None, process_name=None, image_path=None):
        self.pid = pid
        self.filepath = filepath
        self.event_type = event_type
        self.timestamp = timestamp or datetime.now()
        self.process_name = process_name
        self.image_path = image_path
    
    def __repr__(self):
        return f"FileIOEvent(pid={self.pid}, type={self.event_type}, file={self.filepath})"


class ETWFileMonitor:
    """
    Monitors file I/O operations at the kernel level using a real-time
    ETW trace session (not the Event Log API).
    
    Provides real-time PID attribution for file modifications — catches
    operations that psutil polling misses (memory-mapped files, fast
    open/close handles, kernel drivers).
    
    Architecture:
        Uses pywintrace to run a true NT Kernel Logger session with
        EVENT_TRACE_FLAG_FILE_IO. Events are delivered via callback on
        a dedicated ProcessTrace thread — zero polling, microsecond latency.
    """
    
    def __init__(self, max_queue_size: int = 10000) -> None:
        self.event_queue: queue.Queue[FileIOEvent] = queue.Queue(maxsize=max_queue_size)
        self._running: bool = False
        self._thread: Optional[threading.Thread] = None
        self._kernel_trace_active: bool = False
        self._sysmon_active: bool = False
        
        # pywintrace ETW session object (Tier 1)
        self._etw_job = None
        
        # Synchronization events for thread startup
        self._startup_event = threading.Event()
        self._startup_error: Optional[str] = None
        
        # Recent file→PID mapping cache (filepath → (pid, timestamp))
        self._file_pid_cache: Dict[str, Tuple[int, float]] = {}
        self._cache_lock = threading.Lock()
        self._cache_ttl: float = 15.0  # seconds (increased from 5s for burst handling)
        
        # Process info cache: PID → {name, exe, start_time}
        # Survives process exit so we can still attribute after short-lived ransomware exits
        self._process_cache: Dict[int, Dict[str, Any]] = {}
        self._process_cache_lock = threading.Lock()
        
        # FileObject pointer → filepath mapping (kernel events use FileObject pointers,
        # only Create/Name events contain the actual filename)
        self._fileobj_cache: Dict[str, str] = {}  # hex FileObject → filepath
        self._fileobj_lock = threading.Lock()
        
        # Track file access patterns per PID
        self.pid_file_map: DefaultDict[int, Set[str]] = defaultdict(set)  # type: ignore[assignment]
        self._map_lock = threading.Lock()
        
        # Volume device path → drive letter mapping for ETW path normalization
        self._volume_map: Dict[str, str] = self._build_volume_map()
        
        # Stats
        self._events_received = 0
        self._cache_hits = 0
        self._cache_misses = 0
        
        logger.info("ETW File Monitor v3.0 initialized (kernel trace mode)")

    def _build_volume_map(self) -> Dict[str, str]:
        """
        Build a mapping of \\Device\\HarddiskVolumeN → C: (etc.)
        
        ETW kernel events use NT device paths like:
            \\Device\\HarddiskVolume3\\Users\\...
        But watchdog uses Win32 paths like:
            C:\\Users\\...
        
        Without this mapping, the ETW cache never matches watchdog paths.
        """
        volume_map = {}
        try:
            import ctypes
            buf = ctypes.create_unicode_buffer(261)
            # Check all possible drive letters
            for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                drive = f"{letter}:"
                ret = ctypes.windll.kernel32.QueryDosDeviceW(drive, buf, 261)
                if ret > 0:
                    device_path = buf.value  # e.g. \Device\HarddiskVolume3
                    volume_map[device_path.lower()] = drive
                    logger.debug(f"Volume map: {device_path} → {drive}")
        except Exception as e:
            logger.warning(f"Failed to build volume map: {e}")
        
        if volume_map:
            logger.info(f"Volume map: {len(volume_map)} drive(s) mapped")
        else:
            logger.warning("Volume map empty — ETW path normalization disabled")
        
        return volume_map

    def _normalize_etw_path(self, filepath: str) -> str:
        """
        Convert ETW kernel device paths to standard Win32 paths.
        
        \\Device\\HarddiskVolume3\\Users\\Adarsh\\Desktop\\file.txt
        → C:\\Users\\Adarsh\\Desktop\\file.txt
        """
        if not filepath:
            return filepath
        
        # Already a Win32 path
        if len(filepath) >= 2 and filepath[1] == ':':
            return filepath
        
        # Try to match against volume map
        fp_lower = filepath.lower()
        for device_path, drive_letter in self._volume_map.items():
            if fp_lower.startswith(device_path):
                return drive_letter + filepath[len(device_path):]
        
        return filepath
    
    def start(self):
        """Start the ETW monitoring session."""
        if self._running:
            return
        
        self._running = True
        
        # Try Tier 1 (kernel trace), Tier 2 (Sysmon), Tier 3 (psutil polling)
        if self._try_start_kernel_trace():
            self._kernel_trace_active = True
            logger.info("✓ Real-time kernel file trace session started (pywintrace)")
        elif self._try_start_sysmon():
            self._sysmon_active = True
            logger.info("✓ Sysmon log monitoring started as fallback")
        else:
            # Final fallback: enhanced psutil polling in a background thread
            self._thread = threading.Thread(
                target=self._enhanced_polling_loop,
                daemon=True,
                name="GuardianX-FileMonitor"
            )
            self._thread.start()
            logger.warning("Kernel trace and Sysmon unavailable — using enhanced polling fallback")
    
    def stop(self):
        """Stop the monitoring session."""
        self._running = False
        
        # Stop pywintrace kernel trace
        if self._etw_job is not None:
            try:
                # pywintrace's stop() calls CloseTrace then process_thread.join()
                # which can block if ProcessTrace hasn't returned yet.
                # Use a separate thread with timeout to avoid hanging on Ctrl+C.
                stop_thread = threading.Thread(target=self._safe_stop_etw, daemon=True)
                stop_thread.start()
                stop_thread.join(timeout=3.0)
                if stop_thread.is_alive():
                    logger.debug("Kernel trace stop timed out (ProcessTrace still blocking)")
            except Exception as e:
                logger.debug(f"Error stopping kernel trace: {e}")
            self._etw_job = None
        
        _t = self._thread
        if _t is not None and _t.is_alive():
            _t.join(timeout=5)
        
        # Log stats
        total = self._cache_hits + self._cache_misses
        hit_rate = (self._cache_hits / total * 100) if total > 0 else 0
        fobj_size = len(self._fileobj_cache)
        logger.info(
            f"ETW Monitor stopped — {self._events_received} events received, "
            f"cache hit rate: {hit_rate:.1f}% ({self._cache_hits}/{total}), "
            f"FileObject cache: {fobj_size} entries"
        )
    
    def _safe_stop_etw(self):
        """Stop ETW session in a separate thread (ProcessTrace can block)."""
        try:
            if self._etw_job is not None:
                self._etw_job.stop()
                logger.info("Kernel trace session stopped")
        except Exception as e:
            logger.debug(f"ETW stop error: {e}")
    
    def get_process_for_file(self, filepath):
        """
        Get the PID that most recently modified a file.
        
        Uses the ETW event cache for real-time attribution.
        Returns None immediately on cache miss (no blocking scan).
        
        Returns: pid (int) or None
        """
        filepath_normalized = os.path.normpath(filepath).lower()
        
        # Check ETW event cache
        with self._cache_lock:
            if filepath_normalized in self._file_pid_cache:
                pid, timestamp = self._file_pid_cache[filepath_normalized]
                if time.time() - timestamp < self._cache_ttl:
                    self._cache_hits += 1
                    logger.info(f"ETW cache HIT: {os.path.basename(filepath)} → PID {pid}")
                    return pid
                else:
                    self._file_pid_cache.pop(filepath_normalized, None)
            
            cache_size = len(self._file_pid_cache)
        
        self._cache_misses += 1
        
        # Debug: log misses for Desktop/test events
        if 'guardianx_test' in filepath_normalized or 'desktop' in filepath_normalized:
            logger.info(
                f"[ETW-DEBUG] MISS lookup_key={filepath_normalized[-60:]} "
                f"cache_size={cache_size}"
            )
            # Try to find near-matches
            basename = os.path.basename(filepath_normalized)
            with self._cache_lock:
                near = [k for k in self._file_pid_cache if basename in k]
            if near:
                logger.info(f"[ETW-DEBUG] Near-matches found: {near[:3]}")
        
        # No blocking fallback — return None immediately
        if cache_size == 0:
            logger.debug(f"ETW cache EMPTY — no entries at all")
        else:
            logger.debug(f"ETW cache MISS for {os.path.basename(filepath)} (cache has {cache_size} entries)")
        
        return None
    
    def get_events(self, max_events=100):
        """Drain events from the queue (non-blocking)."""
        events = []
        try:
            while len(events) < max_events:
                events.append(self.event_queue.get_nowait())
        except queue.Empty:
            pass
        return events
    
    def get_recent_files_for_pid(self, pid):
        """Get the set of files recently accessed by a PID."""
        with self._map_lock:
            return set(self.pid_file_map.get(pid, set()))
    
    def get_cached_process_info(self, pid):
        """
        Get cached process info for a PID. Works even after the process exits.
        
        Returns: dict with 'name', 'exe' keys or None
        """
        with self._process_cache_lock:
            return self._process_cache.get(pid)
    
    # ─── Tier 1: Real-Time Kernel Trace (pywintrace) ──────────────────────
    
    def _try_start_kernel_trace(self):
        """
        Start a real-time NT Kernel Logger session with FILE_IO + PROCESS flags.
        
        Uses pywintrace to call StartTrace/EnableTraceEx2/ProcessTrace.
        Events are delivered via callback — zero polling.
        
        Requires administrator privileges.
        """
        try:
            # Check admin privileges
            if not ctypes.windll.shell32.IsUserAnAdmin():
                logger.warning("Kernel trace requires administrator privileges — skipping")
                return False
            
            import etw  # pywintrace
            
            # Suppress pywintrace's TDH parser warnings for kernel events.
            # Kernel FileIO events have variable-length FileName fields that
            # TDH often fails to parse — this is expected and handled by our
            # FileObject→FileName cache below.
            logging.getLogger('etw.etw').setLevel(logging.ERROR)
            
            # The NT Kernel Logger uses EnableFlags (not EnableTraceEx2 providers).
            # We set file I/O + process + image load flags for full attribution:
            #   FILE_IO + FILE_IO_INIT → captures file create/read/write/delete/rename with PID
            #   PROCESS → captures process start/exit (for process info cache)
            #   IMAGE_LOAD → captures DLL loads (for detecting injection)
            kernel_flags = (
                EVENT_TRACE_FLAG_FILE_IO |
                EVENT_TRACE_FLAG_FILE_IO_INIT |
                EVENT_TRACE_FLAG_PROCESS |
                EVENT_TRACE_FLAG_IMAGE_LOAD |
                EVENT_TRACE_FLAG_DISK_FILE_IO
            )
            
            providers = [
                etw.ProviderInfo(
                    'NT Kernel Logger',
                    etw.GUID("{9E814AAD-3204-11D2-9A82-006008A86939}"),  # SystemTraceControlGuid
                    any_keywords=kernel_flags,
                )
            ]
            
            # pywintrace v0.2.0 callback_data_flag:
            #   2 = RETURN_RAW_DATA_ON_ERROR — still deliver events when TDH fails
            # No task_name_filters — kernel events use numeric tags, not "FILEIO".
            # We filter by opcode in the callback instead.
            self._etw_job = etw.ETW(
                session_name='NT Kernel Logger',
                providers=providers,
                event_callback=self._kernel_event_callback,
                callback_data_flag=2,  # RETURN_RAW_DATA_ON_ERROR
                ring_buf_size=256,     # 256 KB per buffer
            )
            
            self._etw_job.start()
            
            logger.info(
                f"Kernel trace started — flags: FILE_IO|FILE_IO_INIT|PROCESS|"
                f"IMAGE_LOAD|DISK_FILE_IO (0x{kernel_flags:08X})"
            )
            return True
            
        except ImportError:
            logger.warning(
                "pywintrace not installed — install with: pip install pywintrace"
            )
            return False
        except OSError as e:
            # ERROR_ALREADY_EXISTS (183) — another kernel logger is running
            if getattr(e, 'winerror', 0) == 183:
                logger.warning(
                    "Another NT Kernel Logger session is already active "
                    "(ProcMon, xperf, or another EDR). Falling back to Sysmon."
                )
            else:
                logger.warning(f"Failed to start kernel trace: {e}")
            return False
        except Exception as e:
            logger.warning(f"Kernel trace startup error: {e}")
            return False
    
    def _kernel_event_callback(self, event_tufo):
        """
        Callback from pywintrace ProcessTrace thread.
        
        pywintrace v0.2.0 uses 'tufo' format: (tag, event_data_dict).
        For kernel events, tag is typically "0" (numeric ProviderId).
        
        This runs on the pywintrace consumer thread — keep it fast.
        """
        try:
            # pywintrace v0.2.0: callback receives (tag, data_dict) tuples
            if isinstance(event_tufo, tuple) and len(event_tufo) == 2:
                _, event_data = event_tufo
            elif isinstance(event_tufo, dict):
                event_data = event_tufo  # Future versions may use dicts
            else:
                return
            
            if not isinstance(event_data, dict):
                return
            
            self._events_received += 1
            
            # Extract header fields
            header = event_data.get('EventHeader', {})
            if not isinstance(header, dict):
                return
            
            pid = header.get('ProcessId', 0)
            descriptor = header.get('EventDescriptor', {})
            opcode = descriptor.get('Opcode', -1)
            
            # Filter by opcode — much faster than task_name matching
            # FileIO opcodes: 0, 32, 35, 36, 64-76
            # Process opcodes: 1-4
            if opcode in (1, 2, 3, 4):
                # Process start/exit events
                if pid:
                    self._handle_process_event(event_data, pid)
            elif opcode >= 0:
                # FileIO events — all other opcodes
                self._handle_fileio_event(event_data, pid, opcode)
                
        except Exception as e:
            logger.debug(f"Kernel event callback error: {e}")
    
    def _handle_process_event(self, event_data, pid):
        """Cache process start info so we can attribute even after exit."""
        try:
            image_name = event_data.get('ImageFileName', '')
            command_line = event_data.get('CommandLine', '')
            
            if image_name:
                with self._process_cache_lock:
                    self._process_cache[pid] = {
                        'name': os.path.basename(image_name),
                        'exe': image_name,
                        'cmdline': command_line or '',
                        'start_time': time.time(),
                    }
                
                if len(self._process_cache) <= 5 or len(self._process_cache) % 100 == 0:
                    logger.debug(
                        f"Process cache: PID {pid} → {os.path.basename(image_name)} "
                        f"(cache size: {len(self._process_cache)})"
                    )
                    
        except Exception as e:
            logger.debug(f"Process event handling error: {e}")
    
    def _handle_fileio_event(self, event_data, pid, opcode):
        """
        Process a FileIO event — update file→PID and FileObject→FileName caches.
        
        Kernel FileIO architecture:
          - Create events (opcode 64) contain 'OpenPath' with the full file path
          - Name events (opcode 0, 32, 36) contain 'FileName' → maps FileObject to path
          - Write/Delete/Rename events only contain 'FileObject' pointer, no filename
          
        We build a FileObject→FileName cache from Create/Name events, then use it
        to resolve filenames for write/delete/rename events.
        """
        try:
            # ─── Step 1: Extract file path (varies by event type) ───
            filepath = None
            file_object = event_data.get('FileObject', '')
            file_object_key = str(file_object) if file_object else ''
            
            # Create events (opcode 64) — have 'OpenPath' with full NT device path
            if opcode == FILEIO_CREATE:
                filepath = event_data.get('OpenPath', '')
                # Cache FileObject → FileName for future lookups
                if filepath and file_object_key:
                    normalized = self._normalize_etw_path(filepath)
                    with self._fileobj_lock:
                        self._fileobj_cache[file_object_key] = normalized
            
            # Name events (opcode 0, 32, 36) — have 'FileName'
            elif opcode in (FILEIO_NAME, FILEIO_FILECREATE, FILEIO_FILERUNDOWN):
                filepath = event_data.get('FileName', '')
                # Cache FileObject → FileName
                if filepath and file_object_key:
                    normalized = self._normalize_etw_path(filepath)
                    with self._fileobj_lock:
                        self._fileobj_cache[file_object_key] = normalized
            
            # All other events — try parsed 'FileName', then FileObject cache
            else:
                filepath = event_data.get('FileName') or event_data.get('OpenPath')
                if not filepath and file_object_key:
                    # Look up FileObject in our cache
                    with self._fileobj_lock:
                        filepath = self._fileobj_cache.get(file_object_key)
            
            if not filepath or not isinstance(filepath, str):
                return
            
            # ─── Step 2: Normalize and determine event type ───
            filepath = self._normalize_etw_path(filepath)
            
            # Map opcodes to event types we care about for PID attribution
            opcode_map = {
                FILEIO_CREATE: 'created',
                FILEIO_FILECREATE: 'created',
                FILEIO_WRITE: 'modified',
                FILEIO_SETINFO: 'modified',
                FILEIO_DELETE: 'deleted',
                FILEIO_FILEDELETE: 'deleted',
                FILEIO_RENAME: 'renamed',
                FILEIO_CLEANUP: 'cleanup',
                FILEIO_CLOSE: 'closed',
            }
            
            event_type = opcode_map.get(opcode)
            if not event_type:
                return  # Not a file event we track
            
            # Skip PID 0 and PID 4 (System) for file attribution
            if pid in (0, 4):
                return
            
            # Only cache write-related events (these are what watchdog will see)
            if event_type in ('created', 'modified', 'deleted', 'renamed'):
                # Debug: log Desktop/test events for PID attribution diagnostics
                if 'guardianx_test' in filepath.lower() or 'desktop' in filepath.lower():
                    logger.info(
                        f"[ETW-DEBUG] {event_type.upper()} opcode={opcode} PID={pid} "
                        f"file={os.path.basename(filepath)} "
                        f"key={os.path.normpath(filepath).lower()[-60:]}"
                    )
                self._update_cache(filepath, pid)
                
                # Create FileIOEvent and add to queue
                file_event = FileIOEvent(
                    pid=pid,
                    filepath=filepath,
                    event_type=event_type,
                )
                
                try:
                    self.event_queue.put_nowait(file_event)
                except queue.Full:
                    pass  # Drop if queue is full
                
        except Exception as e:
            logger.debug(f"FileIO event handling error: {e}")
    
    # ─── Tier 2: Sysmon Fallback ──────────────────────────────────────────
    
    def _try_start_sysmon(self):
        """
        Fall back to Sysmon event log parsing.
        
        Sysmon provides process-level file create/delete events through
        the Windows Event Log, which doesn't require ETW session management.
        """
        try:
            import win32evtlog
            
            # Check if Sysmon log exists using the modern Event Log API
            channel = 'Microsoft-Windows-Sysmon/Operational'
            try:
                test_query = win32evtlog.EvtQuery(
                    channel,
                    win32evtlog.EvtQueryForwardDirection,
                    '*[System[EventID=1]]',
                )
                # If we get here, Sysmon channel is accessible
                logger.info(f"Sysmon channel '{channel}' is accessible")
            except pywintypes.error as e:
                logger.info(f"Sysmon not installed or not accessible: {e}")
                return False
            except Exception as e:
                logger.info(f"Sysmon channel check failed: {e}")
                return False
            
            # Reset startup synchronization
            self._startup_event.clear()
            self._startup_error = None
            
            self._thread = threading.Thread(
                target=self._sysmon_consumer_loop,
                daemon=True,
                name="GuardianX-Sysmon"
            )
            self._thread.start()
            
            # Wait for the thread to signal success or failure (up to 3 seconds)
            if not self._startup_event.wait(timeout=3.0):
                logger.error("Sysmon consumer thread did not start within 3 seconds")
                return False
            
            if self._startup_error:
                logger.error(f"Sysmon consumer startup failed: {self._startup_error}")
                return False
            
            return self._sysmon_active
            
        except ImportError:
            logger.warning("win32evtlog not available — Sysmon monitoring not possible")
            return False
        except Exception as e:
            logger.error(f"Failed to start Sysmon monitoring: {e}")
            return False
    
    def _sysmon_consumer_loop(self):
        """Poll Sysmon event log for file creation/deletion events."""
        handle = None
        signal_event = None
        try:
            import win32evtlog
            import win32event
            
            WAIT_OBJECT_0 = 0x00000000
            
            # Create a Win32 auto-reset event using pywin32.
            # This returns a PyHANDLE which EvtSubscribe requires.
            signal_event = win32event.CreateEvent(None, False, False, None)
            if not signal_event:
                self._startup_error = "CreateEvent failed"
                self._startup_event.set()
                return
            
            channel = 'Microsoft-Windows-Sysmon/Operational'
            query = (
                '<QueryList>'
                '  <Query Id="0" Path="Microsoft-Windows-Sysmon/Operational">'
                '    <Select Path="Microsoft-Windows-Sysmon/Operational">'
                '      *[System[(EventID=11 or EventID=23 or EventID=26)]]'
                '    </Select>'
                '  </Query>'
                '</QueryList>'
            )
            
            try:
                # pywin32 EvtSubscribe parameter order (different from C API!):
                # (ChannelPath, Flags, SignalEvent, Callback, Context, Query, Session, Bookmark)
                handle = win32evtlog.EvtSubscribe(
                    channel,                                        # ChannelPath
                    win32evtlog.EvtSubscribeToFutureEvents,         # Flags
                    SignalEvent=int(signal_event),                   # SignalEvent (int handle)
                    Query=query,                                    # Query (structured XML)
                )
            except Exception as e:
                self._startup_error = f"EvtSubscribe failed on '{channel}': {e}"
                self._startup_event.set()
                return
            
            self._sysmon_active = True
            self._startup_event.set()  # Signal success to the main thread
            logger.info("Sysmon subscription active")
            
            while self._running:
                wait_result = win32event.WaitForSingleObject(signal_event, 2000)
                
                if wait_result == WAIT_OBJECT_0:
                    while True:
                        try:
                            events = win32evtlog.EvtNext(handle, 50, 100)
                        except pywintypes.error:
                            break
                        except Exception:
                            break
                        if not events:
                            break
                        for event in events:
                            self._process_sysmon_event(event)
            
        except Exception as e:
            self._startup_error = str(e)
            logger.error(f"Sysmon consumer error: {e}")
            self._sysmon_active = False
        finally:
            # Signal the startup event in case we failed before signaling
            self._startup_event.set()
            # Clean up handles
            if signal_event is not None:
                try:
                    win32api.CloseHandle(signal_event)
                except Exception:
                    pass
            if handle is not None:
                try:
                    handle.Close()
                except Exception:
                    pass
    
    def _process_sysmon_event(self, event):
        """Parse a Sysmon event for file operations."""
        try:
            import win32evtlog
            import xml.etree.ElementTree as ET
            
            xml_str = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
            root = ET.fromstring(xml_str)
            
            ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
            
            event_data = root.find('.//e:EventData', ns)
            if event_data is None:
                return
            
            data_dict = {}
            for data in event_data.findall('e:Data', ns):
                name = data.get('Name')
                if name:
                    data_dict[name] = data.text
            
            pid_str = data_dict.get('ProcessId')
            pid = int(pid_str) if pid_str else 0
            filepath = data_dict.get('TargetFilename', '')
            process_name = data_dict.get('Image', '')
            
            event_id_elem = root.find('.//e:EventID', ns)
            event_id = int(event_id_elem.text or '0') if event_id_elem is not None else 0
            
            event_type_map = {
                SYSMON_FILE_CREATE: 'created',
                SYSMON_FILE_DELETE: 'deleted',
                SYSMON_FILE_DELETE_DETECTED: 'deleted',
            }
            
            if filepath and pid:
                file_event = FileIOEvent(
                    pid=pid,
                    filepath=filepath,
                    event_type=event_type_map.get(event_id, 'unknown'),
                    process_name=os.path.basename(process_name) if process_name else None,
                    image_path=process_name,
                )
                
                self._update_cache(filepath, pid)
                
                # Also cache process info from Sysmon
                if process_name and pid:
                    with self._process_cache_lock:
                        if pid not in self._process_cache:
                            self._process_cache[pid] = {
                                'name': os.path.basename(process_name),
                                'exe': process_name,
                                'cmdline': '',
                                'start_time': time.time(),
                            }
                
                try:
                    self.event_queue.put_nowait(file_event)
                except queue.Full:
                    pass
                    
        except Exception as e:
            logger.debug(f"Error parsing Sysmon event: {e}")
    
    # ─── Tier 3: Enhanced Polling Fallback ────────────────────────────────
    
    def _enhanced_polling_loop(self):
        """
        Enhanced psutil polling as final fallback.
        
        Improvements over basic polling:
        - Caches process→file mappings with timestamps
        - Polls more frequently (200ms vs on-demand)
        - Tracks file access history per PID
        """
        logger.info("Enhanced polling loop started")
        
        while self._running:
            try:
                for proc in psutil.process_iter(['pid', 'name']):
                    if not self._running:
                        return
                    try:
                        pid = proc.info['pid']
                        open_files = proc.open_files()
                        
                        for item in open_files:
                            self._update_cache(item.path, pid)
                            
                            with self._map_lock:
                                self.pid_file_map[pid].add(item.path.lower())
                            
                        # Also cache process info
                        with self._process_cache_lock:
                            if pid not in self._process_cache:
                                self._process_cache[pid] = {
                                    'name': proc.info.get('name', ''),
                                    'exe': '',
                                    'cmdline': '',
                                    'start_time': time.time(),
                                }
                                
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        continue
                    except Exception:
                        continue
                
                time.sleep(0.2)  # 200ms polling interval
                
            except Exception as e:
                logger.error(f"Polling error: {e}")
                time.sleep(1)
    
    # ─── Cache Management ─────────────────────────────────────────────────
    
    def _update_cache(self, filepath, pid):
        """Update the file→PID cache."""
        normalized = os.path.normpath(filepath).lower()
        with self._cache_lock:
            self._file_pid_cache[normalized] = (pid, time.time())
            cache_size = len(self._file_pid_cache)
            
        with self._map_lock:
            self.pid_file_map[pid].add(normalized)
        
        # Log first few cache entries for diagnostics
        if cache_size <= 5 or cache_size % 500 == 0:
            logger.info(f"ETW cache UPDATE: {os.path.basename(filepath)} → PID {pid} (cache size: {cache_size})")
    
    def cleanup_cache(self, max_age=30.0):
        """Remove stale entries from the file→PID cache."""
        now = time.time()
        with self._cache_lock:
            stale_keys = [
                k for k, (_, ts) in self._file_pid_cache.items()
                if now - ts > max_age
            ]
            for k in stale_keys:
                self._file_pid_cache.pop(k, None)
        
        # Also clean up old process cache entries (>5 minutes old)
        with self._process_cache_lock:
            stale_pids = [
                pid for pid, info in self._process_cache.items()
                if now - info.get('start_time', 0) > 300
            ]
            for pid in stale_pids:
                self._process_cache.pop(pid, None)
    
    @property
    def is_etw_active(self):
        return self._kernel_trace_active
    
    @property
    def is_sysmon_active(self):
        return self._sysmon_active
    
    @property
    def monitoring_mode(self):
        if self._kernel_trace_active:
            return "ETW Kernel Trace (Real-Time)"
        elif self._sysmon_active:
            return "Sysmon (Event Log)"
        else:
            return "Enhanced Polling (User-Mode)"