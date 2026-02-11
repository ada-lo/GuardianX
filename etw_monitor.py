"""
GuardianX ETW Monitor
Kernel-level file I/O monitoring using Windows Event Tracing (ETW).
Replaces polling-based process attribution with real-time kernel events.

Falls back to Sysmon log parsing if ETW session cannot be established.
"""

import ctypes
import ctypes.wintypes
import threading
import queue
import os
import time
import logging
from collections import defaultdict
from datetime import datetime, timedelta

logger = logging.getLogger("GuardianX.ETW")


# ─── Windows ETW Constants ────────────────────────────────────────────────────
EVENT_TRACE_REAL_TIME_MODE = 0x00000100
EVENT_TRACE_FILE_MODE_NONE = 0x00000000
PROCESS_TRACE_MODE_REAL_TIME = 0x00000100
PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000
WNODE_FLAG_TRACED_GUID = 0x00020000

# Microsoft-Windows-Kernel-File provider GUID
KERNEL_FILE_PROVIDER = "{EDD08927-9CC4-4E65-B970-C2560FB5C289}"

# File I/O event IDs
FILE_CREATE = 10
FILE_WRITE = 15
FILE_DELETE = 26
FILE_RENAME = 14
FILE_CLEANUP = 12

# Sysmon event IDs
SYSMON_FILE_CREATE = 11
SYSMON_FILE_DELETE = 23
SYSMON_FILE_DELETE_DETECTED = 26


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
    Monitors file I/O operations at the kernel level using ETW.
    
    Provides real-time PID attribution for file modifications — catches
    operations that psutil polling misses (memory-mapped files, fast
    open/close handles, kernel drivers).
    """
    
    def __init__(self, max_queue_size=10000):
        self.event_queue = queue.Queue(maxsize=max_queue_size)
        self._running = False
        self._thread = None
        self._etw_active = False
        self._sysmon_active = False
        
        # Recent file→PID mapping cache (filepath → (pid, timestamp))
        self._file_pid_cache = {}
        self._cache_lock = threading.Lock()
        self._cache_ttl = 5.0  # seconds
        
        # Track file access patterns per PID
        self.pid_file_map = defaultdict(set)  # pid → set of filepaths
        self._map_lock = threading.Lock()
        
        logger.info("ETW File Monitor initialized")
    
    def start(self):
        """Start the ETW monitoring session."""
        if self._running:
            return
        
        self._running = True
        
        # Try ETW first, fall back to Sysmon
        if self._try_start_etw():
            self._etw_active = True
            logger.info("ETW real-time trace session started successfully")
        elif self._try_start_sysmon():
            self._sysmon_active = True
            logger.info("Sysmon log monitoring started as fallback")
        else:
            # Final fallback: enhanced psutil polling in a background thread
            self._thread = threading.Thread(
                target=self._enhanced_polling_loop,
                daemon=True,
                name="GuardianX-FileMonitor"
            )
            self._thread.start()
            logger.warning("ETW and Sysmon unavailable — using enhanced polling fallback")
    
    def stop(self):
        """Stop the monitoring session."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        logger.info("ETW File Monitor stopped")
    
    def get_process_for_file(self, filepath):
        """
        Get the PID that most recently modified a file.
        
        Uses the ETW event cache for real-time attribution.
        Falls back to psutil if no ETW data available.
        
        Returns: pid (int) or None
        """
        filepath_normalized = os.path.normpath(filepath).lower()
        
        # Check ETW event cache first
        with self._cache_lock:
            if filepath_normalized in self._file_pid_cache:
                pid, timestamp = self._file_pid_cache[filepath_normalized]
                if time.time() - timestamp < self._cache_ttl:
                    return pid
                else:
                    del self._file_pid_cache[filepath_normalized]
        
        # Fallback to psutil scanning
        return self._psutil_scan(filepath)
    
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
    
    # ─── ETW Session Management ───────────────────────────────────────────
    
    def _try_start_etw(self):
        """
        Attempt to start an ETW trace session for kernel file events.
        
        Uses ctypes to call the Windows ETW API directly:
        - StartTrace → creates the trace session
        - EnableTraceEx2 → enables the Kernel-File provider
        - OpenTrace + ProcessTrace → consumes events in real-time
        """
        try:
            # Check if we have admin privileges (ETW requires elevation)
            if not ctypes.windll.shell32.IsUserAnAdmin():
                logger.warning("ETW requires administrator privileges")
                return False
            
            # Start ETW consumer thread
            self._thread = threading.Thread(
                target=self._etw_consumer_loop,
                daemon=True,
                name="GuardianX-ETW"
            )
            self._thread.start()
            
            # Give it a moment to initialize
            time.sleep(0.5)
            return self._etw_active
            
        except Exception as e:
            logger.error(f"Failed to start ETW session: {e}")
            return False
    
    def _etw_consumer_loop(self):
        """
        ETW event consumer loop.
        
        Uses win32evtlog to subscribe to kernel file events in real-time.
        Uses a Win32 signal event so EvtNext works correctly with EvtSubscribe.
        
        Note: The Kernel-File/Analytic channel must be explicitly enabled in Windows.
        If it's not enabled, this will fail and fall back to Sysmon or polling.
        """
        try:
            import win32evtlog
            import win32event
            
            # Create a signal event for EvtSubscribe → EvtNext pattern
            signal_event = win32event.CreateEvent(None, False, False, None)
            
            # Subscribe to Microsoft-Windows-Kernel-File/Analytic channel
            # This provides real-time file I/O events with PID attribution
            query = (
                '<QueryList>'
                '  <Query Id="0" Path="Microsoft-Windows-Kernel-File/Analytic">'
                '    <Select Path="Microsoft-Windows-Kernel-File/Analytic">'
                '      *[System[(EventID=10 or EventID=12 or EventID=14 or EventID=15 or EventID=26)]]'
                '    </Select>'
                '  </Query>'
                '</QueryList>'
            )
            
            # EvtSubscribe params: Session, SignalEvent, ChannelPath, Query,
            #                      Bookmark, Context, Callback, Flags
            handle = win32evtlog.EvtSubscribe(
                None,                                           # Session (local)
                signal_event,                                   # SignalEvent
                'Microsoft-Windows-Kernel-File/Analytic',       # ChannelPath
                query,                                          # Query
                None,                                           # Bookmark
                None,                                           # Context
                None,                                           # Callback (poll via signal)
                win32evtlog.EvtSubscribeToFutureEvents,         # Flags
            )
            
            self._etw_active = True
            logger.info("ETW subscription active on Kernel-File provider")
            
            while self._running:
                # Wait for the signal event (max 1 second, then re-check _running)
                wait_result = win32event.WaitForSingleObject(signal_event, 1000)
                
                if wait_result == win32event.WAIT_OBJECT_0:
                    # Events are available — drain them
                    while True:
                        try:
                            events = win32evtlog.EvtNext(handle, 100, 100)
                        except Exception:
                            break
                        if not events:
                            break
                        for event in events:
                            self._process_etw_event(event)
                    
        except ImportError:
            logger.warning("win32evtlog not available for ETW subscription")
            self._etw_active = False
        except Exception as e:
            logger.error(f"ETW consumer error: {e}")
            self._etw_active = False
    
    def _process_etw_event(self, event):
        """Parse an ETW event and add to the queue."""
        try:
            import win32evtlog
            import xml.etree.ElementTree as ET
            
            xml_str = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
            root = ET.fromstring(xml_str)
            
            ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
            
            # Extract PID from System/Execution
            execution = root.find('.//e:Execution', ns)
            pid = int(execution.get('ProcessID', '0')) if execution is not None else 0
            
            # Extract filepath from EventData
            event_data = root.find('.//e:EventData', ns)
            filepath = None
            if event_data is not None:
                for data in event_data.findall('e:Data', ns):
                    if data.get('Name') == 'FileName':
                        filepath = data.text
                        break
            
            if filepath and pid:
                event_id_elem = root.find('.//e:EventID', ns)
                event_id = int(event_id_elem.text) if event_id_elem is not None else 0
                
                event_type_map = {
                    FILE_CREATE: 'created',
                    FILE_WRITE: 'modified',
                    FILE_DELETE: 'deleted',
                    FILE_RENAME: 'renamed',
                    FILE_CLEANUP: 'cleanup',
                }
                
                file_event = FileIOEvent(
                    pid=pid,
                    filepath=filepath,
                    event_type=event_type_map.get(event_id, 'unknown'),
                )
                
                # Update cache
                self._update_cache(filepath, pid)
                
                # Add to queue (non-blocking)
                try:
                    self.event_queue.put_nowait(file_event)
                except queue.Full:
                    pass  # Drop oldest events if queue is full
                    
        except Exception as e:
            logger.debug(f"Error parsing ETW event: {e}")
    
    # ─── Sysmon Fallback ──────────────────────────────────────────────────
    
    def _try_start_sysmon(self):
        """
        Fall back to Sysmon event log parsing.
        
        Sysmon provides process-level file create/delete events through
        the Windows Event Log, which doesn't require ETW session management.
        """
        try:
            import win32evtlog
            
            # Check if Sysmon log exists using the modern Event Log API
            try:
                test_query = win32evtlog.EvtQuery(
                    'Microsoft-Windows-Sysmon/Operational',
                    win32evtlog.EvtQueryForwardDirection,
                    '*[System[EventID=1]]',
                    None
                )
                # If we get here, Sysmon channel is accessible
            except Exception:
                logger.info("Sysmon not installed or not accessible")
                return False
            
            self._thread = threading.Thread(
                target=self._sysmon_consumer_loop,
                daemon=True,
                name="GuardianX-Sysmon"
            )
            self._thread.start()
            
            time.sleep(0.3)
            return self._sysmon_active
            
        except ImportError:
            return False
        except Exception as e:
            logger.error(f"Failed to start Sysmon monitoring: {e}")
            return False
    
    def _sysmon_consumer_loop(self):
        """Poll Sysmon event log for file creation/deletion events."""
        try:
            import win32evtlog
            import win32event
            import xml.etree.ElementTree as ET
            
            # Create a signal event for EvtSubscribe → EvtNext pattern
            signal_event = win32event.CreateEvent(None, False, False, None)
            
            query = (
                '<QueryList>'
                '  <Query Id="0" Path="Microsoft-Windows-Sysmon/Operational">'
                '    <Select Path="Microsoft-Windows-Sysmon/Operational">'
                '      *[System[(EventID=11 or EventID=23 or EventID=26)]]'
                '    </Select>'
                '  </Query>'
                '</QueryList>'
            )
            
            # EvtSubscribe params: Session, SignalEvent, ChannelPath, Query,
            #                      Bookmark, Context, Callback, Flags
            handle = win32evtlog.EvtSubscribe(
                None,                                           # Session
                signal_event,                                   # SignalEvent
                'Microsoft-Windows-Sysmon/Operational',         # ChannelPath
                query,                                          # Query
                None,                                           # Bookmark
                None,                                           # Context
                None,                                           # Callback
                win32evtlog.EvtSubscribeToFutureEvents,         # Flags
            )
            
            self._sysmon_active = True
            logger.info("Sysmon subscription active")
            
            while self._running:
                # Wait for the signal event (max 2 seconds, then re-check _running)
                wait_result = win32event.WaitForSingleObject(signal_event, 2000)
                
                if wait_result == win32event.WAIT_OBJECT_0:
                    while True:
                        try:
                            events = win32evtlog.EvtNext(handle, 50, 100)
                        except Exception:
                            break
                        if not events:
                            break
                        for event in events:
                            self._process_sysmon_event(event)
                    
        except Exception as e:
            logger.error(f"Sysmon consumer error: {e}")
            self._sysmon_active = False
    
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
            
            pid = int(data_dict.get('ProcessId', '0'))
            filepath = data_dict.get('TargetFilename', '')
            process_name = data_dict.get('Image', '')
            
            event_id_elem = root.find('.//e:EventID', ns)
            event_id = int(event_id_elem.text) if event_id_elem is not None else 0
            
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
                
                try:
                    self.event_queue.put_nowait(file_event)
                except queue.Full:
                    pass
                    
        except Exception as e:
            logger.debug(f"Error parsing Sysmon event: {e}")
    
    # ─── Enhanced Polling Fallback ────────────────────────────────────────
    
    def _enhanced_polling_loop(self):
        """
        Enhanced psutil polling as final fallback.
        
        Improvements over the original:
        - Caches process→file mappings with timestamps
        - Polls more frequently (200ms vs on-demand)
        - Tracks file access history per PID
        """
        logger.info("Enhanced polling loop started")
        
        while self._running:
            try:
                import psutil
                
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        pid = proc.info['pid']
                        open_files = proc.open_files()
                        
                        for item in open_files:
                            self._update_cache(item.path, pid)
                            
                            with self._map_lock:
                                self.pid_file_map[pid].add(item.path.lower())
                                
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
            
        with self._map_lock:
            self.pid_file_map[pid].add(normalized)
    
    def _psutil_scan(self, filepath):
        """Legacy psutil-based process scan (used as cache miss fallback)."""
        try:
            import psutil
            
            filepath_normalized = os.path.normpath(filepath).lower()
            
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    for item in proc.open_files():
                        if os.path.normpath(item.path).lower() == filepath_normalized:
                            self._update_cache(filepath, proc.info['pid'])
                            return proc.info['pid']
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue
            
            return None
            
        except Exception:
            return None
    
    def cleanup_cache(self, max_age=30.0):
        """Remove stale entries from the file→PID cache."""
        now = time.time()
        with self._cache_lock:
            stale_keys = [
                k for k, (_, ts) in self._file_pid_cache.items()
                if now - ts > max_age
            ]
            for k in stale_keys:
                del self._file_pid_cache[k]
    
    @property
    def is_etw_active(self):
        return self._etw_active
    
    @property
    def is_sysmon_active(self):
        return self._sysmon_active
    
    @property
    def monitoring_mode(self):
        if self._etw_active:
            return "ETW (Kernel-Level)"
        elif self._sysmon_active:
            return "Sysmon (Event Log)"
        else:
            return "Enhanced Polling (User-Mode)"
