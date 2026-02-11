"""
GuardianX Evasion Detector
Detects advanced ransomware evasion techniques:
- Parent-child process chain analysis
- Command-line argument inspection
- Living-off-the-Land Binary (LOLBin) abuse
- Process injection detection
- Trusted process abuse patterns
"""

import os
import re
import logging
import psutil
from pathlib import Path

logger = logging.getLogger("GuardianX.Evasion")

# Living-off-the-Land Binaries — legitimate Windows tools abused by malware
LOLBINS = {
    'certutil.exe': {
        'suspicious_args': ['-urlcache', '-decode', '-encode', '-decodehex', 'http://', 'https://'],
        'description': 'Certificate utility — can download files and decode payloads',
    },
    'mshta.exe': {
        'suspicious_args': ['javascript:', 'vbscript:', 'http://', 'https://'],
        'description': 'HTML Application host — can execute scripts',
    },
    'rundll32.exe': {
        'suspicious_args': ['javascript:', 'shell32.dll', 'url.dll', 'temp', 'appdata'],
        'description': 'DLL loader — can execute arbitrary DLL functions',
    },
    'regsvr32.exe': {
        'suspicious_args': ['/s', '/u', '/i:http', 'scrobj.dll'],
        'description': 'COM object registration — can execute remote scripts',
    },
    'wmic.exe': {
        'suspicious_args': ['process', 'call', 'create', '/node:', 'shadowcopy', 'delete'],
        'description': 'WMI command line — can execute commands and delete shadow copies',
    },
    'bitsadmin.exe': {
        'suspicious_args': ['/transfer', '/create', '/addfile', 'http://', 'https://'],
        'description': 'BITS transfer — can download files stealthily',
    },
    'powershell.exe': {
        'suspicious_args': [
            '-enc', '-encodedcommand', '-e ', 'downloadstring', 'iex',
            'invoke-expression', 'bypass', '-nop', '-w hidden',
            'webclient', 'bitstransfer', 'start-process',
            'new-object net.webclient', 'invoke-webrequest',
        ],
        'description': 'PowerShell — most abused LOLBin for fileless attacks',
    },
    'cmd.exe': {
        'suspicious_args': [
            '/c powershell', '/c certutil', '/c wmic', 'shadowcopy',
            'vssadmin delete', 'bcedit /set',
        ],
        'description': 'Command prompt — used to chain other LOLBins',
    },
    'cscript.exe': {
        'suspicious_args': ['//e:jscript', '//e:vbscript', 'http://', '.js', '.vbs'],
        'description': 'Script host — executes VBScript/JScript remotely',
    },
    'wscript.exe': {
        'suspicious_args': ['//e:jscript', '//e:vbscript', 'http://', '.js', '.vbs'],
        'description': 'Windows Script Host — executes scripts',
    },
    'msiexec.exe': {
        'suspicious_args': ['/q', 'http://', 'https://', '/i'],
        'description': 'MSI installer — can install payloads silently',
    },
}

# Shadow copy deletion patterns — critical ransomware indicator
SHADOW_DELETE_PATTERNS = [
    r'vssadmin.*delete.*shadows',
    r'wmic.*shadowcopy.*delete',
    r'bcdedit.*/set.*recoveryenabled.*no',
    r'wbadmin.*delete.*catalog',
    r'bcdedit.*/set.*bootstatuspolicy.*ignoreallfailures',
]

# Suspicious directory patterns
SUSPICIOUS_EXEC_DIRS = [
    'temp', 'tmp', 'appdata\\local\\temp', 'appdata\\roaming',
    'programdata', 'public', 'recycler', '$recycle.bin',
]


class EvasionDetector:
    """
    Detects advanced evasion techniques used by modern ransomware.
    
    Analyzes process context beyond simple name/signature matching:
    - Is a trusted process being abused by a suspicious parent?
    - Is a LOLBin running with attack-pattern arguments?
    - Is a process running from an unusual location?
    - Does the process tree look like a malware execution chain?
    """
    
    def __init__(self):
        self._analysis_cache = {}  # pid → (score, timestamp)
        self._cache_ttl = 30  # Reuse analysis for 30s
        logger.info("Evasion Detector initialized")
    
    def get_evasion_score(self, pid):
        """
        Calculate a composite evasion risk score for a process.
        
        Returns dict with:
        - score: float 0.0 (clean) to 1.0 (highly evasive)
        - indicators: list of detected evasion techniques
        - should_override_whitelist: bool — if True, whitelist should be bypassed
        """
        import time as _time
        
        # Check cache
        if pid in self._analysis_cache:
            cached_score, cached_time = self._analysis_cache[pid]
            if _time.time() - cached_time < self._cache_ttl:
                return cached_score
        
        result = {
            'score': 0.0,
            'indicators': [],
            'should_override_whitelist': False,
            'details': {},
        }
        
        try:
            proc = psutil.Process(pid)
            
            # Run all checks
            self._check_parent_chain(proc, result)
            self._check_command_line(proc, result)
            self._check_lolbin_abuse(proc, result)
            self._check_execution_location(proc, result)
            self._check_process_injection(proc, result)
            self._check_shadow_copy_deletion(proc, result)
            
            # Cap score at 1.0
            result['score'] = min(1.0, result['score'])
            
            # Override whitelist if score is very high
            if result['score'] >= 0.7:
                result['should_override_whitelist'] = True
            
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        except Exception as e:
            logger.debug(f"Evasion analysis error for PID {pid}: {e}")
        
        # Cache result
        self._analysis_cache[pid] = (result, _time.time())
        
        return result
    
    def _check_parent_chain(self, proc, result):
        """
        Walk the parent process tree.
        
        Flags suspicious patterns:
        - Trusted process spawned by untrusted parent
        - Deep process chains (normal is 2-3 levels)
        - Unexpected parent (e.g., explorer.exe spawning PowerShell spawning cmd)
        """
        try:
            chain = []
            current = proc
            depth = 0
            max_depth = 10
            
            while current and depth < max_depth:
                try:
                    info = {
                        'pid': current.pid,
                        'name': current.name().lower(),
                        'exe': current.exe() if current.pid != 0 else 'System',
                    }
                    chain.append(info)
                    current = current.parent()
                    depth += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    break
            
            result['details']['process_chain'] = [c['name'] for c in chain]
            
            if len(chain) >= 2:
                child_name = chain[0]['name']
                parent_name = chain[1]['name']
                
                # Suspicious parent-child relationships
                suspicious_chains = [
                    # Office document spawning command shells
                    ({'winword.exe', 'excel.exe', 'powerpnt.exe'}, 
                     {'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe'}),
                    # Browser spawning command shells (drive-by)
                    ({'chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe'},
                     {'cmd.exe', 'powershell.exe', 'mshta.exe'}),
                    # Services hosting unusual children
                    ({'svchost.exe', 'services.exe'},
                     {'powershell.exe', 'cmd.exe', 'mshta.exe'}),
                ]
                
                for parents, children in suspicious_chains:
                    if parent_name in parents and child_name in children:
                        result['score'] += 0.3
                        result['indicators'].append(
                            f"Suspicious parent-child: {parent_name} → {child_name}"
                        )
                        break
            
            # Deep chains are suspicious
            if len(chain) > 5:
                result['score'] += 0.1
                result['indicators'].append(f"Deep process chain ({len(chain)} levels)")
                
        except Exception as e:
            logger.debug(f"Parent chain analysis error: {e}")
    
    def _check_command_line(self, proc, result):
        """
        Analyze process command-line arguments for encoded commands,
        download cradles, and obfuscation patterns.
        """
        try:
            cmdline = ' '.join(proc.cmdline()).lower()
            
            if not cmdline:
                return
            
            result['details']['cmdline'] = cmdline[:200]  # Truncate for storage
            
            # Encoded PowerShell commands
            if re.search(r'-e(nc(odedcommand)?)?[\s]+[A-Za-z0-9+/=]{50,}', cmdline):
                result['score'] += 0.4
                result['indicators'].append("Encoded PowerShell command detected")
            
            # Download cradles
            download_patterns = [
                r'(new-object\s+net\.webclient)',
                r'(invoke-webrequest|iwr|wget|curl)',
                r'(downloadstring|downloadfile)',
                r'(start-bitstransfer)',
                r'(certutil.*-urlcache)',
            ]
            
            for pattern in download_patterns:
                if re.search(pattern, cmdline):
                    result['score'] += 0.3
                    result['indicators'].append(f"Download cradle pattern: {pattern}")
                    break
            
            # Invoke-Expression (IEX) — code execution
            if re.search(r'\biex\b|\binvoke-expression\b', cmdline):
                result['score'] += 0.2
                result['indicators'].append("Invoke-Expression detected")
            
            # ExecutionPolicy bypass
            if 'bypass' in cmdline and 'executionpolicy' in cmdline:
                result['score'] += 0.1
                result['indicators'].append("ExecutionPolicy bypass")
            
            # Hidden window
            if '-w hidden' in cmdline or '-windowstyle hidden' in cmdline:
                result['score'] += 0.15
                result['indicators'].append("Hidden window execution")
            
            # Base64-like long strings in arguments
            if re.search(r'[A-Za-z0-9+/=]{100,}', cmdline):
                result['score'] += 0.2
                result['indicators'].append("Long Base64-like string in arguments")
                
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
        except Exception as e:
            logger.debug(f"Command line analysis error: {e}")
    
    def _check_lolbin_abuse(self, proc, result):
        """
        Check if a Living-off-the-Land Binary is being used with
        suspicious arguments.
        """
        try:
            proc_name = proc.name().lower()
            
            if proc_name not in LOLBINS:
                return
            
            lolbin = LOLBINS[proc_name]
            cmdline = ' '.join(proc.cmdline()).lower()
            
            matched_args = []
            for suspicious_arg in lolbin['suspicious_args']:
                if suspicious_arg.lower() in cmdline:
                    matched_args.append(suspicious_arg)
            
            if matched_args:
                score_contribution = min(0.4, len(matched_args) * 0.15)
                result['score'] += score_contribution
                result['indicators'].append(
                    f"LOLBin abuse: {proc_name} with args [{', '.join(matched_args[:3])}]"
                )
                result['details']['lolbin'] = {
                    'binary': proc_name,
                    'matched_args': matched_args,
                    'description': lolbin['description'],
                }
                
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
        except Exception as e:
            logger.debug(f"LOLBin analysis error: {e}")
    
    def _check_execution_location(self, proc, result):
        """
        Check if the process is running from a suspicious directory.
        
        Legitimate applications run from Program Files or System32.
        Malware often runs from temp directories, AppData, or user folders.
        """
        try:
            exe_path = proc.exe().lower()
            
            # Check for suspicious execution directories
            for suspicious_dir in SUSPICIOUS_EXEC_DIRS:
                if suspicious_dir in exe_path:
                    # Don't flag known legitimate temp executables
                    known_temp_procs = ['setup.exe', 'update.exe', 'installer.exe']
                    proc_name = proc.name().lower()
                    
                    if proc_name not in known_temp_procs:
                        result['score'] += 0.15
                        result['indicators'].append(
                            f"Executing from suspicious path: {exe_path[:60]}..."
                        )
                    break
            
            # Check for double extensions (malware.pdf.exe)
            name = proc.name().lower()
            common_extensions = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.jpg', '.png', '.txt']
            for ext in common_extensions:
                if ext in name and name.endswith('.exe'):
                    result['score'] += 0.3
                    result['indicators'].append(f"Double extension detected: {name}")
                    break
                    
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
        except Exception as e:
            logger.debug(f"Execution location analysis error: {e}")
    
    def _check_process_injection(self, proc, result):
        """
        Detect indicators of process injection/hollowing.
        
        Checks:
        - Mismatch between process name and actual executable path
        - Processes with unusual memory regions
        - System processes running from wrong locations
        """
        try:
            proc_name = proc.name().lower()
            exe_path = proc.exe().lower()
            
            # System process location validation
            # These should ONLY run from System32
            system32_only = {
                'svchost.exe': 'windows\\system32\\svchost.exe',
                'csrss.exe': 'windows\\system32\\csrss.exe',
                'lsass.exe': 'windows\\system32\\lsass.exe',
                'services.exe': 'windows\\system32\\services.exe',
                'smss.exe': 'windows\\system32\\smss.exe',
                'winlogon.exe': 'windows\\system32\\winlogon.exe',
            }
            
            if proc_name in system32_only:
                expected_path = system32_only[proc_name]
                if expected_path not in exe_path:
                    result['score'] += 0.5
                    result['indicators'].append(
                        f"PROCESS MASQUERADE: {proc_name} running from {exe_path} "
                        f"(expected {expected_path})"
                    )
            
            # Check for unsigned processes with system names
            system_names = {'explorer.exe', 'taskmgr.exe', 'regedit.exe'}
            if proc_name in system_names and 'windows' not in exe_path:
                result['score'] += 0.4
                result['indicators'].append(
                    f"Process impersonation: {proc_name} not running from Windows directory"
                )
                
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
        except Exception as e:
            logger.debug(f"Process injection analysis error: {e}")
    
    def _check_shadow_copy_deletion(self, proc, result):
        """
        Check if the process is attempting to delete Volume Shadow Copies.
        This is a CRITICAL ransomware indicator — almost no legitimate
        software deletes shadow copies.
        """
        try:
            cmdline = ' '.join(proc.cmdline()).lower()
            
            for pattern in SHADOW_DELETE_PATTERNS:
                if re.search(pattern, cmdline):
                    result['score'] += 0.5  # Very high weight
                    result['indicators'].append(
                        f"CRITICAL: Shadow copy deletion attempt detected"
                    )
                    result['should_override_whitelist'] = True
                    break
                    
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
        except Exception as e:
            logger.debug(f"Shadow copy deletion check error: {e}")
    
    def cleanup_cache(self):
        """Remove stale entries from the analysis cache."""
        import time as _time
        now = _time.time()
        stale = [pid for pid, (_, ts) in self._analysis_cache.items() 
                 if now - ts > self._cache_ttl]
        for pid in stale:
            del self._analysis_cache[pid]
