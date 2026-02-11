"""
GuardianX Debug Script
Run this to diagnose why ransomware detection isn't working
"""

import os
import sys
import time
import psutil
from pathlib import Path
import json

print("="*60)
print("GuardianX Detection Failure Diagnostic Tool")
print("="*60)

# 1. Check if config.py has python.exe whitelisted
print("\n[1] Checking config.py whitelist...")
try:
    from config import WHITELISTED_PROCESSES
    if 'python.exe' in WHITELISTED_PROCESSES:
        print("❌ PROBLEM FOUND: python.exe is in WHITELISTED_PROCESSES")
        print("   → GuardianX will ALLOW all python.exe file modifications!")
        print("   → FIX: Edit config.py and comment out 'python.exe'")
    else:
        print("✅ python.exe is NOT whitelisted (good)")
except Exception as e:
    print(f"❌ Error reading config: {e}")

# 2. Check monitored directories
print("\n[2] Checking monitored directories...")
try:
    user_home = Path.home()
    desktop = user_home / 'Desktop'
    test_dir = desktop / 'GuardianX_Test'
    
    print(f"   User home: {user_home}")
    print(f"   Desktop: {desktop} (exists: {desktop.exists()})")
    print(f"   Test dir: {test_dir} (exists: {test_dir.exists()})")
    
    if not desktop.exists():
        print("❌ PROBLEM: Desktop directory doesn't exist!")
    elif not test_dir.exists():
        print("⚠️  Test directory doesn't exist yet (will be created by simulator)")
    else:
        print("✅ Test directory exists")
        files = list(test_dir.glob("*"))
        print(f"   Files in test dir: {len(files)}")
        if files:
            print(f"   Sample files: {[f.name for f in files[:5]]}")
except Exception as e:
    print(f"❌ Error checking directories: {e}")

# 3. Check if GuardianX is running
print("\n[3] Checking if GuardianX is running...")
try:
    guardian_found = False
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if proc.info['name'] == 'python.exe':
                cmdline = proc.info['cmdline']
                if cmdline and 'main.py' in ' '.join(cmdline):
                    print(f"✅ GuardianX found: PID {proc.info['pid']}")
                    print(f"   Command: {' '.join(cmdline)}")
                    guardian_found = True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    if not guardian_found:
        print("❌ GuardianX (main.py) is NOT running!")
        print("   → Start it first: py main.py")
except Exception as e:
    print(f"❌ Error checking processes: {e}")

# 4. Check logs
print("\n[4] Checking GuardianX logs...")
try:
    log_dir = Path(os.getenv('TEMP')) / 'GuardianX' / 'logs'
    print(f"   Log directory: {log_dir}")
    print(f"   Exists: {log_dir.exists()}")
    
    if log_dir.exists():
        threats_log = log_dir / 'threats.json'
        suspended_log = log_dir / 'suspended.json'
        activity_log = log_dir / 'activity.json'
        
        print(f"\n   Threats log: {threats_log.exists()}")
        if threats_log.exists():
            try:
                with open(threats_log, 'r') as f:
                    threats = json.load(f)
                print(f"   Threats detected: {len(threats)}")
                if threats:
                    print(f"   Last threat: {threats[-1]}")
            except:
                print(f"   Size: {threats_log.stat().st_size} bytes")
        
        print(f"\n   Suspended log: {suspended_log.exists()}")
        if suspended_log.exists():
            try:
                with open(suspended_log, 'r') as f:
                    suspended = json.load(f)
                print(f"   Processes suspended: {len(suspended)}")
                if suspended:
                    print(f"   Last suspension: {suspended[-1]}")
            except:
                print(f"   Size: {suspended_log.stat().st_size} bytes")
        
        print(f"\n   Activity log: {activity_log.exists()}")
        if activity_log.exists():
            try:
                size = activity_log.stat().st_size
                print(f"   Size: {size} bytes")
                if size > 0:
                    with open(activity_log, 'r') as f:
                        # Read last few lines
                        lines = f.readlines()
                        print(f"   Total events: {len(lines)}")
                        if lines:
                            print(f"   Last event: {lines[-1].strip()}")
            except Exception as e:
                print(f"   Error reading: {e}")
    else:
        print("❌ Log directory doesn't exist - GuardianX may not have started properly")
except Exception as e:
    print(f"❌ Error checking logs: {e}")

# 5. Test file system watcher
print("\n[5] Testing file system event detection...")
print("   This will create a test file to see if GuardianX detects it.")
print("   Make sure GuardianX is running before continuing!")
input("   Press ENTER to create test file (or Ctrl+C to skip)...")

try:
    test_file = Path.home() / 'Desktop' / 'guardianx_detection_test.txt'
    print(f"\n   Creating: {test_file}")
    
    with open(test_file, 'w') as f:
        f.write("This is a test file created at " + str(time.time()))
    
    print("   ✅ File created")
    print("\n   → Check GuardianX terminal for a message like:")
    print("      [GuardianX] File event: created - ...guardianx_detection_test.txt")
    print("\n   → If you see the message: File events ARE being detected ✅")
    print("   → If you DON'T see it: File watcher is NOT working ❌")
    
    time.sleep(2)
    
    # Modify the file
    print("\n   Modifying file...")
    with open(test_file, 'a') as f:
        f.write("\nModified at " + str(time.time()))
    
    print("   → Check for: [GuardianX] File event: modified - ...")
    
    time.sleep(1)
    test_file.unlink()
    print("   Test file deleted")
    
except Exception as e:
    print(f"❌ Error creating test file: {e}")

# 6. Check detection thresholds
print("\n[6] Checking detection thresholds...")
try:
    from config import SLOW_BURN_THRESHOLD, SLOW_BURN_WINDOW, IDLE_TIMEOUT
    print(f"   Slow-burn threshold: {SLOW_BURN_THRESHOLD} files")
    print(f"   Slow-burn window: {SLOW_BURN_WINDOW}s ({SLOW_BURN_WINDOW/60:.0f} minutes)")
    print(f"   Idle timeout: {IDLE_TIMEOUT}s ({IDLE_TIMEOUT/60:.0f} minutes)")
    print("\n   ⚠️  Note: Fast attack (0.1s delay) should trigger MAGIC BYTE detection")
    print("      NOT slow-burn detection (which needs 50+ files)")
except Exception as e:
    print(f"❌ Error reading thresholds: {e}")

# 7. Summary
print("\n" + "="*60)
print("SUMMARY & RECOMMENDATIONS")
print("="*60)

print("\n❓ If file events ARE detected but no threats found:")
print("   → Check if python.exe is whitelisted (Step 1)")
print("   → Check if process has visible window (SUSPEND instead of KILL)")
print("   → Check if you're considered ACTIVE (reduces aggression)")
print("   → Enable verbose logging in detectors.py")

print("\n❓ If file events are NOT detected:")
print("   → File watcher (watchdog) isn't working")
print("   → Check if Desktop path matches")
print("   → Try running as Administrator")
print("   → Check antivirus isn't blocking watchdog")

print("\n❓ To enable detailed logging:")
print("   → Edit main.py line 31-34")
print("   → Change logging.INFO to logging.DEBUG")
print("   → Restart GuardianX")

print("\n📝 Next steps:")
print("   1. Check if Step 1 found python.exe whitelisted → Fix it")
print("   2. Run the file creation test (Step 5) → Verify detection")
print("   3. If file events detected: Check logs for why no action taken")
print("   4. If file events NOT detected: watchdog issue")

print("\n" + "="*60)