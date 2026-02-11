"""
GuardianX CLI Utility v2.0
Command-line interface for managing GuardianX operations.
Includes new commands: restore, backups, baseline, evasion, dashboard.
"""

import sys
import json
from pathlib import Path
from datetime import datetime

from config import *
from process_manager import ProcessManager


def show_status():
    """Show current GuardianX status"""
    print("\n" + "="*60)
    print("GuardianX Status")
    print("="*60)
    
    pm = ProcessManager()
    
    # Show suspended processes
    suspended = pm.get_suspended_processes()
    print(f"\nSuspended Processes: {len(suspended)}")
    if suspended:
        for pid, info in suspended:
            print(f"  PID {pid}: {info['info']['name']}")
            print(f"    Reason: {info['reason']}")
            print(f"    Time: {info['timestamp']}")
            print()
    
    # Show recent threats
    threats = pm.get_threat_log(limit=10)
    print(f"\nRecent Threats: {len(threats)}")
    for threat in threats:
        print(f"  [{threat['timestamp']}] PID {threat['pid']}")
        print(f"    Action: {threat['action']}")
        print(f"    Reason: {threat['reason']}")
        print()
    
    # Show self-protection status
    try:
        from self_defense import SelfDefense
        protection = SelfDefense.get_protection_status()
        print(f"Self-Protection:")
        print(f"  PID: {protection['pid']}")
        print(f"  Priority: {protection['priority']}")
        print(f"  Admin: {protection['is_admin']}")
        print(f"  Heartbeat: {'Active' if protection['heartbeat_active'] else 'Inactive'}")
    except Exception:
        pass
    
    # Show backup stats
    try:
        from file_recovery import FileRecoveryManager
        recovery = FileRecoveryManager()
        stats = recovery.get_backup_stats()
        print(f"\nFile Recovery:")
        print(f"  Backed up files: {stats['total_files']}")
        print(f"  Storage used: {stats['total_size_mb']}MB / {stats['max_size_mb']}MB ({stats['usage_percent']}%)")
    except Exception:
        pass
    
    # Show baseline status
    try:
        from adaptive_baseline import AdaptiveBaseline
        baseline = AdaptiveBaseline()
        info = baseline.get_baseline_info()
        print(f"\nAdaptive Baseline:")
        print(f"  Mode: {info['mode']}")
        print(f"  Profiled processes: {info['total_profiled_processes']}")
        print(f"  Global EMA: {info['global_ema']} files/hour")
        print(f"  Global samples: {info['global_samples']}")
    except Exception:
        pass


def undo_suspension(pid):
    """Resume a suspended process"""
    try:
        pid = int(pid)
        pm = ProcessManager()
        success, message = pm.resume_process(pid)
        
        if success:
            print(f"✓ {message}")
        else:
            print(f"✗ {message}")
    
    except ValueError:
        print(f"✗ Invalid PID: {pid}")


def view_logs(log_type='all', limit=20):
    """View GuardianX logs"""
    print("\n" + "="*60)
    print(f"GuardianX Logs ({log_type})")
    print("="*60 + "\n")
    
    log_files = {
        'threats': THREAT_LOG,
        'suspended': SUSPEND_LOG,
        'activity': ACTIVITY_LOG,
    }
    
    if log_type == 'all':
        files_to_read = log_files.values()
    elif log_type in log_files:
        files_to_read = [log_files[log_type]]
    else:
        print(f"Unknown log type: {log_type}")
        print(f"Available: {', '.join(log_files.keys())}, all")
        return
    
    all_entries = []
    
    for log_file in files_to_read:
        if log_file.exists():
            try:
                with open(log_file, 'r') as f:
                    entries = json.load(f)
                    all_entries.extend(entries)
            except Exception as e:
                print(f"Error reading {log_file}: {e}")
    
    # Sort by timestamp
    all_entries.sort(key=lambda x: x['timestamp'], reverse=True)
    
    # Show most recent entries
    for entry in all_entries[:limit]:
        print(f"[{entry['timestamp']}] {entry['action']} - PID {entry['pid']}")
        print(f"  {entry['reason']}")
        print()
    
    if len(all_entries) > limit:
        print(f"... and {len(all_entries) - limit} more entries")


def clear_logs():
    """Clear all log files"""
    response = input("Are you sure you want to clear all logs? (yes/no): ")
    
    if response.lower() == 'yes':
        for log_file in [THREAT_LOG, SUSPEND_LOG, ACTIVITY_LOG]:
            if log_file.exists():
                log_file.unlink()
        
        print("✓ All logs cleared")
    else:
        print("✗ Cancelled")


def show_config():
    """Display current configuration"""
    print("\n" + "="*60)
    print("GuardianX Configuration")
    print("="*60 + "\n")
    
    print(f"Detection Thresholds:")
    print(f"  Slow-Burn: {SLOW_BURN_THRESHOLD} files / {SLOW_BURN_WINDOW}s")
    print(f"  Idle Timeout: {IDLE_TIMEOUT}s")
    print(f"  Idle Paranoia: {IDLE_PARANOIA_MULTIPLIER}x")
    print(f"  High Entropy: {HIGH_ENTROPY_THRESHOLD}")
    
    print(f"\nWhitelisted Processes: {len(WHITELISTED_PROCESSES)}")
    for proc in WHITELISTED_PROCESSES[:10]:
        print(f"  - {proc}")
    if len(WHITELISTED_PROCESSES) > 10:
        print(f"  ... and {len(WHITELISTED_PROCESSES) - 10} more")
    
    print(f"\nTrusted Signers: {len(TRUSTED_SIGNERS)}")
    for signer in TRUSTED_SIGNERS[:5]:
        print(f"  - {signer}")
    if len(TRUSTED_SIGNERS) > 5:
        print(f"  ... and {len(TRUSTED_SIGNERS) - 5} more")
    
    print(f"\nLog Directory: {LOG_DIR}")


def restore_file(filepath):
    """Restore a file from backup"""
    try:
        from file_recovery import FileRecoveryManager
        recovery = FileRecoveryManager()
        
        # Try local backup first
        success, message = recovery.restore_file(filepath)
        if success:
            print(f"✓ {message}")
            return
        
        print(f"Local backup: {message}")
        
        # Try VSS
        print("Attempting Volume Shadow Copy restore...")
        success, message = recovery.restore_from_vss(filepath)
        if success:
            print(f"✓ {message}")
        else:
            print(f"✗ {message}")
    
    except Exception as e:
        print(f"✗ Restore error: {e}")


def list_backups(limit=20):
    """List available file backups"""
    try:
        from file_recovery import FileRecoveryManager
        recovery = FileRecoveryManager()
        
        backups = recovery.list_backups(limit=limit)
        stats = recovery.get_backup_stats()
        
        print("\n" + "="*60)
        print(f"GuardianX File Backups ({stats['total_files']} files, {stats['total_size_mb']}MB)")
        print("="*60 + "\n")
        
        if not backups:
            print("No backups available.")
            return
        
        for backup in backups:
            status = "✓" if backup['available'] else "✗"
            size_kb = backup['size'] / 1024
            print(f"  {status} {backup['original_name']} ({size_kb:.1f}KB)")
            print(f"    Path: {backup['original_path']}")
            print(f"    Backed up: {backup['timestamp']}")
            print()
        
    except Exception as e:
        print(f"✗ Error listing backups: {e}")


def launch_dashboard():
    """Launch the web dashboard"""
    try:
        from dashboard.app import app
        import uvicorn
        
        print("\n" + "="*60)
        print("GuardianX Dashboard")
        print("="*60)
        print(f"\nStarting dashboard at http://localhost:9090")
        print("Press Ctrl+C to stop\n")
        
        uvicorn.run(app, host="0.0.0.0", port=9090, log_level="info")
        
    except ImportError:
        print("✗ Dashboard dependencies not installed.")
        print("  Run: pip install fastapi uvicorn")
    except Exception as e:
        print(f"✗ Dashboard error: {e}")


def show_help():
    """Display help information"""
    help_text = """
GuardianX CLI Utility v2.0

Usage: python guardianx.py <command> [arguments]

Commands:
  status              Show current GuardianX status
  undo <pid>          Resume a suspended process
  logs [type] [limit] View logs (type: threats|suspended|activity|all)
  clear-logs          Clear all log files
  config              Show current configuration
  restore <filepath>  Restore a file from backup or VSS
  backups [limit]     List available file backups
  dashboard           Launch the web dashboard
  help                Show this help message

Examples:
  python guardianx.py status
  python guardianx.py undo 1234
  python guardianx.py logs threats 10
  python guardianx.py restore C:\\Users\\user\\Documents\\file.pdf
  python guardianx.py backups 50
  python guardianx.py dashboard

To run GuardianX protection:
  python main.py

To run without dashboard:
  python main.py --no-dashboard

To test with simulated attacks:
  python test_attack.py
"""
    print(help_text)


def main():
    """Main CLI entry point"""
    if len(sys.argv) < 2:
        show_help()
        return
    
    command = sys.argv[1].lower()
    
    if command == 'status':
        show_status()
    
    elif command == 'undo':
        if len(sys.argv) < 3:
            print("Usage: python guardianx.py undo <pid>")
        else:
            undo_suspension(sys.argv[2])
    
    elif command == 'logs':
        log_type = sys.argv[2] if len(sys.argv) > 2 else 'all'
        limit = int(sys.argv[3]) if len(sys.argv) > 3 else 20
        view_logs(log_type, limit)
    
    elif command == 'clear-logs':
        clear_logs()
    
    elif command == 'config':
        show_config()
    
    elif command == 'restore':
        if len(sys.argv) < 3:
            print("Usage: python guardianx.py restore <filepath>")
        else:
            restore_file(sys.argv[2])
    
    elif command == 'backups':
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else 20
        list_backups(limit)
    
    elif command == 'dashboard':
        launch_dashboard()
    
    elif command == 'help':
        show_help()
    
    else:
        print(f"Unknown command: {command}")
        print("Run 'python guardianx.py help' for usage information")


if __name__ == '__main__':
    main()
