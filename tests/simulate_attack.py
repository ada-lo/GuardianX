"""
GuardianX Realistic Ransomware Simulator v2
SAFE TO RUN LOCALLY — only modifies files inside Desktop/GuardianX_Test

Two-phase design:
  Phase 1 (setup):  Create legitimate test documents and WAIT so GuardianX
                     can index, backup, and learn their normal baselines.
  Phase 2 (attack): Simulate ransomware encrypting the pre-existing files.

Usage:
  python tests/simulate_attack.py setup       Create test files only
  python tests/simulate_attack.py attack      Attack existing test files
  python tests/simulate_attack.py full        Setup → wait → attack (interactive)
  python tests/simulate_attack.py cleanup     Remove test directory
"""

import os
import sys
import time
import random
from pathlib import Path
from datetime import datetime


TEST_DIR = Path.home() / "Desktop" / "GuardianX_Test"

# Hard safety lock
if str(TEST_DIR).lower() in ["c:\\", "c:/", str(Path.home()).lower()]:
    print("[SAFETY] Refusing to use unsafe test directory.")
    sys.exit(1)


# ──────────────────────────────────────────────────────────────────────
# Phase 1: Create legitimate documents
# ──────────────────────────────────────────────────────────────────────

def create_test_files(count=50):
    """Create realistic test files with valid magic bytes."""
    TEST_DIR.mkdir(parents=True, exist_ok=True)
    print(f"\n[SETUP] Creating {count} legitimate test files in {TEST_DIR}")

    templates = [
        ('.txt',  b'This is a normal text document.\nLorem ipsum dolor sit amet.\n' * 10),
        ('.pdf',  b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<< /Type /Catalog >>\nendobj\n' + b'\x00' * 800),
        ('.jpg',  b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01' + b'\x42' * 990),
        ('.docx', b'PK\x03\x04\x14\x00\x00\x00\x08\x00' + b'\x55' * 990),
        ('.png',  b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR' + b'\x33' * 986),
        ('.xlsx', b'PK\x03\x04\x14\x00\x06\x00\x08\x00' + b'\x44' * 990),
    ]

    files_created = []
    for i in range(count):
        ext, content = templates[i % len(templates)]
        filepath = TEST_DIR / f"document_{i:03d}{ext}"
        with open(filepath, "wb") as f:
            f.write(content)
        files_created.append(filepath)

    print(f"[SETUP] ✓ Created {len(files_created)} files")
    print(f"[SETUP] Extensions: {', '.join(set(f.suffix for f in files_created))}")
    return files_created


# ──────────────────────────────────────────────────────────────────────
# Phase 2: Ransomware simulation attacks
# ──────────────────────────────────────────────────────────────────────

def _encrypt_file(filepath):
    """Overwrite file contents with random bytes (simulates encryption)."""
    size = filepath.stat().st_size
    with open(filepath, "wb") as f:
        f.write(os.urandom(size))


def _drop_ransom_note():
    """Drop a ransom note that matches GuardianX's signature database."""
    note_path = TEST_DIR / "DECRYPT_INSTRUCTIONS.txt"
    note_path.write_text(f"""
=======================================
   YOUR FILES HAVE BEEN ENCRYPTED
   GuardianX TEST SIMULATION
=======================================

This is a SAFE LOCAL simulation.
Timestamp: {datetime.now().isoformat()}
All files in this directory have been encrypted.

To decrypt, send 1 BTC to: 1FAKE_ADDRESS_TEST_ONLY
""")
    print(f"[ATTACK] Ransom note dropped: {note_path.name}")


def fast_attack():
    """Rapid-fire encryption — 0.05s between files."""
    files = sorted(TEST_DIR.glob("document_*"))
    if not files:
        print("[ERROR] No test files found. Run 'setup' first.")
        return

    print(f"\n[ATTACK] FAST ransomware — encrypting {len(files)} files (0.05s delay)")
    _drop_ransom_note()  # Drop note FIRST — gives GuardianX the signal
    time.sleep(0.2)      # Brief pause so the note event gets processed

    for i, f in enumerate(files, 1):
        _encrypt_file(f)
        t = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        if i <= 5 or i % 10 == 0:
            print(f"[FAST] {i}/{len(files)} encrypted — {f.name} at {t}")
        time.sleep(0.05)

    print(f"[ATTACK] ✓ Fast attack complete — {len(files)} files encrypted")


def slow_attack():
    """Stealth encryption — 2s between files, only first 20."""
    files = sorted(TEST_DIR.glob("document_*"))[:20]
    if not files:
        print("[ERROR] No test files found. Run 'setup' first.")
        return

    print(f"\n[ATTACK] SLOW stealth — encrypting {len(files)} files (2s delay)")
    for i, f in enumerate(files, 1):
        _encrypt_file(f)
        t = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        print(f"[SLOW] {i}/{len(files)} encrypted — {f.name} at {t}")
        time.sleep(2)

    _drop_ransom_note()
    print(f"[ATTACK] ✓ Slow attack complete — {len(files)} files encrypted")


def targeted_attack():
    """Only encrypt PDF and DOCX files."""
    files = [f for f in TEST_DIR.glob("document_*") if f.suffix in ('.pdf', '.docx')]
    if not files:
        print("[ERROR] No PDF/DOCX files found. Run 'setup' first.")
        return

    print(f"\n[ATTACK] TARGETED — encrypting {len(files)} PDF/DOCX files (0.1s delay)")
    for i, f in enumerate(files, 1):
        _encrypt_file(f)
        t = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        print(f"[TARGETED] {i}/{len(files)} encrypted — {f.name} at {t}")
        time.sleep(0.1)

    _drop_ransom_note()
    print(f"[ATTACK] ✓ Targeted attack complete — {len(files)} files encrypted")


def cleanup():
    """Remove the test directory."""
    if TEST_DIR.exists():
        for f in TEST_DIR.iterdir():
            f.unlink()
        TEST_DIR.rmdir()
        print("[CLEANUP] ✓ Test directory removed")
    else:
        print("[CLEANUP] Nothing to clean — directory doesn't exist")


# ──────────────────────────────────────────────────────────────────────
# Interactive full demo
# ──────────────────────────────────────────────────────────────────────

def full_demo():
    """Interactive: setup → wait for GuardianX → attack."""
    print("""
╔══════════════════════════════════════════════╗
║   GuardianX Realistic Attack Simulator v2    ║
╠══════════════════════════════════════════════╣
║                                              ║
║   Phase 1: Create legitimate files           ║
║   Phase 2: Wait for GuardianX to index       ║
║   Phase 3: Launch ransomware simulation      ║
║                                              ║
╚══════════════════════════════════════════════╝
""")

    # Phase 1: Create files
    create_test_files(50)

    print("\n" + "=" * 50)
    print("  FILES CREATED — GuardianX should now be")
    print("  backing up and indexing these files.")
    print("=" * 50)
    print()
    print("  ⏳ Waiting 15 seconds for GuardianX to process...")
    print("     (Make sure GuardianX is running in another terminal)")
    print()

    for remaining in range(15, 0, -1):
        print(f"\r  Starting attack in {remaining}s... (press Ctrl+C to cancel)", end="", flush=True)
        time.sleep(1)
    print("\r" + " " * 60)

    # Phase 2: Select attack
    print("\nSelect attack type:")
    print("  1. Fast Attack   (0.05s delay — tests rapid detection)")
    print("  2. Slow Attack   (2s delay   — tests stealth detection)")
    print("  3. Targeted      (PDF/DOCX   — tests file-type analysis)")

    choice = input("\nChoice (1-3): ").strip()

    if choice == "1":
        fast_attack()
    elif choice == "2":
        slow_attack()
    elif choice == "3":
        targeted_attack()
    else:
        print("Invalid choice.")
        return

    print(f"\n[DONE] Simulation complete. Test folder: {TEST_DIR}")
    response = input("Delete test folder? (yes/no): ").strip()
    if response.lower() == "yes":
        cleanup()


# ──────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────

def main():
    usage = """
Usage: python tests/simulate_attack.py <command>

Commands:
  setup     Create test files only (let GuardianX learn them first)
  attack    Attack existing files (run after 'setup')
  full      Full interactive demo (setup → wait → attack)
  cleanup   Remove the test directory
"""

    if len(sys.argv) < 2:
        print(usage)
        return

    cmd = sys.argv[1].lower()

    if cmd == "setup":
        create_test_files(50)
        print("\n  Now start GuardianX (python run.py) and wait ~15s,")
        print("  then run: python tests/simulate_attack.py attack")

    elif cmd == "attack":
        if not TEST_DIR.exists():
            print("[ERROR] No test directory found. Run 'setup' first.")
            return
        print("\nSelect attack type:")
        print("  1. Fast Attack")
        print("  2. Slow Attack")
        print("  3. Targeted Attack")
        choice = input("\nChoice (1-3): ").strip()
        if choice == "1":
            fast_attack()
        elif choice == "2":
            slow_attack()
        elif choice == "3":
            targeted_attack()
        else:
            print("Invalid choice.")

    elif cmd == "full":
        full_demo()

    elif cmd == "cleanup":
        cleanup()

    else:
        print(f"Unknown command: {cmd}")
        print(usage)


if __name__ == "__main__":
    main()
