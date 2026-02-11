"""
GuardianX Local Ransomware Simulator
SAFE TO RUN LOCALLY
Only modifies files inside Desktop/GuardianX_Test
"""

import os
import time
import random
from pathlib import Path
from datetime import datetime


class RansomwareSimulator:

    def __init__(self):
        self.test_dir = Path.home() / "Desktop" / "GuardianX_Test"

        # Hard safety lock
        if str(self.test_dir).lower() in ["c:\\", "c:/", str(Path.home()).lower()]:
            raise Exception("Unsafe test directory.")

        self.test_dir.mkdir(parents=True, exist_ok=True)
        print(f"[SAFE MODE] Using test directory: {self.test_dir}")

    def create_dummy_files(self, count=100):
        print(f"[SIMULATOR] Creating {count} test files...")

        file_types = [
            ('.txt', b'Test document\n' * 20),
            ('.pdf', b'%PDF-1.4\n%Test' + b'\x00' * 1000),
            ('.jpg', b'\xFF\xD8\xFF\xE0' + b'\x00' * 1000),
            ('.docx', b'PK\x03\x04' + b'\x00' * 1000),
            ('.png', b'\x89PNG\r\n\x1a\n' + b'\x00' * 1000),
        ]

        files = []

        for i in range(count):
            ext, content = random.choice(file_types)
            file_path = self.test_dir / f"document_{i:03d}{ext}"

            with open(file_path, "wb") as f:
                f.write(content)

            files.append(file_path)

        return files

    # ---------------- ATTACK TYPES ----------------

    def fast_attack(self, files):
        print("\n[ATTACK] FAST ransomware simulation (0.05s delay)")
        for i, file in enumerate(files):
            self._encrypt(file)
            print(f"[FAST] {i+1}/{len(files)} encrypted")
            time.sleep(0.05)
        self._ransom_note()

    def slow_attack(self, files):
        print("\n[ATTACK] SLOW stealth simulation (3s delay)")
        for i, file in enumerate(files[:20]):
            self._encrypt(file)
            print(f"[SLOW] {i+1}/20 encrypted")
            time.sleep(3)
        self._ransom_note()

    def targeted_attack(self, files):
        print("\n[ATTACK] TARGETED simulation (PDF/DOCX only)")
        targets = [f for f in files if f.suffix in ['.pdf', '.docx']]
        for i, file in enumerate(targets):
            self._encrypt(file)
            print(f"[TARGETED] {i+1}/{len(targets)} encrypted")
            time.sleep(0.1)
        self._ransom_note()

    # ---------------- CORE METHODS ----------------

    def _encrypt(self, filepath):
        size = filepath.stat().st_size
        with open(filepath, "wb") as f:
            f.write(os.urandom(size))

    def _ransom_note(self):
        note_path = self.test_dir / "README_SIMULATION.txt"
        content = f"""
==============================
   GUARDIANX TEST SIMULATION
==============================

This is a SAFE LOCAL simulation.
Timestamp: {datetime.now().isoformat()}
"""
        with open(note_path, "w") as f:
            f.write(content)

        print(f"[ATTACK] Ransom note created.")

    def cleanup(self):
        print("[CLEANUP] Removing test directory...")
        for file in self.test_dir.glob("*"):
            file.unlink()
        self.test_dir.rmdir()
        print("[CLEANUP] Done.")


# ---------------- MAIN ----------------

def main():
    print("""
╔═══════════════════════════════════╗
║  GuardianX Local Attack Simulator ║
╚═══════════════════════════════════╝
""")

    sim = RansomwareSimulator()
    files = sim.create_dummy_files(100)

    print("\nSelect attack type:")
    print("1. Fast Attack")
    print("2. Slow Attack")
    print("3. Targeted Attack")
    print("4. Files only")

    choice = input("\nChoice (1-4): ")

    input("\nStart GuardianX now if needed. Press ENTER to launch attack...")

    if choice == "1":
        sim.fast_attack(files)
    elif choice == "2":
        sim.slow_attack(files)
    elif choice == "3":
        sim.targeted_attack(files)
    elif choice == "4":
        print("Files created. No attack executed.")
    else:
        print("Invalid choice.")

    print("\nSimulation complete.")
    print(f"Test folder: {sim.test_dir}")

    delete = input("\nDelete test folder? (yes/no): ")
    if delete.lower() == "yes":
        sim.cleanup()


if __name__ == "__main__":
    main()
