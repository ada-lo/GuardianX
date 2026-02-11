"""
GuardianX Test Simulator
Simulates ransomware behavior in a controlled environment.
DO NOT RUN OUTSIDE OF A VM!
"""

import os
import time
import random
from pathlib import Path
from datetime import datetime


class RansomwareSimulator:
    """
    Simulates various ransomware attack patterns for testing.
    Creates dummy files and "encrypts" them (just scrambles content).
    """
    
    def __init__(self, test_dir=None):
        """Initialize simulator in a safe test directory"""
        if test_dir is None:
            self.test_dir = Path.home() / 'Desktop' / 'GuardianX_Test'
        else:
            self.test_dir = Path(test_dir)
        
        self.test_dir.mkdir(parents=True, exist_ok=True)
        print(f"[SIMULATOR] Test directory: {self.test_dir}")
    
    def create_dummy_files(self, count=100):
        """Create legitimate-looking test files"""
        print(f"[SIMULATOR] Creating {count} dummy files...")
        
        file_types = [
            ('.txt', b'This is a test document.\n' * 10),
            ('.pdf', b'%PDF-1.4\n%Test PDF content' + b'\x00' * 1000),
            ('.jpg', b'\xFF\xD8\xFF\xE0' + b'\x00' * 1000),
            ('.docx', b'PK\x03\x04' + b'\x00' * 1000),  # ZIP signature
            ('.png', b'\x89PNG\r\n\x1a\n' + b'\x00' * 1000),
        ]
        
        created_files = []
        
        for i in range(count):
            ext, content = random.choice(file_types)
            filename = self.test_dir / f"document_{i:03d}{ext}"
            
            with open(filename, 'wb') as f:
                f.write(content)
            
            created_files.append(filename)
        
        print(f"[SIMULATOR] Created {len(created_files)} files")
        return created_files
    
    def simulate_fast_attack(self, files, delay=0.1):
        """
        Simulate fast ransomware (WannaCry-style).
        Encrypts files rapidly.
        """
        print(f"\n[ATTACK] Simulating FAST ransomware attack...")
        print(f"[ATTACK] Delay between files: {delay}s")
        
        for i, filepath in enumerate(files):
            self._encrypt_file(filepath)
            print(f"[ATTACK] Encrypted {i+1}/{len(files)}: {filepath.name}")
            time.sleep(delay)
        
        # Create ransom note
        self._create_ransom_note()
    
    def simulate_slow_attack(self, files, delay=5.0):
        """
        Simulate slow ransomware (stealthy).
        Encrypts files slowly to avoid detection.
        """
        print(f"\n[ATTACK] Simulating SLOW ransomware attack...")
        print(f"[ATTACK] Delay between files: {delay}s")
        
        for i, filepath in enumerate(files[:20]):  # Only encrypt 20 files slowly
            self._encrypt_file(filepath)
            print(f"[ATTACK] Encrypted {i+1}/20: {filepath.name}")
            time.sleep(delay)
        
        self._create_ransom_note()
    
    def simulate_targeted_attack(self, files):
        """
        Simulate targeted attack on specific file types.
        Only encrypts PDFs and DOCXs.
        """
        print(f"\n[ATTACK] Simulating TARGETED attack (PDF/DOCX only)...")
        
        target_files = [f for f in files if f.suffix in ['.pdf', '.docx']]
        
        for i, filepath in enumerate(target_files):
            self._encrypt_file(filepath)
            print(f"[ATTACK] Encrypted {i+1}/{len(target_files)}: {filepath.name}")
            time.sleep(0.2)
        
        self._create_ransom_note()
    
    def _encrypt_file(self, filepath):
        """
        "Encrypt" a file by replacing its content with random bytes.
        In real ransomware, this would be actual encryption.
        """
        try:
            # Read original size
            original_size = filepath.stat().st_size
            
            # Generate random bytes (simulating encryption)
            random_data = os.urandom(original_size)
            
            # Overwrite file
            with open(filepath, 'wb') as f:
                f.write(random_data)
            
            # Optionally add ransomware extension
            # new_path = filepath.with_suffix(filepath.suffix + '.locked')
            # filepath.rename(new_path)
            
        except Exception as e:
            print(f"[ERROR] Failed to encrypt {filepath}: {e}")
    
    def _create_ransom_note(self):
        """Create a fake ransom note"""
        note_path = self.test_dir / 'README.txt'
        
        note_content = f"""
╔══════════════════════════════════════════════════════════╗
║              YOUR FILES HAVE BEEN ENCRYPTED              ║
╚══════════════════════════════════════════════════════════╝

What happened to my files?
--------------------------
All your important files (documents, photos, videos, databases)
have been encrypted with military-grade encryption.

This is a TEST simulation by GuardianX.
No actual harm has been done to your system.

Timestamp: {datetime.now().isoformat()}
Simulator: GuardianX Test Suite

If you see this note, it means ransomware reached the 
"Ransom Note Creation" phase. GuardianX should have 
stopped this before any real damage occurred.

═══════════════════════════════════════════════════════════
THIS IS A SIMULATION - Your actual files are safe
═══════════════════════════════════════════════════════════
"""
        
        with open(note_path, 'w') as f:
            f.write(note_content)
        
        print(f"\n[ATTACK] Ransom note created: {note_path}")


def main():
    """Run attack simulation"""
    print("""
    ╔═══════════════════════════════════════════╗
    ║   GuardianX Attack Simulator              ║
    ║                                           ║
    ║   WARNING: Only run in a VM!              ║
    ╚═══════════════════════════════════════════╝
    """)
    
    # Safety check
    response = input("\nAre you running this in a VM? (yes/no): ")
    if response.lower() != 'yes':
        print("[ABORTED] Please run this only in a virtual machine!")
        return
    
    # Create simulator
    sim = RansomwareSimulator()
    
    # Menu
    print("\n" + "="*50)
    print("Select attack type:")
    print("="*50)
    print("1. Fast Attack (0.1s delay) - Tests rapid detection")
    print("2. Slow Attack (5s delay) - Tests sliding window")
    print("3. Targeted Attack (PDF/DOCX only) - Tests selective encryption")
    print("4. Create test files only (no attack)")
    print("="*50)
    
    choice = input("\nEnter choice (1-4): ")
    
    # Create test files
    files = sim.create_dummy_files(count=100)
    
    if choice == '1':
        input("\n[READY] Press ENTER to start FAST attack...")
        sim.simulate_fast_attack(files, delay=0.1)
    
    elif choice == '2':
        input("\n[READY] Press ENTER to start SLOW attack...")
        sim.simulate_slow_attack(files, delay=5.0)
    
    elif choice == '3':
        input("\n[READY] Press ENTER to start TARGETED attack...")
        sim.simulate_targeted_attack(files)
    
    elif choice == '4':
        print("\n[DONE] Test files created. No attack executed.")
    
    else:
        print("\n[ERROR] Invalid choice")
        return
    
    print("\n" + "="*50)
    print("Simulation complete!")
    print("="*50)
    print("\nCheck GuardianX logs to see if the attack was detected.")
    print(f"Test directory: {sim.test_dir}")


if __name__ == '__main__':
    main()
