# GuardianX - Ransomware Early-Warning System

<img src="https://img.shields.io/badge/Status-Experimental-orange" /> <img src="https://img.shields.io/badge/Platform-Windows-blue" /> <img src="https://img.shields.io/badge/Python-3.8%2B-green" />

**"Set it and Forget it" Ransomware Protection**

GuardianX catches ransomware attacks in the "micro-damage" phase (first 3-5 files) before mass destruction occurs.

---

## 🎯 The Problem

Traditional antivirus solutions suffer from two critical flaws:

1. **Too Slow**: They wait for mass file destruction before raising alerts
2. **Too Annoying**: They constantly ask users for permission, leading to "alert fatigue"

## 💡 The Solution

GuardianX uses a **Trinity Architecture** combining three detection methods:

### 1. **Slow-Burn Detector** (Time-Based)
- Tracks file modification patterns using a sliding window
- Catches stealthy ransomware that encrypts 1 file every 5 minutes
- Threshold: 50 files modified within 1 hour

### 2. **Magic-Byte Sentry** (Content-Based)
- Validates file integrity by checking magic bytes (file headers)
- Detects when a `.pdf` file no longer starts with `%PDF`
- Supports: PDF, JPG, PNG, DOCX, XLSX, ZIP, EXE, and more

### 3. **Idle-State Hyper-Visor** (Context-Based) ⭐ **Novel Feature**
- Goes into "paranoid mode" when user is AFK (>5 minutes)
- Relaxed when user is active to minimize false positives
- Catches attacks that occur during sleep, gaming, or coffee breaks

---

## 🏗️ Architecture

```
File Event → Get Modifying Process → Run Detectors → Decision Tree → Action
                                         ↓
                        ┌────────────────┴────────────────┐
                        │                                 │
                   Known Threat?                    Whitelisted?
                        │                                 │
                       YES → KILL                        YES → ALLOW
                        │                                 │
                        NO                                NO
                        ↓                                 ↓
                 File Corrupted?                    Has GUI Window?
                        │                                 │
                       YES ──────────┐                   YES → SUSPEND
                        │            │                    │
                        NO           │                    NO
                        ↓            ↓                    ↓
                 High File Rate?   User Idle?        SUSPEND/KILL
                        │            │
                       YES ────────→ YES → KILL
                        │            │
                        NO          NO → SUSPEND
                        ↓
                     ALLOW
```

### Decision Tree Logic

1. **Whitelisted** (Microsoft, Google, etc.) → **ALLOW**
2. **Known Ransomware Signature** → **KILL** immediately
3. **Has Visible Window** (user is aware) → **SUSPEND** if suspicious
4. **File Corruption Detected**:
   - User **Active** → **SUSPEND** (likely false positive)
   - User **Idle** → **KILL** (high confidence threat)
5. **High File Modification Rate**:
   - User **Active** → **SUSPEND**
   - User **Idle** → **KILL**

### Actions

| Action | Description | Can Undo? |
|--------|-------------|-----------|
| **ALLOW** | Normal behavior, logged only | N/A |
| **SUSPEND** | Freeze process, allow user review | ✅ Yes |
| **KILL** | Terminate immediately | ❌ No |

---

## 🚀 Installation

### Prerequisites

1. **Windows 11** (or Windows 10)
2. **Python 3.8+**
3. **VirtualBox** (for testing)

### Setup

1. **Download Windows 11 ISO**:
   ```
   https://www.microsoft.com/software-download/windows11
   ```

2. **Create VM in VirtualBox**:
   - RAM: 4GB minimum
   - Disk: 50GB
   - **IMPORTANT**: Take snapshot "Clean Install" before testing!

3. **Install Python** in VM:
   ```bash
   # Download from python.org
   # Check "Add to PATH" during installation
   ```

4. **Install GuardianX**:
   ```bash
   cd C:\Users\YourName\Desktop
   git clone <your-repo-url> GuardianX
   cd GuardianX
   
   pip install -r requirements.txt
   ```

---

## 🎮 Usage

### Basic Protection

```bash
# Run with default settings (monitors Documents, Desktop, Downloads)
python main.py
```

**Output:**
```
    ╔═══════════════════════════════════════════╗
    ║         GuardianX v1.0                    ║
    ║   Ransomware Early-Warning System         ║
    ╚═══════════════════════════════════════════╝

[GuardianX] Initializing defense systems...
[GuardianX] Monitoring 3 directories
  - C:\Users\YourName\Documents
  - C:\Users\YourName\Desktop
  - C:\Users\YourName\Downloads

[GuardianX] Starting file system monitoring...
[GuardianX] User idle timeout: 300s
[GuardianX] Slow-burn threshold: 50 files/3600s
[GuardianX] Press Ctrl+C to stop
```

### Testing

#### 1. Create Test Environment

```bash
python test_attack.py
```

**Menu:**
```
1. Fast Attack (0.1s delay) - Tests rapid detection
2. Slow Attack (5s delay) - Tests sliding window
3. Targeted Attack (PDF/DOCX only) - Tests selective encryption
4. Create test files only (no attack)
```

#### 2. Recommended Test Sequence

**Terminal 1:**
```bash
python main.py
```

**Terminal 2:**
```bash
# Wait 10 seconds for GuardianX to initialize
python test_attack.py
# Choose option 1 (Fast Attack)
```

**Expected Output (Terminal 1):**
```
============================================================
[THREAT NEUTRALIZED] PID 1234
File: C:\Users\...\Desktop\GuardianX_Test\document_003.pdf
Reason: File corruption detected while user is IDLE
============================================================
```

### Undo False Positives

If GuardianX suspends a legitimate process:

```bash
# List suspended processes
python -c "from process_manager import ProcessManager; pm = ProcessManager(); print(pm.get_suspended_processes())"

# Resume a process
python -c "from process_manager import ProcessManager; pm = ProcessManager(); pm.resume_process(1234)"
```

---

## 📊 Logs

All activity is logged to `%TEMP%\GuardianX\logs\`:

| File | Contents |
|------|----------|
| `threats.json` | Killed processes (confirmed threats) |
| `suspended.json` | Suspended processes (under review) |
| `activity.json` | All file events (for forensics) |

**Example log entry:**
```json
{
  "timestamp": "2026-02-10T14:23:45",
  "action": "KILL",
  "pid": 5432,
  "reason": "KNOWN RANSOMWARE: wannacry.exe"
}
```

---

## ⚙️ Configuration

Edit `config.py` to customize thresholds:

```python
# Detection sensitivity
SLOW_BURN_THRESHOLD = 50  # Files per window
SLOW_BURN_WINDOW = 3600   # 1 hour

# Idle detection
IDLE_TIMEOUT = 300  # 5 minutes
IDLE_PARANOIA_MULTIPLIER = 0.3  # Reduce threshold to 30% when idle

# File corruption detection
HIGH_ENTROPY_THRESHOLD = 7.5  # Shannon entropy (0-8 scale)
```

### Adding Custom Whitelists

```python
WHITELISTED_PROCESSES = [
    'explorer.exe',
    'YourBackupSoftware.exe',  # Add your trusted apps
]

TRUSTED_SIGNERS = [
    'Microsoft Corporation',
    'Your Company Name',  # Add your digital certificate
]
```

---

## 🧪 Testing Checklist

Before deploying to production:

- [ ] VM snapshot created ("Clean Install")
- [ ] GuardianX detects fast attack (<2 seconds)
- [ ] GuardianX detects slow attack (within threshold)
- [ ] No false positives on normal file operations
- [ ] Suspended processes can be resumed
- [ ] Logs are being written correctly
- [ ] Ransomware note creation is detected

---

## 🔬 Known Limitations

1. **Process Attribution**: 
   - May not catch attacks that use kernel drivers
   - Relies on processes having file handles open

2. **Whitelist Bypass**:
   - Malware signed with stolen certificates can evade detection
   - Solution: Use additional heuristics (entropy, file rate)

3. **Resource Intensity**:
   - Watching large directories can consume CPU
   - Optimize by excluding temp folders

4. **Windows-Only**:
   - Current implementation uses Windows APIs
   - Linux/macOS ports would need platform-specific code

---

## 🛡️ Academic Foundation

This project implements concepts from:

- **ShieldFS** (2016): Ransomware detection via I/O patterns
- **CryptoDrop** (2016): Self-healing ransomware detection
- **UNVEIL** (2016): Early-stage ransomware detection

**Novel Contribution**: Idle-state context awareness (not present in prior work)

---

## 📝 Future Enhancements

- [ ] Machine learning classifier for unknown threats
- [ ] Network activity monitoring (C2 communication)
- [ ] Automatic file backups before suspension
- [ ] GUI dashboard for non-technical users
- [ ] Cross-platform support (Linux, macOS)
- [ ] Integration with Windows Defender
- [ ] Cloud-based threat intelligence feed

---

## ⚠️ Legal Disclaimer

**This software is for educational and research purposes only.**

- Only test in isolated virtual machines
- Do not deploy on production systems without extensive testing
- The authors are not responsible for any damage or data loss
- Comply with all applicable computer security laws in your jurisdiction

---

## 📄 License

MIT License - See LICENSE file

---

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new features
4. Submit a pull request

---

## 📧 Contact

For research collaboration or questions:
- GitHub Issues: [your-repo-url]
- Email: [your-email]

---

**Built with ❤️ for a safer digital world**
