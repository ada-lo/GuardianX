# GuardianX Quick Start Guide

## ⚡ 5-Minute Setup (VM Testing)

### Step 1: Prepare Your VM
1. Download Windows 11 ISO from Microsoft
2. Create VM in VirtualBox:
   - RAM: 4GB
   - Disk: 50GB
   - **Take Snapshot: "Clean Install"**

### Step 2: Install Python
```bash
# In VM, download Python 3.11+ from python.org
# Check "Add to PATH" during installation
```

### Step 3: Install GuardianX
```bash
# Open PowerShell in VM
cd C:\Users\YourName\Desktop
mkdir GuardianX
cd GuardianX

# Copy all project files to this directory

# Install dependencies
pip install -r requirements.txt
```

### Step 4: First Test Run

**Terminal 1 - Start Protection:**
```bash
python main.py
```

**Terminal 2 - Run Attack Simulation:**
```bash
# Wait 10 seconds for GuardianX to initialize
python test_attack.py
# Select option 1 (Fast Attack)
```

### Expected Output

GuardianX should detect and kill the malicious process within 2 seconds:

```
============================================================
[THREAT NEUTRALIZED] PID 5432
File: C:\Users\...\Desktop\GuardianX_Test\document_003.pdf
Reason: File corruption detected while user is IDLE
============================================================
```

### Step 5: Check Logs

```bash
python guardianx.py logs threats 10
```

---

## 🎯 Common Use Cases

### Monitor Specific Directories Only

Edit `main.py` and add:

```python
# At the end of the file, replace:
guardian = GuardianX()

# With:
guardian = GuardianX(watch_paths=[
    'C:\\Users\\YourName\\Documents',
    'D:\\ImportantFiles',
])
```

### Adjust Sensitivity

Edit `config.py`:

```python
# More aggressive (catches attacks faster, more false positives)
SLOW_BURN_THRESHOLD = 30  # Down from 50
IDLE_PARANOIA_MULTIPLIER = 0.2  # Down from 0.3

# Less aggressive (fewer false positives, slower detection)
SLOW_BURN_THRESHOLD = 100  # Up from 50
IDLE_PARANOIA_MULTIPLIER = 0.5  # Up from 0.3
```

### Resume False Positive

```bash
# Check what's suspended
python guardianx.py status

# Resume process 1234
python guardianx.py undo 1234
```

---

## 🧪 Testing Scenarios

### Test 1: Fast Ransomware (WannaCry-style)
```bash
python test_attack.py
# Choose: 1. Fast Attack
# Expected: Detection in <2 seconds
```

### Test 2: Slow Ransomware (Stealthy)
```bash
python test_attack.py
# Choose: 2. Slow Attack
# Expected: Detection after threshold is exceeded
```

### Test 3: Targeted Attack
```bash
python test_attack.py
# Choose: 3. Targeted Attack
# Expected: Detection when PDF/DOCX corruption is found
```

### Test 4: False Positive Handling
```bash
# In a new window, create a legitimate file operation
# Example: Open Word, save a document
# GuardianX should ALLOW (Microsoft signed) or SUSPEND (if unsigned)
```

---

## 🔍 Troubleshooting

### "Access Denied" when killing process
**Solution**: Run PowerShell as Administrator
```bash
# Right-click PowerShell → Run as Administrator
python main.py
```

### Too many false positives
**Solution**: Add your software to whitelist in `config.py`:
```python
WHITELISTED_PROCESSES = [
    'explorer.exe',
    'YourApp.exe',  # Add here
]
```

### Not detecting test attacks
**Solution**: Check if user is truly idle
```bash
# In main.py, you can force idle state for testing:
# In GuardianX.__init__(), add:
self.idle_monitor.last_activity_time = 0  # Force idle
```

### Logs not appearing
**Solution**: Check log directory exists
```bash
python -c "from config import LOG_DIR; print(LOG_DIR); LOG_DIR.mkdir(parents=True, exist_ok=True)"
```

---

## 📊 Performance Benchmarks

Expected performance on a modern system:

| Metric | Value |
|--------|-------|
| Detection Latency | <2 seconds |
| CPU Usage (Idle) | <1% |
| CPU Usage (Active) | 2-5% |
| RAM Usage | ~50MB |
| False Positive Rate | <0.1% (with proper whitelisting) |

---

## ⚠️ Production Deployment Checklist

Before deploying on a real system:

- [ ] Test for at least 7 days in VM
- [ ] Whitelist all trusted applications
- [ ] Configure backup system (GuardianX can't recover encrypted files)
- [ ] Set up log rotation (logs can grow large)
- [ ] Document undo procedure for team
- [ ] Test network drive scenarios
- [ ] Verify no conflicts with existing antivirus
- [ ] Create runbook for incident response

---

## 🎓 Learning Resources

### Understanding the Code

1. Start with `config.py` - See all thresholds and settings
2. Read `detectors.py` - Understand the 3 detection engines
3. Study `process_manager.py` - Learn the decision tree
4. Review `main.py` - See how everything ties together

### Key Functions to Understand

```python
# How threat assessment works
GuardianX._assess_threat()

# How the decision tree works
ProcessManager.decide_action()

# How slow-burn detection works
SlowBurnDetector.check_threshold()

# How magic bytes work
MagicByteSentry.check_file_integrity()
```

---

## 📈 Next Steps

After you have GuardianX working:

1. **Collect Data**: Run for a week, analyze logs
2. **Tune Thresholds**: Adjust based on false positive rate
3. **Add ML**: Train a classifier on your file access patterns
4. **Contribute**: Share improvements with the community
5. **Publish**: Write a blog post or research paper

---

**Ready to build? Let's go! 🚀**
