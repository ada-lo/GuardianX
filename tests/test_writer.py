# test_writer.py
import time
import os

TARGET_DIR = "test_folder"
os.makedirs(TARGET_DIR, exist_ok=True)

print("Writer started. PID:", os.getpid())

for i in range(20):
    with open(os.path.join(TARGET_DIR, f"file_{i}.txt"), "w") as f:
        f.write("malicious content " * 1000)
    time.sleep(0.2)  # Slow it down so we can catch it

print("Done writing. Sleeping...")
time.sleep(10)  # Keep process alive
