# file_monitor.py
import time
import psutil
import watchdog
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

TARGET_DIR = "test_folder"

class Handler(FileSystemEventHandler):
    def on_modified(self, event):
        print("File modified:", event.src_path)

        # Find python process running test_writer
        for proc in psutil.process_iter(['pid', 'cmdline']):
            try:
                if proc.info['cmdline'] and "test_writer.py" in " ".join(proc.info['cmdline']):
                    print("Found writer PID:", proc.pid)
                    proc.suspend()
                    print("Suspended.")
            except:
                pass

observer = Observer()
observer.schedule(Handler(), TARGET_DIR, recursive=True)
observer.start()

print("Watching folder...")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    observer.stop()

observer.join()
