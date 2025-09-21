import ctypes
import ctypes.wintypes
import win32gui
import win32process
import win32con
import psutil
import time
import json
import urllib.request
import os
import sys
import datetime

# ----------------------------------------------------------
# Load keywords from network; fallback to empty list on failure
# ----------------------------------------------------------
KEYWORDS_URL = "https://stone.meiko.cyou/kw.php"
try:
    with urllib.request.urlopen(KEYWORDS_URL, timeout=5) as resp:
        KEYWORDS = json.loads(resp.read().decode('utf-8'))
except Exception as e:
    print("Failed to fetch keywords, using empty list:", e)
    KEYWORDS = []

# ----------------------------------------------------------
# Blacklist: only these processes are checked for keywords
# ----------------------------------------------------------
BLACKLISTED_PROCESSES = {
    # Chrome
    "chrome.exe", "chrome_beta.exe", "chrome_dev.exe", "chrome_canary.exe",
    # Edge
    "msedge.exe", "msedge_beta.exe", "msedge_dev.exe", "msedge_canary.exe",
    # Firefox
    "firefox.exe", "firefox_beta.exe", "firefox_dev.exe", "firefox_nightly.exe",
    # Opera
    "opera.exe", "opera_beta.exe", "opera_gx.exe", "opera_gx_beta.exe",
    # Brave
    "brave.exe", "brave_beta.exe", "brave_dev.exe", "brave_nightly.exe",
    # Safari (legacy Windows build)
    "safari.exe",
}

# ----------------------------------------------------------
# Blocked monitoring tools (not Task Manager!)
# ----------------------------------------------------------
BLOCKED_MONITOR_NAMES = {
    "resmon.exe",
    "perfmon.exe",
    "procexp.exe",
    "processhacker.exe",
}

# ----------------------------------------------------------
# Windows thread suspend constants and function prototypes
# ----------------------------------------------------------
THREAD_SUSPEND_RESUME = 0x0002

OpenThread = ctypes.windll.kernel32.OpenThread
OpenThread.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD]
OpenThread.restype = ctypes.wintypes.HANDLE

SuspendThread = ctypes.windll.kernel32.SuspendThread
SuspendThread.argtypes = [ctypes.wintypes.HANDLE]
SuspendThread.restype = ctypes.wintypes.DWORD

CloseHandle = ctypes.windll.kernel32.CloseHandle
CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
CloseHandle.restype = ctypes.wintypes.BOOL

# ----------------------------------------------------------
# Helper: check for admin
# ----------------------------------------------------------
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

# ----------------------------------------------------------
# Suspend all threads of a given PID
# ----------------------------------------------------------
def suspend_process(pid):
    try:
        process = psutil.Process(pid)
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        print(f"[suspend_process] Can't access PID {pid}: {e}")
        return False

    try:
        threads = process.threads()
        success_any = False
        for thread in threads:
            h_thread = OpenThread(THREAD_SUSPEND_RESUME, False, ctypes.wintypes.DWORD(thread.id))
            if h_thread:
                try:
                    prev_count = SuspendThread(h_thread)
                    if prev_count != 0xFFFFFFFF:
                        success_any = True
                finally:
                    CloseHandle(h_thread)
        return success_any
    except Exception as e:
        print(f"[suspend_process] Exception while suspending {pid}: {e}")
        return False

# ----------------------------------------------------------
# Get visible window titles and their owning PIDs
# ----------------------------------------------------------
def get_window_titles():
    windows = []
    def callback(hwnd, _):
        if win32gui.IsWindowVisible(hwnd):
            title = win32gui.GetWindowText(hwnd)
            if title:
                _, pid = win32process.GetWindowThreadProcessId(hwnd)
                windows.append((title, pid, hwnd))
        return True
    win32gui.EnumWindows(callback, None)
    return windows

# ----------------------------------------------------------
# Kill blocked monitoring tools
# ----------------------------------------------------------
def terminate_blocking_tools():
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            name = (proc.info.get('name') or "").lower()
            if name in BLOCKED_MONITOR_NAMES:
                pid = proc.info['pid']
                if pid == os.getpid():
                    continue
                psutil.Process(pid).kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

# ----------------------------------------------------------
# Check if current time is in the Sunday 17:30–18:20 block window
# ----------------------------------------------------------
def in_block_time():
    now = datetime.datetime.now()
    return (now.weekday() == 6 and  # Sunday (Mon=0 ... Sun=6)
            ((now.hour == 17 and now.minute >= 30) or
             (now.hour == 18 and now.minute < 20)))

# ----------------------------------------------------------
# Main monitoring loop
# ----------------------------------------------------------
def main():
    if not is_admin():
        print("Warning: not running as admin. Some actions may fail.")

    print("Starting monitor... (Ctrl+C to stop)")
    check_interval = 3.0
    last_log_time = {}
    LOG_COOLDOWN = 5.0

    try:
        while True:
            terminate_blocking_tools()

            # 大杀戒：周日 17:30–18:20
            if in_block_time():
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        name = (proc.info.get('name') or "").lower()
                        if name in BLACKLISTED_PROCESSES and proc.pid != os.getpid():
                            print(f"[block_time] Killing {name} (PID {proc.pid}) due to schedule")
                            psutil.Process(proc.pid).kill()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

            # 其他时间：只检测黑名单进程 + 关键词
            else:
                windows = get_window_titles()
                for title, pid, hwnd in windows:
                    try:
                        pname = psutil.Process(pid).name().lower()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                    if pname not in BLACKLISTED_PROCESSES:
                        continue  # 非黑名单进程忽略

                    if any((kw and kw in title) for kw in KEYWORDS):
                        now = time.time()
                        if last_log_time.get((pid, title), 0) + LOG_COOLDOWN < now:
                            print(f"[monitor] Sensitive window: '{title}' ({pname}, PID {pid})")
                            last_log_time[(pid, title)] = now

                        if suspend_process(pid):
                            try:
                                win32gui.ShowWindow(hwnd, win32con.SW_MINIMIZE)
                            except Exception:
                                pass

            time.sleep(check_interval)

    except KeyboardInterrupt:
        print("\nStopped by user.")

if __name__ == "__main__":
    main()