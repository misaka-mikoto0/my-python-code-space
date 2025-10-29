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
import re

# ----------------------------------------------------------
# Constants
# ----------------------------------------------------------
KEYWORDS_URL = "https://stone.meiko.cyou/kw.php"
CACHE_FILE = "keywords_cache.json"
CACHE_TTL_SECONDS = 2 * 60 * 60  # 2 hours

BLOCKED_MONITOR_NAMES = {
    "resmon.exe",
    "perfmon.exe",
    "procexp.exe",
    "processhacker.exe",
}

BLACKLISTED_PROCESSES = {
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
    "opera_beta.exe", "opera_gx.exe", "vivaldi.exe", "qqbrowser.exe",
    "360se.exe", "sogouexplorer.exe", "ucbrowser.exe", "liebao.exe",
    "maxthon.exe", "tor.exe", "waterfox.exe", "chromium.exe",
    "edge_beta.exe", "edgecanary.exe", "safari.exe",
}

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
# Load keywords with caching
# ----------------------------------------------------------
def load_keywords():
    def load_from_cache():
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def save_to_cache(keywords):
        try:
            with open(CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(keywords, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"[cache] Failed to save cache: {e}")

    # Step 1: Check if cache exists and is fresh
    if os.path.exists(CACHE_FILE):
        mtime = os.path.getmtime(CACHE_FILE)
        age = time.time() - mtime
        if age < CACHE_TTL_SECONDS:
            print("[keywords] Using cached keywords (fresh within 2h).")
            return load_from_cache()
        else:
            print("[keywords] Cache expired, trying to refresh from network...")
    else:
        print("[keywords] No cache found, fetching from network...")

    # Step 2: Try fetching from network
    try:
        with urllib.request.urlopen(KEYWORDS_URL, timeout=5) as resp:
            keywords = json.loads(resp.read().decode('utf-8'))
            save_to_cache(keywords)
            print(f"[keywords] Successfully fetched {len(keywords)} keywords.")
            return keywords
    except Exception as e:
        print(f"[keywords] Network fetch failed: {e}")
        # Step 3: fallback to cache if available
        cached = load_from_cache()
        if cached:
            print("[keywords] Falling back to cached keywords.")
            return cached
        else:
            print("[keywords] No cached keywords available, using empty list.")
            return []


KEYWORDS = load_keywords()


# ----------------------------------------------------------
# WM_QUERYENDSESSION handler
# ----------------------------------------------------------
def wnd_proc(hwnd, msg, wparam, lparam):
    if msg == win32con.WM_QUERYENDSESSION:
        return True
    return win32gui.DefWindowProc(hwnd, msg, wparam, lparam)


# ----------------------------------------------------------
# Check admin
# ----------------------------------------------------------
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


# ----------------------------------------------------------
# Suspend process threads
# ----------------------------------------------------------
def suspend_process(pid):
    try:
        process = psutil.Process(pid)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False
    try:
        for t in process.threads():
            h = OpenThread(THREAD_SUSPEND_RESUME, False, t.id)
            if h:
                SuspendThread(h)
                CloseHandle(h)
        return True
    except Exception:
        return False


# ----------------------------------------------------------
# Get visible windows
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
# Kill blocked tools
# ----------------------------------------------------------
def terminate_blocking_tools():
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            name = (proc.info.get('name') or "").lower()
            if name in BLOCKED_MONITOR_NAMES:
                psutil.Process(proc.info['pid']).kill()
        except Exception:
            continue


# ----------------------------------------------------------
# Main loop
# ----------------------------------------------------------
def main():
    if not is_admin():
        print("Warning: run as administrator for full functionality.")

    print("Starting monitor...")

    while True:
        try:
            now = datetime.datetime.now()
            # 大杀戒：周六 17:30~18:20
            if now.weekday() == 5 and ((now.hour == 17 and now.minute >= 30) or (now.hour == 18 and now.minute < 20)):
                for proc in psutil.process_iter(['pid', 'name']):
                    name = (proc.info.get('name') or "").lower()
                    if name in BLACKLISTED_PROCESSES:
                        try:
                            print(f"[KILL] 大杀戒时间杀死 {name} (PID {proc.pid})")
                            psutil.Process(proc.pid).kill()
                        except Exception:
                            pass
                time.sleep(10)
                continue

            terminate_blocking_tools()

            windows = get_window_titles()
            for title, pid, hwnd in windows:
                try:
                    proc = psutil.Process(pid)
                    pname = proc.name().lower()
                    if pname not in BLACKLISTED_PROCESSES:
                        continue  # 只检测黑名单
                    # 匹配关键词（含Unicode范围）
                    for kw in KEYWORDS:
                        try:
                            if re.search(kw, title):
                                print(f"[DETECT] '{title}' (PID {pid}) matched '{kw}' in {pname}")
                                suspend_process(pid)
                                win32gui.ShowWindow(hwnd, win32con.SW_MINIMIZE)
                                break
                        except re.error:
                            continue
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            time.sleep(3)
        except KeyboardInterrupt:
            print("\nUser stopped monitoring.")
            break
        except Exception as e:
            print(f"[main] error: {e}")
            time.sleep(2)


if __name__ == "__main__":
    main()