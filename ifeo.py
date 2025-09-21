#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IFEO 演示脚本（教育用途）
仅用于展示 Windows Image File Execution Options 机制，
请勿用于任何恶意用途！
"""

from __future__ import annotations
import argparse
import ctypes
import os
import random
import sys
import winreg
from pathlib import Path
from typing import List, Tuple

try:
    import win32com.client  # pywin32
except ImportError:
    print("❌ 请先安装 pywin32:  pip install pywin32")
    sys.exit(1)

# ---------- 工具 ----------
def is_admin() -> bool:
    """检查当前进程是否拥有管理员令牌"""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run_as_admin() -> bool:
    """自动提权，成功返回 True，失败或用户拒绝返回 False"""
    if is_admin():
        return True
    try:
        hinstance = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        return hinstance > 32
    except Exception:
        return False
    finally:
        # 提权成功后旧进程直接退出
        sys.exit(0)


def get_desktop_path() -> Path:
    return Path(os.path.expanduser("~/Desktop"))


def expand_choice(choice_str: str, max_val: int) -> List[int]:
    """
    解析用户输入的序号字符串
    支持 1,3,5-7,9 写法
    """
    indices: set[int] = set()
    for part in choice_str.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = map(int, part.split("-", 1))
                indices.update(range(start, end + 1))
            except ValueError:
                continue
        else:
            if part.isdigit():
                indices.add(int(part))
    return sorted(i for i in indices if 1 <= i <= max_val)


# ---------- 核心逻辑 ----------
ShortcutInfo = Tuple[int, str, str]  # (序号, 显示名, 目标exe)


def scan_shortcuts(keywords: List[str]) -> List[ShortcutInfo]:
    desktop = get_desktop_path()
    shortcuts = desktop.glob("*.lnk")
    results: List[ShortcutInfo] = []
    shell = win32com.client.Dispatch("WScript.Shell")

    for lnk in shortcuts:
        try:
            sc = shell.CreateShortcut(str(lnk))
            target = Path(sc.TargetPath)
            if not target or not target.is_file() or target.suffix.lower() != ".exe":
                continue
            name = lnk.stem
            if any(kw.lower() in name.lower() for kw in keywords):
                results.append((len(results) + 1, name, str(target)))
        except Exception as e:
            print(f"⚠️  读取 {lnk} 失败: {e}")
    return results


def set_ifeo_debugger(target_exe: str, debugger_path: str) -> bool:
    """写入 IFEO，成功返回 True"""
    try:
        key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        exe_name = Path(target_exe).name
        with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, f"{key_path}\\{exe_name}") as key:
            winreg.SetValueEx(key, "Debugger", 0, winreg.REG_SZ, str(debugger_path))
            print(f"✅ 演示：已为 {exe_name} 设置 Debugger → {debugger_path}")
            return True
    except PermissionError:
        print("❌ 权限不足，请以管理员运行。")
    except Exception as e:
        print(f"❌ 设置 IFEO 失败: {e}")
    return False


def restore_ifeo(target_exe: str) -> bool:
    """删除指定程序的 Debugger 值，恢复默认"""
    try:
        key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        exe_name = Path(target_exe).name
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{key_path}\\{exe_name}", 0,
                            winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, "Debugger")
            print(f"🔄 已清除 {exe_name} 的 Debugger")
            return True
    except FileNotFoundError:
        print(f"ℹ️  {exe_name} 无 Debugger 值，无需清理")
        return True
    except Exception as e:
        print(f"❌ 清理 {exe_name} 失败: {e}")
        return False


# ---------- 主流程 ----------
def main() -> None:
    parser = argparse.ArgumentParser(description="IFEO 教育演示脚本")
    parser.add_argument("--restore", action="store_true", help="一键还原本次演示写入的 Debugger")
    args = parser.parse_args()

    if args.restore:
        if not is_admin():
            print("❌ 还原操作需要管理员权限，请右键“以管理员运行”")
            sys.exit(1)
        desktop = get_desktop_path()
        for lnk in desktop.glob("*.lnk"):
            try:
                sc = win32com.client.Dispatch("WScript.Shell").CreateShortcut(str(lnk))
                target = Path(sc.TargetPath)
                if target and target.is_file() and target.suffix.lower() == ".exe":
                    restore_ifeo(str(target))
            except Exception:
                continue
        print("\n✅ 还原完成！")
        return

    # 正常演示流程
    if not run_as_admin():
        print("❌ 无法获取管理员权限，脚本终止")
        sys.exit(1)

    keywords = ["抖音", "浏览器", "360", "chrome", "edge", "firefox", "sogou", "猎豹"]
    print("🔍 正在扫描桌面快捷方式...")
    shortcuts = scan_shortcuts(keywords)
    if not shortcuts:
        print("❌ 未找到含关键词的快捷方式")
        return

    print("\n🎯 找到以下快捷方式：")
    for idx, name, target in shortcuts:
        print(f"  [{idx}] {name}  →  {Path(target).name}")

    all_targets = [target for _, _, target in shortcuts]
    calc = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "calc.exe"

    while True:
        raw = input("\n📌 请选择要演示劫持的序号（如 1,3-5）\n>>> ").strip()
        selected_indices = expand_choice(raw, len(shortcuts))
        if selected_indices:
            break
        print("⚠️  输入有误，请重新选择")

    selected = [(name, target) for idx, name, target in shortcuts if idx in selected_indices]
    print(f"\n🔄 将为 {len(selected)} 个程序设置 IFEO 演示项...")

    for name, target in selected:
        # 随机挑一个“替身”
        candidates = [t for t in all_targets if t != target]
        fake_target = Path(random.choice(candidates)) if candidates else calc
        print(f"➡️  {name}  → 将指向 {fake_target.name}（演示）")
        set_ifeo_debugger(target, str(fake_target))

    print("\n✅ 演示操作完成！所有修改仅为教学展示。")
    print("📌 一键还原命令：")
    print(f"   {Path(sys.argv[0]).name} --restore")


if __name__ == "__main__":
    main()