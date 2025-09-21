#!/usr/bin/env python3
"""
hls_full_featured.py

Full-featured HLS streaming + web UI service.

Features:
- screen + camera -> HLS (m3u8 + .ts) via ffmpeg
- auto-detect camera device on Windows/macOS/Linux (best-effort)
- serve UI on PORT (default 1108) with hls.js player
- snapshot API, record start/stop, download recent minutes as zip
- auto-restart ffmpeg with exponential backoff
- retention policy: keep last N hours of files (default 3 hours)
- optional basic auth via ENV AUTH_USER / AUTH_PASS
- logs to console, health/status endpoint

Dependencies:
  pip install aiohttp aiohttp_basicauth psutil
Requires system ffmpeg in PATH.

Usage examples:
  python hls_full_featured.py --port 1108
  python hls_full_featured.py --cam-device '-f dshow -i video="USB Camera"' --keep-hours 3
"""
from __future__ import annotations
import argparse
import asyncio
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Tuple, Optional, Dict
import json
import uuid
import zipfile

from aiohttp import web
# optional small basic auth helper; if not available we implement simple decorator
try:
    from aiohttp_basicauth import BasicAuthMiddleware
    _have_aiohttp_basicauth = True
except Exception:
    _have_aiohttp_basicauth = False

# optional psutil for disk usage
try:
    import psutil
    _have_psutil = True
except Exception:
    _have_psutil = False

# --------------- Config & paths ---------------
DEFAULT_PORT = 1108
BASE = Path(__file__).resolve().parent
HLS_DIR = BASE / "hls"
SCREEN_DIR = HLS_DIR / "screen"
CAM_DIR = HLS_DIR / "cam"
SNAP_DIR = BASE / "snapshots"
REC_DIR = BASE / "recordings"
TMP_DIR = BASE / "tmp"

# defaults
FPS = 15
HLS_TIME = 2
HLS_LIST_SIZE = 6
HLS_FLAGS = "delete_segments+append_list"
VIDEO_CODEC = "libx264"
PRESET = "veryfast"
KEEP_HOURS_DEFAULT = 3
MAX_RESTART_BACKOFF = 60  # seconds

# runtime state
FFPROCS = {}
REC_JOBS = {}  # job_id -> {proc, path, target}
AUTH_USER = os.environ.get("AUTH_USER")
AUTH_PASS = os.environ.get("AUTH_PASS")

# ---------------- util helpers ----------------
def now_ts() -> str:
    return datetime.utcnow().strftime("%Y%m%d-%H%M%S")

def run_cmd_capture(cmd: List[str], timeout=30) -> Tuple[int, str]:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout)
        return p.returncode, p.stdout
    except Exception as e:
        return -1, f"exception: {e}"

def list_dir_sorted(path: Path):
    try:
        return sorted([p for p in path.iterdir()], key=lambda p: p.stat().st_mtime)
    except Exception:
        return []

# ------------- device detection --------------
def find_windows_dshow_devices() -> List[str]:
    cmd = ["ffmpeg", "-list_devices", "true", "-f", "dshow", "-i", "dummy"]
    rc, out = run_cmd_capture(cmd)
    devices = []
    for m in re.finditer(r'"([^"]+)"\s*\(.*video', out, flags=re.IGNORECASE):
        devices.append(m.group(1))
    if not devices:
        for m in re.finditer(r'\]\s*"([^"]+)"', out):
            devices.append(m.group(1))
    return list(dict.fromkeys(devices))

def find_macos_avfoundation_devices() -> List[str]:
    cmd = ["ffmpeg", "-f", "avfoundation", "-list_devices", "true", "-i", ""]
    rc, out = run_cmd_capture(cmd)
    devices = []
    for m in re.finditer(r'\[\d+\]\s+(.+)', out):
        devices.append(m.group(1).strip())
    return devices

def find_linux_video_devices() -> List[str]:
    devs = []
    for p in sorted(Path("/dev").glob("video*")):
        if p.exists():
            devs.append(str(p))
    return devs

def detect_camera_input() -> Tuple[Optional[str], List[str]]:
    sysname = platform.system()
    if sysname == "Windows":
        devs = find_windows_dshow_devices()
        if devs:
            # use first candidate
            return f'-f dshow -i video="{devs[0]}"', devs
        return None, []
    elif sysname == "Darwin":
        devs = find_macos_avfoundation_devices()
        if devs:
            return '-f avfoundation -framerate 25 -i 0', devs
        return None, []
    else:
        devs = find_linux_video_devices()
        if devs:
            return f'-f v4l2 -framerate 25 -i {devs[0]}', devs
        return None, []

# -------------- ffmpeg command builders --------------
def build_screen_cmd(screen_input_override: Optional[str], fps_override: Optional[int]=None, bitrate: Optional[str]=None) -> str:
    fps = fps_override or FPS
    out = str((SCREEN_DIR / "index.m3u8").resolve())
    if screen_input_override:
        input_part = screen_input_override
    else:
        sysname = platform.system()
        if sysname == "Windows":
            input_part = f"-f gdigrab -framerate {fps} -i desktop"
        elif sysname == "Darwin":
            input_part = f"-f avfoundation -framerate {fps} -i 1"
        else:
            display = os.environ.get("DISPLAY", ":0.0")
            input_part = f"-f x11grab -framerate {fps} -i {display}"
    vb = f"-b:v {bitrate}" if bitrate else ""
    cmd = f"ffmpeg {input_part} -c:v {VIDEO_CODEC} {vb} -preset {PRESET} -g {fps*2} -sc_threshold 0 -f hls -hls_time {HLS_TIME} -hls_list_size {HLS_LIST_SIZE} -hls_flags {HLS_FLAGS} {out}"
    return cmd

def build_cam_cmd(cam_input_override: Optional[str], bitrate: Optional[str]=None) -> str:
    out = str((CAM_DIR / "index.m3u8").resolve())
    if cam_input_override:
        input_part = cam_input_override
    else:
        cand, candidates = detect_camera_input()
        if cand:
            input_part = cand
        else:
            # fallback
            sysname = platform.system()
            if sysname == "Windows":
                input_part = '-f dshow -i video="Integrated Camera"'
            elif sysname == "Darwin":
                input_part = '-f avfoundation -framerate 25 -i 0'
            else:
                input_part = '-f v4l2 -framerate 25 -i /dev/video0'
    vb = f"-b:v {bitrate}" if bitrate else ""
    cmd = f"ffmpeg {input_part} -c:v {VIDEO_CODEC} {vb} -preset {PRESET} -g 50 -sc_threshold 0 -f hls -hls_time {HLS_TIME} -hls_list_size {HLS_LIST_SIZE} -hls_flags {HLS_FLAGS} {out}"
    return cmd

# ------------- process manager with restart --------------
class FFWorker:
    def __init__(self, name: str, cmd: str):
        self.name = name
        self.cmd = cmd
        self.proc: Optional[asyncio.subprocess.Process] = None
        self.backoff = 1

    async def start(self):
        await self._ensure_dir()
        await self._spawn()

    async def _ensure_dir(self):
        # ensure output dir exists
        out = Path(self.cmd.strip().split()[-1])
        out.parent.mkdir(parents=True, exist_ok=True)

    async def _spawn(self):
        print(f"[{self.name}] spawning ffmpeg: {self.cmd}")
        self.proc = await asyncio.create_subprocess_shell(self.cmd,
                                                          stdout=asyncio.subprocess.PIPE,
                                                          stderr=asyncio.subprocess.PIPE)
        asyncio.create_task(self._drain(self.proc))
        asyncio.create_task(self._monitor(self.proc))

    async def _drain(self, proc):
        try:
            while True:
                line = await proc.stderr.readline()
                if not line:
                    break
                print(f"[{self.name}] {line.decode(errors='ignore').rstrip()}")
        except Exception as e:
            print(f"[{self.name}] drain err: {e}")

    async def _monitor(self, proc):
        rc = await proc.wait()
        print(f"[{self.name}] ffmpeg exited with {rc}")
        # restart with backoff
        await asyncio.sleep(min(self.backoff, MAX_RESTART_BACKOFF))
        self.backoff = min(self.backoff*2 if self.backoff else 1, MAX_RESTART_BACKOFF)
        print(f"[{self.name}] restarting (backoff={self.backoff})")
        await self._spawn()

    async def stop(self):
        if self.proc and self.proc.returncode is None:
            try:
                self.proc.terminate()
                await asyncio.wait_for(self.proc.wait(), timeout=5)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass

# ------------- snapshot / record helpers --------------
async def take_snapshot(target: str) -> Optional[Path]:
    """Use ffmpeg to capture a single frame from live stream input. Returns Path of saved image or None."""
    ts = now_ts()
    SNAP_DIR.mkdir(parents=True, exist_ok=True)
    out_path = SNAP_DIR / f"{target}-{ts}.jpg"
    # try to read from the HLS index or from device directly
    if target == "cam":
        cand, _ = detect_camera_input()
        src = cand or '-f v4l2 -i /dev/video0'
    else:
        # screen
        sysname = platform.system()
        if sysname == "Windows":
            src = f'-f gdigrab -i desktop'
        elif sysname == "Darwin":
            src = f'-f avfoundation -i 1'
        else:
            display = os.environ.get("DISPLAY", ":0.0")
            src = f'-f x11grab -i {display}'
    # build ffmpeg snapshot command: grab single frame (-frames:v 1)
    cmd = f"ffmpeg {src} -frames:v 1 -q:v 2 {str(out_path)} -y"
    print("[snapshot] cmd:", cmd)
    # run blocking subprocess to create snapshot quickly
    try:
        p = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=15)
        if p.returncode == 0 and out_path.exists():
            return out_path
        else:
            print("[snapshot] ffmpeg failed:", p.returncode, p.stdout)
            return None
    except Exception as e:
        print("[snapshot] exception:", e)
        return None

def start_record_task(target: str, duration: int) -> Tuple[str, Optional[Path]]:
    """
    Start an ffmpeg recording job reading from the HLS (or device) to an mp4 file.
    If duration > 0, ffmpeg will stop automatically after duration seconds.
    Returns (job_id, path)
    """
    ts = now_ts()
    REC_DIR.mkdir(parents=True, exist_ok=True)
    out_path = REC_DIR / f"{target}-{ts}.mp4"
    # use device/input similar to snapshot
    if target == "cam":
        cand, _ = detect_camera_input()
        src = cand or '-f v4l2 -i /dev/video0'
    else:
        sysname = platform.system()
        if sysname == "Windows":
            src = f'-f gdigrab -framerate {FPS} -i desktop'
        elif sysname == "Darwin":
            src = f'-f avfoundation -framerate {FPS} -i 1'
        else:
            display = os.environ.get("DISPLAY", ":0.0")
            src = f'-f x11grab -framerate {FPS} -i {display}'
    dur_opt = f"-t {duration}" if duration and duration>0 else ""
    # write reasonably encoded mp4
    cmd = f"ffmpeg {src} -c:v {VIDEO_CODEC} -preset {PRESET} {dur_opt} {str(out_path)} -y"
    print("[record] cmd:", cmd)
    # spawn background process
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    job_id = str(uuid.uuid4())
    REC_JOBS[job_id] = {"proc": proc, "path": out_path, "target": target}
    return job_id, out_path

def stop_record_task(job_id: str) -> bool:
    job = REC_JOBS.get(job_id)
    if not job:
        return False
    proc = job["proc"]
    if proc and proc.poll() is None:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
    return True

# ------------- retention / cleanup task --------------
async def retention_loop(keep_hours: int, sleep_seconds: int = 60):
    """
    Periodically remove files older than keep_hours in HLS, recordings, snapshots, tmp.
    """
    keep_delta = timedelta(hours=keep_hours)
    while True:
        try:
            cutoff = datetime.utcnow() - keep_delta
            # HLS segments (.ts) and playlists
            for d in (SCREEN_DIR, CAM_DIR):
                if not d.exists(): continue
                for p in d.glob("*.ts"):
                    if datetime.utcfromtimestamp(p.stat().st_mtime) < cutoff:
                        try:
                            p.unlink()
                        except Exception as e:
                            print("[retention] rm ts failed", p, e)
                # optionally prune old m3u8 files (but keep latest)
                for m in d.glob("*.m3u8"):
                    if datetime.utcfromtimestamp(m.stat().st_mtime) < cutoff:
                        try:
                            m.unlink()
                        except Exception:
                            pass
            # recordings
            for p in REC_DIR.glob("*.mp4"):
                if datetime.utcfromtimestamp(p.stat().st_mtime) < cutoff:
                    try:
                        p.unlink()
                    except Exception:
                        pass
            # snapshots
            for p in SNAP_DIR.glob("*.jpg"):
                if datetime.utcfromtimestamp(p.stat().st_mtime) < cutoff:
                    try:
                        p.unlink()
                    except Exception:
                        pass
            # tmp
            for p in TMP_DIR.glob("*"):
                if datetime.utcfromtimestamp(p.stat().st_mtime) < cutoff:
                    try:
                        if p.is_dir():
                            shutil.rmtree(p)
                        else:
                            p.unlink()
                    except Exception:
                        pass
        except Exception as e:
            print("[retention] exception", e)
        await asyncio.sleep(sleep_seconds)

# ------------- Web UI and API routes --------------
INDEX_HTML = """<!doctype html>
<html lang="zh">
<head><meta charset="utf-8"><title>家庭监控 - HLS</title>
<script src="https://cdn.jsdelivr.net/npm/hls.js@latest"></script>
<style>
body{font-family:Arial; background:#071021; color:#e6eef8; margin:0; padding:12px;}
header{display:flex;align-items:center;gap:12px}
h1{margin:0;font-size:20px}
.container{display:flex;flex-wrap:wrap;gap:12px;margin-top:12px}
.card{background:#081423;padding:12px;border-radius:8px;box-shadow:0 4px 14px rgba(0,0,0,0.5);width:48%}
video{width:100%;border-radius:6px;background:black}
.controls{margin-top:8px;display:flex;gap:8px;align-items:center;justify-content:space-between}
.btn{padding:6px 10px;border-radius:6px;border:none;background:#0ea5a4;color:#012;cursor:pointer}
.small{font-size:12px;color:#9fb0c8}
@media (max-width:900px){ .card{width:100%} }
</style>
</head>
<body>
<header><h1>家庭监控（HLS） - 1108</h1><div class="small">快照 / 录像 / 下载 / 状态 面板</div></header>
<div class="container">
  <div class="card">
    <h3>屏幕</h3>
    <video id="screen" controls autoplay muted playsinline></video>
    <div class="controls">
      <div><button class="btn" onclick="snapshot('screen')">快照</button>
              <button class="btn" onclick="startRecord('screen')">开始录像(无限)</button>
              <button class="btn" onclick="downloadRecent('screen')">下载最近30分钟</button></div>
      <div id="screenStatus" class="small">状态: 连接中...</div>
    </div>
  </div>
  <div class="card">
    <h3>摄像头</h3>
    <video id="cam" controls autoplay muted playsinline></video>
    <div class="controls">
      <div><button class="btn" onclick="snapshot('cam')">快照</button>
          <button class="btn" onclick="startRecord('cam')">开始录像(无限)</button>
          <button class="btn" onclick="downloadRecent('cam')">下载最近30分钟</button></div>
      <div id="camStatus" class="small">状态: 连接中...</div>
    </div>
  </div>
</div>

<script>
function attach(id, url, statusId){
  const v = document.getElementById(id), s = document.getElementById(statusId);
  if (Hls.isSupported()){
    const hls = new Hls();
    hls.loadSource(url);
    hls.attachMedia(v);
    hls.on(Hls.Events.MANIFEST_PARSED, ()=>{ s.textContent='播放中'; v.play().catch(()=>{}); });
    hls.on(Hls.Events.ERROR, (ev,data)=>{ s.textContent='HLS 错误: '+data.type; if(data.fatal){ setTimeout(()=>location.reload(),2000);} });
  } else if (v.canPlayType('application/vnd.apple.mpegurl')){
    v.src = url;
    v.addEventListener('loadedmetadata', ()=>{ s.textContent='播放中'; v.play().catch(()=>{}); });
  } else {
    s.textContent='浏览器不支持 HLS';
  }
}
attach('screen','/screen/index.m3u8','screenStatus');
attach('cam','/cam/index.m3u8','camStatus');

async function snapshot(target){
  const res = await fetch('/api/snapshot?target='+target);
  if(res.ok){
    const j = await res.json();
    if(j.url) window.open(j.url, '_blank');
    else alert('快照失败: '+(j.error||'unknown'));
  } else alert('请求失败');
}

async function startRecord(target){
  const res = await fetch('/api/record/start?target='+target+'&duration=0');
  if(res.ok){
    const j = await res.json();
    if(j.job_id) alert('开始录像，job_id='+j.job_id+'；可调用 /api/record/stop?job_id=ID 停止');
    else alert('启动失败');
  } else alert('启动失败');
}

async function downloadRecent(target){
  const res = await fetch('/api/download?target='+target+'&minutes=30');
  if(res.ok){
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = target+'-recent.zip';
    document.body.appendChild(a); a.click(); a.remove();
  } else {
    alert('下载失败');
  }
}
</script>
</body></html>
"""

# --------------- API handlers ----------------
async def handle_index(request):
    return web.Response(text=INDEX_HTML, content_type="text/html")

async def handle_snapshot(request):
    target = request.query.get("target", "cam")
    if target not in ("cam", "screen"):
        return web.json_response({"error":"invalid target"}, status=400)
    p = await asyncio.get_event_loop().run_in_executor(None, lambda: asyncio.run(take_snapshot(target)) if False else None)
    # can't call asyncio.run inside running loop; call blocking snapshot helper via thread
    snap = await asyncio.get_event_loop().run_in_executor(None, lambda: asyncio.run if False else None)
    # simpler: call blocking function in thread wrapper
    def _snap_block():
        return asyncio.get_event_loop()  # placeholder
    # Real call:
    snap_path = await asyncio.get_event_loop().run_in_executor(None, lambda: take_snapshot_blocking(target))
    if snap_path:
        rel = "/" + str(snap_path.relative_to(BASE)).replace("\\","/")
        return web.json_response({"url": rel})
    else:
        return web.json_response({"error":"snapshot failed"}, status=500)

def take_snapshot_blocking(target: str) -> Optional[Path]:
    # wrapper to call the real snapshot helper (which used subprocess.run)
    # reuse same code as async version but blocking
    ts = now_ts()
    SNAP_DIR.mkdir(parents=True, exist_ok=True)
    out_path = SNAP_DIR / f"{target}-{ts}.jpg"
    if target == "cam":
        cand, _ = detect_camera_input()
        src = cand or '-f v4l2 -i /dev/video0'
    else:
        sysname = platform.system()
        if sysname == "Windows":
            src = f'-f gdigrab -i desktop'
        elif sysname == "Darwin":
            src = f'-f avfoundation -i 1'
        else:
            display = os.environ.get("DISPLAY", ":0.0")
            src = f'-f x11grab -i {display}'
    cmd = f"ffmpeg {src} -frames:v 1 -q:v 2 {str(out_path)} -y"
    try:
        p = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=15)
        if p.returncode == 0 and out_path.exists():
            return out_path
        else:
            print("[snapshot-block] failed:", p.returncode, p.stdout)
            return None
    except Exception as e:
        print("[snapshot-block] ex", e)
        return None

async def handle_record_start(request):
    target = request.query.get("target", "cam")
    duration = int(request.query.get("duration","0"))
    if target not in ("cam","screen"):
        return web.json_response({"error":"invalid target"}, status=400)
    job_id, path = await asyncio.get_event_loop().run_in_executor(None, lambda: start_record_task(target, duration))
    return web.json_response({"job_id": job_id, "path": "/" + str(path.relative_to(BASE)).replace("\\","/")})

async def handle_record_stop(request):
    job_id = request.query.get("job_id")
    if not job_id:
        return web.json_response({"error":"missing job_id"}, status=400)
    ok = await asyncio.get_event_loop().run_in_executor(None, lambda: stop_record_task(job_id))
    return web.json_response({"stopped": ok})

async def handle_download(request):
    target = request.query.get("target", "cam")
    minutes = int(request.query.get("minutes","30"))
    if target not in ("cam","screen"):
        return web.json_response({"error":"invalid target"}, status=400)
    # find .ts in target dir newer than cutoff
    cutoff = time.time() - minutes*60
    d = SCREEN_DIR if target=="screen" else CAM_DIR
    if not d.exists():
        return web.json_response({"error":"no data"}, status=404)
    segs = [p for p in d.glob("*.ts") if p.stat().st_mtime >= cutoff]
    if not segs:
        return web.json_response({"error":"no recent segments"}, status=404)
    # create zip in tmp
    TMP_DIR.mkdir(parents=True, exist_ok=True)
    zname = TMP_DIR / f"{target}-recent-{now_ts()}.zip"
    try:
        with zipfile.ZipFile(zname, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for s in segs:
                zf.write(s, arcname=s.name)
    except Exception as e:
        return web.json_response({"error":"zip failed","detail":str(e)}, status=500)
    # stream file back
    return web.FileResponse(path=zname)

async def handle_status(request):
    # basic info
    info = {"time": int(time.time()), "ffmpeg": {}, "devices": {}, "disk": {}}
    for k,v in FFPROCS.items():
        info["ffmpeg"][k] = {"running": v.proc and v.proc.returncode is None}
    cand, candidates = detect_camera_input()
    info["devices"]["camera_candidates"] = candidates
    # disk usage
    try:
        if _have_psutil:
            du = psutil.disk_usage(str(BASE))
            info["disk"]["total"] = du.total
            info["disk"]["used"] = du.used
            info["disk"]["free"] = du.free
        else:
            # fallback approximate using shutil
            st = shutil.disk_usage(str(BASE))
            info["disk"]["total"] = st.total
            info["disk"]["used"] = st.used
            info["disk"]["free"] = st.free
    except Exception as e:
        info["disk"]["error"] = str(e)
    # sizes of hls, recordings, snaps
    def folder_size(p: Path):
        s = 0
        if p.exists():
            for f in p.rglob("*"):
                if f.is_file():
                    try: s += f.stat().st_size
                    except: pass
        return s
    info["sizes"] = {
        "hls_screen_bytes": folder_size(SCREEN_DIR),
        "hls_cam_bytes": folder_size(CAM_DIR),
        "recordings_bytes": folder_size(REC_DIR),
        "snapshots_bytes": folder_size(SNAP_DIR),
    }
    return web.json_response(info)

# ------------- auth middleware (simple) --------------
def basic_auth_middleware(user: Optional[str], pw: Optional[str]):
    @web.middleware
    async def mw(request, handler):
        if not user or not pw:
            return await handler(request)
        auth = request.headers.get("Authorization")
        from base64 import b64decode
        if not auth or not auth.startswith("Basic "):
            return web.Response(status=401, headers={"WWW-Authenticate":"Basic realm=Login"})
        try:
            creds = b64decode(auth.split(" ",1)[1]).decode()
            u,p = creds.split(":",1)
            if u == user and p == pw:
                return await handler(request)
        except Exception:
            pass
        return web.Response(status=401, headers={"WWW-Authenticate":"Basic realm=Login"})
    return mw

# --------------- main runner ----------------
async def start_all(args):
    # ensure dirs
    for p in (HLS_DIR, SCREEN_DIR, CAM_DIR, SNAP_DIR, REC_DIR, TMP_DIR):
        p.mkdir(parents=True, exist_ok=True)

    # prepare ffmpeg commands
    screen_cmd = build_screen_cmd(args.screen_input, fps_override=args.fps, bitrate=args.screen_bitrate)
    cam_cmd = build_cam_cmd(args.cam_device, bitrate=args.cam_bitrate)

    print("[info] screen cmd:", screen_cmd)
    print("[info] cam cmd:   ", cam_cmd)

    # create workers
    screen_w = FFWorker("screen", screen_cmd)
    cam_w = FFWorker("cam", cam_cmd)
    FFPROCS["screen"] = screen_w
    FFPROCS["cam"] = cam_w

    # start workers
    await asyncio.gather(screen_w.start(), cam_w.start())

    # start retention loop
    asyncio.create_task(retention_loop(args.keep_hours))

    # start web server
    app = web.Application(middlewares=[basic_auth_middleware(AUTH_USER, AUTH_PASS)])
    app.router.add_get("/", handle_index)
    app.router.add_get("/api/snapshot", handle_snapshot)
    app.router.add_get("/api/record/start", handle_record_start)
    app.router.add_get("/api/record/stop", handle_record_stop)
    app.router.add_get("/api/download", handle_download)
    app.router.add_get("/api/status", handle_status)
    # static serve HLS dirs and media
    app.router.add_static("/screen", str(SCREEN_DIR), show_index=True)
    app.router.add_static("/cam", str(CAM_DIR), show_index=True)
    app.router.add_static("/snapshots", str(SNAP_DIR), show_index=True)
    app.router.add_static("/recordings", str(REC_DIR), show_index=True)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", args.port)
    await site.start()
    print(f"[http] running on port {args.port} (open /)")

    # keep running until signal
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for s in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(s, lambda s=s: stop.set())
        except NotImplementedError:
            pass
    await stop.wait()
    print("[shutdown] stopping workers...")
    await screen_w.stop()
    await cam_w.stop()
    # stop recordings
    for job in list(REC_JOBS.keys()):
        stop_record_task(job)
    await asyncio.sleep(0.5)

def parse_args():
    p = argparse.ArgumentParser(description="Full featured HLS streaming server")
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--cam-device", type=str, default=None, help='ffmpeg input string for camera (overrides detection)')
    p.add_argument("--screen-input", type=str, default=None, help='ffmpeg input string for screen (overrides)')
    p.add_argument("--screen-bitrate", type=str, default="1500k", help="e.g. 1500k")
    p.add_argument("--cam-bitrate", type=str, default="1000k", help="e.g. 1000k")
    p.add_argument("--fps", type=int, default=FPS)
    p.add_argument("--keep-hours", type=int, default=KEEP_HOURS_DEFAULT)
    p.add_argument("--clean", action="store_true")
    return p.parse_args()

def estimate_disk_usage_examples():
    """
    Return dict with example calculations for combined bitrate scenarios for 3 hours retention.
    We'll compute step-by-step with decimal MB (1 byte = 8 bits).
    """
    scenarios = {
        "screen 1.5 Mbps + cam 1.0 Mbps": 2.5,
        "screen 1.0 Mbps + cam 0.5 Mbps": 1.5,
        "screen 3.0 Mbps + cam 2.0 Mbps": 5.0,
        "screen 0.5 Mbps + cam 0.5 Mbps": 1.0
    }
    out = {}
    for k,total_mbps in scenarios.items():
        # 1) total megabits per second = total_mbps
        # 2) megabytes per second = total_mbps / 8
        mb_per_s = total_mbps / 8.0
        # 3) megabytes per hour = mb_per_s * 3600
        mb_per_hour = mb_per_s * 3600.0
        # 4) for 3 hours:
        three_h_mb = mb_per_hour * 3.0
        # express also in GB (decimal) and GiB (1024-based)
        three_h_gb = three_h_mb / 1000.0
        three_h_gib = three_h_mb / 1024.0
        out[k] = {
            "total_mbps": total_mbps,
            "MB_per_s": mb_per_s,
            "MB_per_hour": mb_per_hour,
            "3h_MB": three_h_mb,
            "3h_GB_decimal": three_h_gb,
            "3h_GiB": three_h_gib
        }
    return out

if __name__ == "__main__":
    args = parse_args()
    if args.clean and HLS_DIR.exists():
        shutil.rmtree(HLS_DIR)
    try:
        # print disk usage estimates
        print("[estimate] storage estimates for 3-hour retention (examples):")
        est = estimate_disk_usage_examples()
        for k,v in est.items():
            print(f"  {k}: total_mbps={v['total_mbps']} -> {v['MB_per_s']:.6f} MB/s -> {v['MB_per_hour']:.1f} MB/hour -> 3h={v['3h_MB']:.1f} MB ({v['3h_GB_decimal']:.3f} GB decimal / {v['3h_GiB']:.3f} GiB)")
        asyncio.run(start_all(args))
    except KeyboardInterrupt:
        print("[main] keyboard interrupt, exiting.")
    except Exception as e:
        print("[main] exception:", e)