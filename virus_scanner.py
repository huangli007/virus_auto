#!/usr/bin/env python3
"""
VirusTotal 批量扫描工具 v3.0
选择文件夹 → 过滤病毒载体文件 → 上传 VirusTotal 扫描 → 生成 HTML 报告
v3.0: 项目分类 + 本地缓存去重 + 跳过已扫描文件

功能：
  - 支持多 API Key 池，配额耗尽自动切换
  - 支持 Key 文档（每行一个 key），自动加载
  - 严格的速率限制 & 日/月配额管控
  - 项目文件夹管理：每次扫描创建独立项目目录
  - SHA-256 本地缓存：已扫描文件跳过上传，节省配额

依赖: pip install requests

用法:
  python virus_scanner.py                              # 交互模式
  python virus_scanner.py -k YOUR_KEY                  # 临时 key
  python virus_scanner.py -k YOUR_KEY --save-key       # 添加 key 到池
  python virus_scanner.py --add-key                    # 交互添加 key
  python virus_scanner.py --add-key YOUR_KEY            # 命令行添加 key
  python virus_scanner.py --key-file keys.txt           # 从文件加载 key 池
  python virus_scanner.py --list-keys                   # 查看 key 池状态
  python virus_scanner.py -f "D:\\Downloads"             # 指定文件夹
  python virus_scanner.py -f "D:\\Downloads" --project-name MyProject  # 自定义项目名
  python virus_scanner.py -f "D:\\Downloads" --no-cache # 强制重扫
  python virus_scanner.py --cache-stats                 # 查看缓存统计
  python virus_scanner.py --clear-cache                 # 清空缓存
  python virus_scanner.py --report-filter scan_data.json   # 筛选报毒报告
  python virus_scanner.py --err scan_data.json              # 文本报毒测试报告
  python virus_scanner.py --gen-emails <结果文件或目录>     # 申诉邮件
  python virus_scanner.py --excel scan_data.json             # 导出报毒 Excel
"""

import os
import sys
import json
import time
import hashlib
import argparse
import threading
from datetime import datetime
from pathlib import Path

# ===== ANSI 终端颜色 =====
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

try:
    import requests
except ImportError:
    print("缺少 requests 模块，正在安装...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
    import requests

# ========== 配置 ==========
CONFIG_DIR = Path(__file__).parent
CONFIG_FILE = CONFIG_DIR / "virus_scanner_config.json"
SCAN_CACHE_FILE = CONFIG_DIR / "scan_cache.json"     # v3.0: 本地扫描缓存（SHA-256 索引）
DECLARED_CACHE_FILE = CONFIG_DIR / "declared_cache.json"  # v3.0: 已申诉记录（SHA256|引擎 索引）
PROJECTS_DIR = CONFIG_DIR / "projects"                # v3.0: 项目目录

VT_API_BASE = "https://www.virustotal.com/api/v3"

# ===== VirusTotal 公共 API 配额（官方限制）=====
RATE_LIMIT_PER_MINUTE = 4             # 每分钟 4 次查询
RATE_LIMIT_INTERVAL = 60.0 / RATE_LIMIT_PER_MINUTE  # 每次请求间隔 15 秒
DAILY_QUOTA = 500                     # 每日 500 次查询（每个 key）
MONTHLY_QUOTA = 155_000               # 每月 15.5 万次查询（每个 key）
MAX_FILE_SIZE = 32 * 1024 * 1024      # 32MB，超过需用 upload_url
EST_CALLS_PER_FILE = 1                # v2.0: 仅查报告扣配额，上传和轮询免费
# v2.0: 渐进式轮询间隔
PROGRESSIVE_INTERVALS = [10, 15, 20, 30, 45, 60, 60, 60]

# 病毒常见载体文件扩展名（扫描目标）
SCAN_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".msi", ".scr", ".cpl", ".pif",
    ".com", ".drv", ".ocx", ".bin", ".apk", ".ipa", ".app", ".deb",
    ".rpm", ".dmg", ".iso", ".img", ".vhd", ".vhdx",
    ".pdf", ".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm",
    ".ppt", ".pptx", ".pptm", ".rtf", ".mdb", ".accdb",
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
    ".cab", ".arj", ".lzh", ".ace", ".jar", ".war", ".ear",
    ".htm", ".html", ".hta", ".chm", ".eml", ".msg", ".swf",
    ".lnk", ".url", ".torrent", ".pyc", ".pyo", ".class",
}

# 显式排除的文本类扩展名
EXCLUDE_EXTENSIONS = {
    ".txt", ".md", ".csv", ".log", ".json", ".xml", ".yaml", ".yml",
    ".ini", ".cfg", ".conf", ".properties", ".env", ".gitignore",
    ".editorconfig", ".toml", ".lock", ".nfo", ".readme",
}

# 扫描优先级：数字越小越优先
FILE_PRIORITY = {
    ".exe": 0, ".dll": 1, ".bin": 2, ".sys": 3, ".drv": 4,
    ".bat": 5, ".cmd": 5, ".ps1": 5, ".vbs": 5, ".vbe": 5,
    ".msi": 6, ".scr": 6, ".cpl": 6, ".pif": 6, ".com": 6,
    ".ocx": 7, ".apk": 7, ".ipa": 7, ".app": 7,
    ".js": 8, ".jse": 8, ".wsf": 8, ".wsh": 8,
}


# ============================================================
#  快捷键控制：Ctrl+Z 暂停 / Ctrl+T 继续
# ============================================================

class PauseController:
    """全局快捷键：Ctrl+Z 暂停扫描，Ctrl+T 继续。"""

    def __init__(self):
        self._paused = threading.Event()
        self._paused.set()  # 初始为"未暂停"状态（set = 不阻塞）
        self._listener = None
        self._active = False

    def start(self):
        if self._active:
            return
        try:
            from pynput import keyboard
        except ImportError:
            print("[提示] pynput 未安装，快捷键不可用。pip install pynput")
            return

        self._active = True
        self._ctrl_pressed = False

        def on_press(key):
            try:
                if key == keyboard.Key.ctrl_l or key == keyboard.Key.ctrl_r:
                    self._ctrl_pressed = True
                elif self._ctrl_pressed and hasattr(key, 'char'):
                    if key.char == 'z':
                        self._paused.clear()  # clear = 阻塞 = 暂停
                        print("\n⏸  [Ctrl+Z] 扫描已暂停，按 Ctrl+T 继续...", flush=True)
                    elif key.char == 't':
                        self._paused.set()    # set = 不阻塞 = 继续
                        print("\n▶  [Ctrl+T] 扫描已继续", flush=True)
            except Exception:
                pass

        def on_release(key):
            if key == keyboard.Key.ctrl_l or key == keyboard.Key.ctrl_r:
                self._ctrl_pressed = False

        self._listener = keyboard.Listener(on_press=on_press, on_release=on_release)
        self._listener.daemon = True
        self._listener.start()
        print("[快捷键] Ctrl+Z 暂停 | Ctrl+T 继续")

    def wait_if_paused(self):
        """在扫描循环中调用，若暂停则阻塞直到恢复。"""
        self._paused.wait()

    def stop(self):
        self._active = False
        if self._listener:
            self._listener.stop()


# ============================================================
#  API Key 管理器 —— 多 Key 池 + 配额追踪 + 自动切换
# ============================================================

class ApiKeyManager:
    """管理多个 VirusTotal API Key，追踪各 key 配额，支持自动切换。"""

    def __init__(self):
        self.keys = []          # [{"key": str, "label": str, "key_id": str}]
        self.active_idx = 0
        self.quotas = {}        # {key_id: {"daily": {"date","count"}, "monthly": {"month","count"}}}
        self._load()

    # ----- 持久化 -----

    def _load(self):
        """从配置文件加载 keys 和配额"""
        if not CONFIG_FILE.exists():
            return
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return

        # 兼容旧版单 key 格式
        if "api_key" in data and data["api_key"]:
            self._add_key_internal(data["api_key"], "default", save=False)

        # 新版多 key 格式
        for entry in data.get("api_keys", []):
            self._add_key_internal(entry["key"], entry.get("label", ""), save=False)

        # 活跃索引
        self.active_idx = data.get("active_key_index", 0)
        if self.active_idx >= len(self.keys):
            self.active_idx = 0

        # 配额数据
        self.quotas = data.get("quota", {})

    def _save(self):
        """保存到配置文件"""
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        data = {
            "api_keys": [{"key": k["key"], "label": k["label"]} for k in self.keys],
            "active_key_index": self.active_idx,
            "quota": self.quotas,
        }
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    # ----- Key 管理 -----

    @staticmethod
    def _make_key_id(key):
        """为 key 生成唯一标识（不暴露原始 key）"""
        return hashlib.md5(key.encode()).hexdigest()[:12]

    def _add_key_internal(self, key, label="", save=True):
        """内部添加 key，去重"""
        key_id = self._make_key_id(key)
        for k in self.keys:
            if k["key_id"] == key_id:
                return  # 去重
        if not label:
            label = f"key-{len(self.keys) + 1}"
        self.keys.append({"key": key, "label": label, "key_id": key_id})
        if save:
            self._save()

    def add_key(self, key, label="", save=True):
        """添加一个 API Key"""
        if not key or len(key) < 20:
            return False, "Key 格式无效（长度应 >= 20 字符）"
        self._add_key_internal(key, label, save=save)
        return True, f"已添加 Key [{label or 'unnamed'}]"

    def load_keys_from_file(self, file_path):
        """从文本文件加载 Key（每行一个 key，忽略空行和 # 注释）"""
        path = Path(file_path)
        if not path.is_file():
            return False, f"文件不存在: {file_path}"
        added = 0
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                ok, _ = self.add_key(line, label=f"file-{added + 1}", save=False)
                if ok:
                    added += 1
        if added:
            self._save()
        return True, f"从文件加载了 {added} 个 Key"

    def list_keys(self):
        """列出所有 key 及其状态"""
        if not self.keys:
            return "Key 池为空。"
        lines = []
        now = datetime.now()
        today = now.strftime("%Y-%m-%d")
        for i, k in enumerate(self.keys):
            marker = " ← 当前" if i == self.active_idx else ""
            q = self._get_quota(k["key_id"])
            daily_r = DAILY_QUOTA - q["daily"]["count"]
            monthly_r = MONTHLY_QUOTA - q["monthly"]["count"]
            d_flag = " ⚠耗尽" if daily_r <= 0 else ""
            m_flag = " ⚠耗尽" if monthly_r <= 0 else ""
            lines.append(
                f"  [{i}] {k['label']}  "
                f"日:{daily_r}/{DAILY_QUOTA}{d_flag}  "
                f"月:{monthly_r}/{MONTHLY_QUOTA}{m_flag}{marker}"
            )
        return "\n".join(lines)

    # ----- 当前 Key -----

    def current_key(self):
        """返回当前活跃的 API Key，无可用 key 返回 None"""
        if not self.keys:
            return None
        if self.active_idx >= len(self.keys):
            self.active_idx = 0
        return self.keys[self.active_idx]["key"]

    def current_label(self):
        if not self.keys or self.active_idx >= len(self.keys):
            return "none"
        return self.keys[self.active_idx]["label"]

    # ----- 配额追踪 -----

    def _get_quota(self, key_id):
        """获取某个 key 的配额数据（自动跨天/跨月归零）"""
        now = datetime.now()
        today = now.strftime("%Y-%m-%d")
        this_month = now.strftime("%Y-%m")

        if key_id not in self.quotas:
            self.quotas[key_id] = {
                "daily": {"date": today, "count": 0},
                "monthly": {"month": this_month, "count": 0},
            }

        q = self.quotas[key_id]
        if q["daily"]["date"] != today:
            q["daily"] = {"date": today, "count": 0}
        if q["monthly"]["month"] != this_month:
            q["monthly"] = {"month": this_month, "count": 0}
        return q

    def record_call(self):
        """记录当前 key 的一次 API 调用"""
        if not self.keys or self.active_idx >= len(self.keys):
            return
        key_id = self.keys[self.active_idx]["key_id"]
        q = self._get_quota(key_id)
        q["daily"]["count"] += 1
        q["monthly"]["count"] += 1
        self._save()

    def check_quota(self):
        """
        检查当前 key 配额。
        返回 (ok: bool, message: str)。
        如果当前 key 已耗尽，自动尝试切换到下一个有剩余配额的 key。
        """
        if not self.keys:
            return False, "Key 池为空，请先添加 API Key。"

        # 尝试当前 key
        key_id = self.keys[self.active_idx]["key_id"]
        q = self._get_quota(key_id)

        if q["daily"]["count"] < DAILY_QUOTA and q["monthly"]["count"] < MONTHLY_QUOTA:
            return True, ""

        # 当前 key 耗尽 → 尝试切换
        label = self.keys[self.active_idx]["label"]
        reason = "日配额" if q["daily"]["count"] >= DAILY_QUOTA else "月配额"
        switched = self._switch_to_next_available()

        if switched:
            new_label = self.keys[self.active_idx]["label"]
            return True, f"[{label}] {reason}已耗尽，已自动切换到 [{new_label}]"

        return False, f"所有 Key 的{reason}均已耗尽。请添加新的 API Key。"

    def _switch_to_next_available(self):
        """切换到下一个有剩余日配额的 key。成功返回 True。"""
        start = self.active_idx
        for offset in range(1, len(self.keys) + 1):
            candidate = (start + offset) % len(self.keys)
            key_id = self.keys[candidate]["key_id"]
            q = self._get_quota(key_id)
            if q["daily"]["count"] < DAILY_QUOTA and q["monthly"]["count"] < MONTHLY_QUOTA:
                self.active_idx = candidate
                self._save()
                return True
        return False

    def prompt_new_key(self):
        """交互式输入新 Key，添加到池并切换"""
        print("\n" + "=" * 60)
        print("  所有 Key 配额已耗尽！")
        print("  请提供新的 VirusTotal API Key。")
        print("  获取方式：https://www.virustotal.com → 注册/登录 → API key")
        print("=" * 60)
        new_key = input("  新 API Key: ").strip()
        if new_key:
            self._add_key_internal(new_key, label=f"manual-{len(self.keys) + 1}", save=True)
            self.active_idx = len(self.keys) - 1
            self._save()
            print(f"  已切换到新 Key [{self.keys[self.active_idx]['label']}]")
            return True
        return False

    def quota_status(self):
        """返回当前 key 的配额状态字符串"""
        if not self.keys:
            return "Key 池为空"
        key_id = self.keys[self.active_idx]["key_id"]
        q = self._get_quota(key_id)
        label = self.keys[self.active_idx]["label"]
        daily_r = DAILY_QUOTA - q["daily"]["count"]
        monthly_r = MONTHLY_QUOTA - q["monthly"]["count"]
        return (f"[{label}] 今日: {q['daily']['count']}/{DAILY_QUOTA}  "
                f"本月: {q['monthly']['count']}/{MONTHLY_QUOTA}  "
                f"速率: {RATE_LIMIT_PER_MINUTE}次/分钟")

    def daily_remaining(self):
        if not self.keys:
            return 0
        key_id = self.keys[self.active_idx]["key_id"]
        q = self._get_quota(key_id)
        return DAILY_QUOTA - q["daily"]["count"]

    def monthly_remaining(self):
        if not self.keys:
            return 0
        key_id = self.keys[self.active_idx]["key_id"]
        q = self._get_quota(key_id)
        return MONTHLY_QUOTA - q["monthly"]["count"]


# ========== 工具函数 ==========

def select_folder():
    """选择文件夹：优先使用 tkinter GUI，回退到命令行输入"""
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        folder = filedialog.askdirectory(title="选择要扫描的文件夹")
        root.destroy()
        if folder:
            return Path(folder)
    except Exception:
        pass

    while True:
        path = input("\n请输入要扫描的文件夹路径（或拖拽文件夹到此处）: ").strip().strip('"').strip("'")
        p = Path(path)
        if p.is_dir():
            return p
        print(f"  '{path}' 不是有效目录，请重新输入")


def should_scan(file_path: Path):
    """判断文件是否应该被扫描"""
    ext = file_path.suffix.lower()
    if ext in EXCLUDE_EXTENSIONS:
        return False
    if ext in SCAN_EXTENSIONS:
        return True
    if not ext and file_path.stat().st_size > 1024:
        return True
    return False


# ========== v3.0: 本地扫描缓存 ==========

def load_scan_cache():
    """加载扫描缓存 {sha256: {filepath, filename, last_scanned, project, malicious, suspicious}}"""
    if SCAN_CACHE_FILE.is_file():
        try:
            with open(SCAN_CACHE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data.get("files", {}) if isinstance(data, dict) else {}
        except (json.JSONDecodeError, IOError):
            return {}
    return {}

def save_scan_cache(cache_data):
    """保存扫描缓存"""
    payload = {
        "version": "1.0",
        "total": len(cache_data),
        "files": cache_data,
    }
    with open(SCAN_CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

def cache_lookup(sha256):
    """查缓存，命中返回条目 dict，否则 None。缓存不过期（按内容永久有效）。"""
    cache = load_scan_cache()
    return cache.get(sha256)

def cache_put(sha256, filepath, filename, project_dir, malicious, suspicious):
    """写入一条扫描缓存"""
    cache = load_scan_cache()
    cache[sha256] = {
        "filepath": filepath,
        "filename": filename,
        "last_scanned": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "project": project_dir,
        "malicious": malicious,
        "suspicious": suspicious,
    }
    save_scan_cache(cache)

def clear_scan_cache():
    """清空缓存"""
    if SCAN_CACHE_FILE.exists():
        SCAN_CACHE_FILE.unlink()
    return True

def cache_stats():
    """返回缓存统计信息"""
    cache = load_scan_cache()
    if not cache:
        return "缓存为空。"
    last = max((e.get("last_scanned", "") for e in cache.values()), default="")
    return (f"缓存条目: {len(cache)} 个\n"
            f"最近扫描: {last}")


# ========== v3.0: 已申诉记录缓存（SHA256+引擎维度去重）==========
def load_declared_cache():
    """加载已申诉记录 {sha256|engine_name: {file_path, declared_at, project}}"""
    if DECLARED_CACHE_FILE.is_file():
        try:
            with open(DECLARED_CACHE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data.get("declared", {}) if isinstance(data, dict) else {}
        except (json.JSONDecodeError, IOError):
            return {}
    return {}


def save_declared_cache(declared_data):
    """保存已申诉记录"""
    payload = {
        "version": "1.0",
        "total": len(declared_data),
        "declared": declared_data,
    }
    with open(DECLARED_CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def is_declared(sha256, engine_name):
    """检查某一文件的某引擎申诉记录是否已存在。返回 True/False"""
    key = f"{sha256}|{engine_name}"
    cache = load_declared_cache()
    return key in cache


def mark_declared(sha256, engine_name, file_path, project=""):
    """标记某一文件的某引擎申诉记录已完成"""
    key = f"{sha256}|{engine_name}"
    cache = load_declared_cache()
    cache[key] = {
        "sha256": sha256,
        "engine": engine_name,
        "file_path": file_path,
        "declared_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "project": project,
    }
    save_declared_cache(cache)


def clear_declared_cache():
    """清空已申诉记录"""
    if DECLARED_CACHE_FILE.exists():
        DECLARED_CACHE_FILE.unlink()
    return True


def declared_stats():
    """返回已申诉记录统计"""
    cache = load_declared_cache()
    if not cache:
        return "已申诉记录为空。"
    last = max((e.get("declared_at", "") for e in cache.values()), default="")
    return (f"已申诉条目: {len(cache)} 个\n"
            f"最近申诉: {last}")


def export_excel(json_path, output_path):
    """从 scan_data JSON 导出报毒清单 Excel"""
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill, Alignment
    except ImportError:
        print("需要 openpyxl，正在安装...")
        import subprocess, sys
        subprocess.check_call([sys.executable, "-m", "pip", "install", "openpyxl", "-q"])
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill, Alignment

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        print("错误: JSON 格式不正确，应为数组")
        return

    # 加载厂家联系方式
    gfe_path = Path(__file__).parent / "generate_fp_emails.py"
    import importlib.util
    spec = importlib.util.spec_from_file_location("gfe", gfe_path)
    gfe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gfe)
    vc = getattr(gfe, "VENDOR_CONTACTS", {})

    # 筛选报毒文件
    detections_data = [r for r in data if r.get("malicious", 0) > 0 or r.get("suspicious", 0) > 0]
    if not detections_data:
        print("没有报毒文件，无需导出。")
        return

    scan_date = datetime.fromtimestamp(Path(json_path).stat().st_mtime).strftime("%Y-%m-%d")

    wb = Workbook()
    ws = wb.active
    ws.title = "报毒清单"

    # 表头
    headers = ["文件路径", "报毒详情", "VT链接", "厂家联系方式", "扫毒日期"]
    header_fill = PatternFill(start_color="4472C4", end_color="4472C4", fill_type="solid")
    header_font = Font(color="FFFFFF", bold=True, size=11)
    wrap_align = Alignment(wrap_text=True, vertical="top")

    for col, h in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col, value=h)
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(horizontal="center", vertical="center")

    # 恶意红 / 可疑橙
    red_fill = PatternFill(start_color="FCE4EC", end_color="FCE4EC", fill_type="solid")
    orange_fill = PatternFill(start_color="FFF3E0", end_color="FFF3E0", fill_type="solid")

    row = 2
    for r in detections_data:
        fp = r.get("filepath", r.get("filename", "?"))
        sha256 = r.get("sha256", "")
        vt_link = f"https://www.virustotal.com/gui/file/{sha256}" if sha256 else ""
        engines = r.get("engines", {})
        m = r.get("malicious", 0)
        s = r.get("suspicious", 0)

        det_lines = []
        contact_lines = []
        for ename, info in engines.items():
            cat = info.get("category", "")
            if cat not in ("malicious", "suspicious"):
                continue
            result = info.get("result", cat)
            det_lines.append(f"{ename}: {result}")
            contact = vc.get(ename, "")
            if contact:
                contact_lines.append(f"{ename}: {contact}")

        det_str = "\n".join(det_lines) if det_lines else "无"
        contact_str = "\n".join(contact_lines) if contact_lines else "无联系方式"

        ws.cell(row=row, column=1, value=fp)
        ws.cell(row=row, column=2, value=det_str)
        ws.cell(row=row, column=3, value=vt_link)
        ws.cell(row=row, column=4, value=contact_str)
        ws.cell(row=row, column=5, value=scan_date)

        row_fill = red_fill if m > 0 else orange_fill
        for c in range(1, 6):
            ws.cell(row=row, column=c).fill = row_fill
            ws.cell(row=row, column=c).alignment = wrap_align

        row += 1

    # 列宽
    ws.column_dimensions["A"].width = 55
    ws.column_dimensions["B"].width = 45
    ws.column_dimensions["C"].width = 50
    ws.column_dimensions["D"].width = 45
    ws.column_dimensions["E"].width = 14

    wb.save(output_path)
    print(f"已导出 {len(detections_data)} 条报毒记录 → {output_path}")


def scan_folder(folder: Path):
    """遍历文件夹，收集待扫描文件"""
    files = []
    skipped_text = []
    for entry in folder.rglob("*"):
        if entry.is_file():
            if should_scan(entry):
                files.append(entry)
            elif entry.suffix.lower() in EXCLUDE_EXTENSIONS:
                skipped_text.append(entry)
    return files, skipped_text


def collect_targets(paths):
    """从混合路径列表收集待扫描文件：文件直接加入，文件夹递归扫描。去重。"""
    seen = set()
    files = []
    skipped_text = []

    for raw in paths:
        p = Path(raw.strip().strip('"').strip("'"))
        if not p.exists():
            print(f"  [警告] 路径不存在，跳过: {raw}")
            continue

        if p.is_file():
            if p.resolve() not in seen:
                seen.add(p.resolve())
                if should_scan(p):
                    files.append(p)
                elif p.suffix.lower() in EXCLUDE_EXTENSIONS:
                    skipped_text.append(p)
        elif p.is_dir():
            sub_files, sub_skip = scan_folder(p)
            for f in sub_files:
                if f.resolve() not in seen:
                    seen.add(f.resolve())
                    files.append(f)
            for s in sub_skip:
                if s.resolve() not in seen:
                    seen.add(s.resolve())
                    skipped_text.append(s)

    return files, skipped_text


def file_sha256(file_path: Path):
    """计算文件 SHA-256"""
    sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha.update(chunk)
    return sha.hexdigest()


def sort_by_priority(files):
    """按文件类型优先级排序：exe > dll > bin > sys > ... > 其他"""
    def priority_key(f):
        ext = f.suffix.lower()
        return FILE_PRIORITY.get(ext, 99)
    files.sort(key=priority_key)
    return files


# v2.0: 上次请求时间，用于精确限速（不浪费首请求 15s 空等）
_last_request_time = 0.0

def vt_request(method, endpoint, api_key, key_mgr, record_quota=True):
    """发送 VirusTotal API 请求，自动处理限速、配额检查、自动切换。

    record_quota=False: 免费操作（上传新文件、轮询新文件分析结果），不扣配额也不检查配额。
    """
    if record_quota:
        ok, msg = key_mgr.check_quota()
        if not ok:
            if "所有 Key" in msg or "Key 池为空" in msg:
                if not key_mgr.prompt_new_key():
                    raise Exception(f"API 配额耗尽: {msg}")
                api_key = key_mgr.current_key()
            else:
                raise Exception(f"API 配额异常: {msg}")

    headers = {"x-apikey": api_key, "Accept": "application/json"}
    url = f"{VT_API_BASE}{endpoint}"

    # v2.0: 精确限速——距上次调用不足间隔才等待，不浪费首请求
    global _last_request_time
    elapsed = time.time() - _last_request_time
    if elapsed < RATE_LIMIT_INTERVAL:
        time.sleep(RATE_LIMIT_INTERVAL - elapsed)

    if method == "GET":
        resp = requests.get(url, headers=headers, timeout=30)
    elif method == "POST":
        resp = requests.post(url, headers=headers, timeout=60)
    else:
        raise ValueError(f"不支持的 HTTP 方法: {method}")

    _last_request_time = time.time()

    # HTTP 429 限速重试：每个 key 最多 3 次，耗尽后切换下一个 key
    retry_count = 0
    attempted_keys = {api_key}

    while resp.status_code == 429 and len(attempted_keys) < len(key_mgr.keys) + 1:
        retry_count += 1
        wait = 60 * retry_count
        label = key_mgr.current_label()
        print(f"\n  [HTTP 429] Key [{label}] 限速，等待 {wait}s 后重试 ({retry_count}/3)...", flush=True)
        time.sleep(wait)
        _last_request_time = time.time()

        if method == "GET":
            resp = requests.get(url, headers=headers, timeout=30)
        else:
            resp = requests.post(url, headers=headers, timeout=60)

        if resp.status_code != 429:
            break  # 成功

        # 当前 key 已重试 3 次仍然 429 → 切换 key
        if retry_count >= 3 and len(key_mgr.keys) > 1:
            old_label = key_mgr.current_label()
            switched = key_mgr._switch_to_next_available()
            if switched:
                new_label = key_mgr.current_label()
                print(f"  [密钥切换] [{old_label}] 3次重试仍限速 → 切换到 [{new_label}]", flush=True)
                api_key = key_mgr.current_key()
                headers = {"x-apikey": api_key, "Accept": "application/json"}
                attempted_keys.add(api_key)
                retry_count = 0
                continue
            else:
                print(f"  [密钥耗尽] [{old_label}] 3次重试仍限速，且无其他可用 key，跳过此文件", flush=True)
                break

        if retry_count >= 3:
            print(f"  [重试耗尽] 当前 key 3次重试仍 429，单 key 模式下跳过此文件", flush=True)
            break

    if record_quota:
        key_mgr.record_call()
    return resp


# v2.0: 限速辅助函数（用于非 vt_request 的请求，如 upload_url POST）


def _wait_rate_limit():
    """等待满足限速间隔"""
    global _last_request_time
    elapsed = time.time() - _last_request_time
    if elapsed < RATE_LIMIT_INTERVAL:
        time.sleep(RATE_LIMIT_INTERVAL - elapsed)


def _update_last_request_time():
    """更新最后请求时间"""
    global _last_request_time
    _last_request_time = time.time()


def check_existing_report(api_key, sha256_hash, key_mgr, filename="", no_cache=False):
    """检查文件是否已有分析报告（先本地缓存，再 VT API）"""
    # v3.0: 优先查本地缓存（除非 --no-cache）
    if not no_cache:
        cached = cache_lookup(sha256_hash)
        if cached:
            return cached  # 返回缓存条目而非完整 VT 响应

    try:
        resp = vt_request("GET", f"/files/{sha256_hash}", api_key, key_mgr)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None


def upload_file(api_key, file_path: Path, key_mgr):
    """上传文件到 VirusTotal"""
    file_size = file_path.stat().st_size

    if file_size > MAX_FILE_SIZE:
        resp = vt_request("GET", "/files/upload_url", api_key, key_mgr, record_quota=False)
        resp.raise_for_status()
        upload_url = resp.json()["data"]
    else:
        upload_url = f"{VT_API_BASE}/files"

    with open(file_path, "rb") as f:
        resp = requests.post(
            upload_url,
            headers={"x-apikey": api_key},
            files={"file": (file_path.name, f)},
            timeout=120,
        )

    # HTTP 429 限速重试：每个 key 最多 3 次，耗尽后切换下一个 key
    retry_count = 0
    attempted_keys = {api_key}

    while resp.status_code == 429 and len(attempted_keys) < len(key_mgr.keys) + 1:
        retry_count += 1
        wait = 60 * retry_count
        label = key_mgr.current_label()
        print(f"\n  [HTTP 429] Key [{label}] 上传限速，等待 {wait}s 后重试 ({retry_count}/3)...", flush=True)
        time.sleep(wait)
        _update_last_request_time()
        with open(file_path, "rb") as f:
            resp = requests.post(
                upload_url,
                headers={"x-apikey": api_key},
                files={"file": (file_path.name, f)},
                timeout=120,
            )

        if resp.status_code != 429:
            break  # 成功

        # 当前 key 已重试 3 次仍然 429 → 切换 key
        if retry_count >= 3 and len(key_mgr.keys) > 1:
            old_label = key_mgr.current_label()
            switched = key_mgr._switch_to_next_available()
            if switched:
                new_label = key_mgr.current_label()
                print(f"  [密钥切换] [{old_label}] 3次重试仍限速 → 切换到 [{new_label}]", flush=True)
                api_key = key_mgr.current_key()
                attempted_keys.add(api_key)
                retry_count = 0
                continue
            else:
                print(f"  [密钥耗尽] [{old_label}] 3次重试仍限速，且无其他可用 key，跳过此文件", flush=True)
                break

        if retry_count >= 3:
            print(f"  [重试耗尽] 当前 key 3次重试仍 429，单 key 模式下跳过此文件", flush=True)
            break

    if resp.status_code == 200:
        return resp.json()
    else:
        raise Exception(f"上传失败 (HTTP {resp.status_code}): {resp.text[:200]}")


def get_analysis(api_key, analysis_id, key_mgr):
    """获取分析结果，v2.0 渐进式轮询 + 免费调用"""
    for i, interval in enumerate(PROGRESSIVE_INTERVALS):
        time.sleep(interval)
        try:
            resp = vt_request("GET", f"/analyses/{analysis_id}", api_key, key_mgr, record_quota=False)
            if resp.status_code == 200:
                data = resp.json()
                status = data.get("data", {}).get("attributes", {}).get("status", "")
                if status == "completed":
                    return data
        except Exception:
            pass
    return None


# ========== 报告生成 ==========

def generate_detection_reports(results, output_dir):
    """为每个报毒文件生成独立的 JSON 和 MD 文件"""
    detections_dir = output_dir / "detections"
    detections_dir.mkdir(parents=True, exist_ok=True)
    count = 0

    for r in results:
        sha256 = r.get("sha256", "")
        malicious = r.get("malicious", 0)
        suspicious = r.get("suspicious", 0)
        if malicious == 0 and suspicious == 0:
            continue
        if not sha256:
            continue

        engines = r.get("engines", {})
        detections = []
        for ename, edata in sorted(engines.items()):
            cat = edata.get("category", "")
            threat = edata.get("result", "")
            if cat in ("malicious", "suspicious"):
                detections.append({
                    "engine": ename,
                    "name": threat,
                    "category": cat,
                })

        if not detections:
            continue

        count += 1
        safe_name = "".join(c if c.isalnum() or c in "._- " else "_" for c in r["filename"])
        vt_link = f"https://www.virustotal.com/gui/file/{sha256}"

        # JSON
        json_data = {
            "file_name": r["filename"],
            "file_path": r["filepath"],
            "sha256": sha256,
            "virus_total_link": vt_link,
            "malicious": malicious,
            "suspicious": suspicious,
            "detections": detections,
        }
        json_path = detections_dir / f"{safe_name}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2, ensure_ascii=False)

        # MD
        md_lines = [
            f"# 报毒文件报告",
            f"",
            f"- **File name**: {r['filename']}",
            f"- **File path**: {r['filepath']}",
            f"- **SHA256**: {sha256}",
            f"- **VirusTotal link**: [{vt_link}]({vt_link})",
            f"",
            f"## 检测结果",
            f"",
        ]
        for d in detections:
            md_lines.append(f"- **Detection engine**: {d['engine']}")
            md_lines.append(f"- **Detection name**: {d['name']}")
            md_lines.append(f"")

        md_path = detections_dir / f"{safe_name}.md"
        with open(md_path, "w", encoding="utf-8") as f:
            f.write("\n".join(md_lines))

    return detections_dir, count


def generate_html_report(results, source_desc, skipped_count):
    """生成 HTML 报告"""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 恶意和可疑排在前面：先按恶意降序，再按可疑降序
    results = sorted(results, key=lambda r: (-r.get("malicious", 0), -r.get("suspicious", 0)))

    rows = ""
    for r in results:
        filename = r["filename"]
        filepath = r["filepath"]
        sha256 = r.get("sha256", "")
        malicious = r.get("malicious", 0)
        suspicious = r.get("suspicious", 0)
        undetected = r.get("undetected", 0)
        harmless = r.get("harmless", 0)
        total_engines = malicious + suspicious + undetected + harmless

        if malicious > 0 or suspicious > 0:
            if malicious > 0 and suspicious > 0:
                badge = "danger"
                badge_text = f'<span class="badge danger">恶意 {malicious}</span> <span class="badge warning">可疑 {suspicious}</span>'
            elif malicious > 0:
                badge = "danger"
                badge_text = f"恶意 {malicious}"
            else:
                badge = "warning"
                badge_text = f"可疑 {suspicious}"
        else:
            badge = "safe"
            badge_text = "安全"

        # 报毒详情
        detections_list = ""
        engines = r.get("engines", {})
        if engines:
            detections = []
            for ename, edata in sorted(engines.items()):
                cat = edata.get("category", "")
                threat = edata.get("result", "")
                if cat in ("malicious", "suspicious"):
                    detections.append(
                        f'<span class="detect-item {cat}" title="{ename} 报毒: {threat}">{ename}: {threat}</span>'
                    )
            detections_list = "".join(detections) if detections else "—"
        else:
            detections_list = "—"

        vt_link = f"https://www.virustotal.com/gui/file/{sha256}"

        rows += f"""
        <tr class="{badge}">
            <td class="filepath" title="{filepath}">{filepath}</td>
            <td class="hash">{sha256}</td>
            <td><span class="badge {badge}">{badge_text}</span></td>
            <td>{malicious}/{total_engines}</td>
            <td class="detections">{detections_list}</td>
            <td class="vt-link"><a href="{vt_link}" target="_blank" title="在 VirusTotal 查看">查看</a></td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>VirusTotal 扫描报告</title>
<style>
    * {{ margin:0; padding:0; box-sizing:border-box; }}
    body {{ font-family: -apple-system, "Microsoft YaHei", sans-serif; background: #f5f5f5; color: #333; padding: 20px; }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    .header {{ background: linear-gradient(135deg, #1a1a2e, #16213e); color: #fff; padding: 30px; border-radius: 12px; margin-bottom: 20px; }}
    .header h1 {{ font-size: 24px; margin-bottom: 8px; }}
    .header .meta {{ font-size: 13px; opacity: 0.7; }}
    .stats {{ display: flex; gap: 16px; margin-bottom: 20px; flex-wrap: wrap; }}
    .stat {{ background: #fff; padding: 16px 24px; border-radius: 8px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); flex: 1; min-width: 120px; text-align: center; }}
    .stat .num {{ font-size: 28px; font-weight: 700; }}
    .stat .label {{ font-size: 12px; color: #888; margin-top: 4px; }}
    .stat.danger .num {{ color: #e74c3c; }}
    .stat.warning .num {{ color: #f39c12; }}
    .stat.safe .num {{ color: #27ae60; }}
    table {{ width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }}
    th {{ background: #fafafa; padding: 12px 16px; text-align: left; font-weight: 600; font-size: 13px; border-bottom: 2px solid #eee; }}
    td {{ padding: 10px 16px; border-bottom: 1px solid #f0f0f0; font-size: 13px; }}
    tr:hover {{ background: #fafbfc; }}
    tr.danger {{ border-left: 4px solid #e74c3c; }}
    tr.warning {{ border-left: 4px solid #f39c12; }}
    tr.safe {{ border-left: 4px solid #27ae60; }}
    .filepath {{ max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 12px; }}
    .hash {{ font-family: "Cascadia Code", monospace; font-size: 11px; color: #888; word-break: break-all; }}
    .badge {{ display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 12px; font-weight: 600; }}
    .badge.danger {{ background: #f8d7da; color: #721c24; }}
    .badge.warning {{ background: #fff3cd; color: #856404; }}
    .badge.safe {{ background: #d4edda; color: #155724; }}
    .detections {{ display: flex; flex-wrap: wrap; gap: 4px; max-width: 400px; }}
    .detect-item {{ font-size: 11px; padding: 3px 8px; border-radius: 4px; white-space: nowrap; }}
    .detect-item.malicious {{ background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }}
    .detect-item.suspicious {{ background: #fff3cd; color: #856404; border: 1px solid #ffeeba; }}
    .vt-link a {{ color: #3498db; text-decoration: none; font-size: 12px; font-weight: 500; }}
    .vt-link a:hover {{ text-decoration: underline; }}
    .footer {{ text-align: center; margin-top: 20px; font-size: 12px; color: #999; }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>VirusTotal 批量扫描报告</h1>
        <div class="meta">扫描时间: {now} | 扫描目标: {source_desc}</div>
    </div>
    <div class="stats">
        <div class="stat"><div class="num">{len(results)}</div><div class="label">扫描文件</div></div>
        <div class="stat danger"><div class="num">{sum(1 for r in results if r.get('malicious', 0) > 0)}</div><div class="label">检测到恶意</div></div>
        <div class="stat warning"><div class="num">{sum(1 for r in results if r.get('malicious', 0) == 0 and r.get('suspicious', 0) > 0)}</div><div class="label">可疑文件</div></div>
        <div class="stat safe"><div class="num">{sum(1 for r in results if r.get('malicious', 0) == 0 and r.get('suspicious', 0) == 0)}</div><div class="label">安全文件</div></div>
        <div class="stat"><div class="num">{skipped_count}</div><div class="label">跳过(文本类)</div></div>
    </div>
    <table>
        <thead>
            <tr><th>文件路径</th><th>SHA-256</th><th>状态</th><th>检出率</th><th>报毒详情</th><th>VT链接</th></tr>
        </thead>
        <tbody>{rows}
        </tbody>
    </table>
    <div class="footer">Powered by VirusTotal API · Generated by Virus Scanner Tool</div>
</div>
</body>
</html>"""
    return html


# ========== 命令行参数 ==========

def parse_args():
    parser = argparse.ArgumentParser(
        description="VirusTotal 批量文件扫描工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python virus_scanner.py                                 交互模式
  python virus_scanner.py -k YOUR_KEY                     临时 key
  python virus_scanner.py -k YOUR_KEY --save-key          添加 key 到池
  python virus_scanner.py --add-key                       交互添加 key
  python virus_scanner.py --add-key YOUR_KEY              命令行添加 key
  python virus_scanner.py --key-file keys.txt             从文件加载 key 池
  python virus_scanner.py --list-keys                     查看 key 池状态
  python virus_scanner.py -f "D:\\Downloads"              直接指定文件夹
  python virus_scanner.py -p file.exe "D:\\Downloads"     混合指定文件和文件夹
        """,
    )
    parser.add_argument("-k", "--key", default=None,
                        help="临时使用指定的 API Key")
    parser.add_argument("--save-key", action="store_true",
                        help="配合 -k 使用，将 Key 持久化到池中")
    parser.add_argument("--add-key", nargs="?", const="__interactive__", default=None,
                        help="添加 API Key 到池（不带参数则交互输入）")
    parser.add_argument("--key-file", default=None,
                        help="从文本文件加载 Key 池（每行一个 key，# 开头为注释）")
    parser.add_argument("--list-keys", action="store_true",
                        help="列出所有 Key 及其配额状态")
    parser.add_argument("-f", "--folder", default=None,
                        help="要扫描的文件夹路径（不传则弹出 GUI 选择）")
    parser.add_argument("-p", "--path", nargs="+", default=None,
                        help="指定文件或文件夹路径（支持多个，文件直接扫描，文件夹递归扫描）")
    parser.add_argument("--project-name", default=None,
                        help="自定义项目名称（默认取扫描根目录名）")
    parser.add_argument("--no-cache", action="store_true",
                        help="忽略本地缓存，强制上传扫描")
    parser.add_argument("--clear-cache", action="store_true",
                        help="清空本地扫描缓存后退出")
    parser.add_argument("--cache-stats", action="store_true",
                        help="显示缓存统计信息")
    parser.add_argument("--report-filter", default=None, metavar="SCAN_DATA_JSON",
                        help="从已有 scan_data JSON 筛选报毒文件，生成仅含报毒项的 HTML 报告")
    parser.add_argument("--err", default=None, metavar="SCAN_DATA_JSON",
                        help="输出报毒文件测试报告（文本），列出所有恶意/可疑文件及引擎详情")
    parser.add_argument("--gen-emails", default=None, metavar="SCAN_DATA_OR_DIR",
                        help="从 scan_data JSON 或 detections 目录自动筛选报毒文件，逐封确认生成申诉邮件")
    parser.add_argument("--excel", default=None, metavar="SCAN_DATA_JSON",
                        help="从 scan_data JSON 导出报毒清单为 Excel，含文件路径/报毒详情/VT链接/厂家联系方式/扫毒日期")
    return parser.parse_args()


# ========== 主流程 ==========

def main():
    args = parse_args()
    key_mgr = ApiKeyManager()

    # ----- 管理类命令（仅执行后退出）-----

    if args.list_keys:
        print("\nKey 池状态:")
        print(key_mgr.list_keys())
        return

    if args.clear_cache:
        clear_scan_cache()
        print("本地扫描缓存已清空。")
        return

    if args.cache_stats:
        print("\n扫描缓存统计:")
        print(cache_stats())
        return

    if args.add_key:
        if args.add_key == "__interactive__":
            new_key = input("请输入 API Key: ").strip()
        else:
            new_key = args.add_key
        ok, msg = key_mgr.add_key(new_key, save=True)
        print(f"\n{msg}")
        if ok:
            print(key_mgr.list_keys())
        return

    if args.key_file:
        ok, msg = key_mgr.load_keys_from_file(args.key_file)
        print(f"\n{msg}")
        if ok:
            print(key_mgr.list_keys())
        return

    # ----- 报告筛选命令 ----

    if args.report_filter:
        json_path = Path(args.report_filter)
        if not json_path.is_file():
            print(f"错误: 文件不存在 - {json_path}")
            return
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            print("错误: JSON 格式不正确，应为数组")
            return
        filtered = [r for r in data if r.get("malicious", 0) > 0 or r.get("suspicious", 0) > 0]
        if not filtered:
            print("没有报毒或可疑文件。")
            return

        source = json_path.parent.parent.name if json_path.parent.parent != json_path.parent else json_path.parent.name
        html = generate_html_report(filtered, f"{source}（仅报毒）", 0)
        out_path = json_path.with_suffix("").with_suffix("")  # 去掉 .json
        out_path = Path(str(out_path) + "_detections_only.html")
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"已生成报毒报告: {out_path}")
        print(f"  共 {len(filtered)} 个文件（恶意: {sum(1 for r in filtered if r.get('malicious', 0) > 0)}，可疑: {sum(1 for r in filtered if r.get('malicious', 0) == 0 and r.get('suspicious', 0) > 0)}）")
        return

    # ----- 报毒测试报告命令 ----

    if args.err:
        json_path = Path(args.err)
        if not json_path.is_file():
            print(f"错误: 文件不存在 - {json_path}")
            return
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            print("错误: JSON 格式不正确，应为数组")
            return

        detections_list = [r for r in data if r.get("malicious", 0) > 0 or r.get("suspicious", 0) > 0]
        if not detections_list:
            print("没有报毒文件。")
            return

        print(f"\n{BOLD}报毒文件测试报告（{len(detections_list)} 个文件）{RESET}")
        print("=" * 70)

        for idx, r in enumerate(detections_list, 1):
            fp = r.get("filepath", r.get("filename", "?"))
            sha = r.get("sha256", "?")
            engines = r.get("engines", {})
            det = [(ename, info.get("result", info.get("category", "?")),
                    info.get("category", "?"))
                   for ename, info in engines.items()
                   if info.get("category") in ("malicious", "suspicious")]

            m = r.get("malicious", 0)
            s = r.get("suspicious", 0)
            color = RED if m > 0 else YELLOW

            print(f"\n  {color}{BOLD}[{idx}] {fp}{RESET}")
            print(f"      SHA256: {sha}")
            print(f"      {RED}恶意: {m}{RESET}  {YELLOW}可疑: {s}{RESET}")
            for ename, threat, cat in det:
                if cat == "malicious":
                    tag = f"{RED}[M]{RESET}"
                else:
                    tag = f"{YELLOW}[S]{RESET}"
                print(f"      {tag} {ename}: {threat}")

        m_cnt = sum(1 for r in detections_list if r.get("malicious", 0) > 0)
        s_cnt = sum(1 for r in detections_list if r.get("malicious", 0) == 0 and r.get("suspicious", 0) > 0)
        print(f"\n{'=' * 70}")
        print(f"  {BOLD}合计: {RED}{m_cnt} 恶意{RESET}{BOLD}, {YELLOW}{s_cnt} 可疑{RESET}")
        return

    # ----- 生成申诉邮件命令 ----

    if args.gen_emails:
        target = Path(args.gen_emails)

        # 动态导入 generate_fp_emails 模块
        import importlib.util
        gfe_path = Path(__file__).parent / "generate_fp_emails.py"
        spec = importlib.util.spec_from_file_location("generate_fp_emails", gfe_path)
        gfe = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gfe)

        # 收集所有待生成邮件
        email_queue = []
        ts = ""

        if target.is_file() and target.suffix == ".json":
            # 模式 1: 直接从 scan_data JSON 自动筛选报毒文件
            with open(target, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, list):
                print("错误: JSON 格式不正确，应为数组")
                return

            detections_data = [r for r in data if r.get("malicious", 0) > 0 or r.get("suspicious", 0) > 0]
            if not detections_data:
                print("没有报毒文件，无需生成邮件。")
                return

            print(f"从 {target.name} 筛选出 {len(detections_data)} 个报毒文件\n")

            uploaded_files = {}  # file_path → github_link
            project_name = target.parent.name
            for r in detections_data:
                file_name = r.get("filename", "?")
                file_path = r.get("filepath", file_name)
                sha256 = r.get("sha256", "")
                vt_link = f"https://www.virustotal.com/gui/file/{sha256}" if sha256 else ""

                # 每个文件只上传一次到 GitHub
                if file_path not in uploaded_files:
                    github_link = gfe.upload_to_github(file_path, project_name)
                    uploaded_files[file_path] = github_link

                engines = r.get("engines", {})
                for ename, info in engines.items():
                    cat = info.get("category", "")
                    if cat not in ("malicious", "suspicious"):
                        continue
                    threat = info.get("result", info.get("category", "?"))
                    body, recipient = gfe.generate_email(
                        file_name, sha256, vt_link, ename, threat,
                        github_link=uploaded_files[file_path])
                    if body is None:
                        continue
                    email_queue.append({
                        "file_name": file_name,
                        "file_path": file_path,
                        "engine": ename,
                        "threat": threat,
                        "sha256": sha256,
                        "vt_link": vt_link,
                        "recipient": recipient,
                        "body": body,
                    })

            ts = target.stem.split("scan_data_", 1)[-1] if "scan_data_" in target.stem \
                else datetime.now().strftime("%Y%m%d_%H%M%S")

        elif target.is_dir():
            # 模式 2: 从 detections 目录读取（兼容旧用法）
            json_files = sorted(target.glob("*.json"))
            if not json_files:
                print(f"错误: 目录下没有 JSON 文件 - {target}")
                return

            uploaded_files = {}  # file_path → github_link
            project_name = target.parent.name
            for jf in json_files:
                with open(jf, "r", encoding="utf-8") as f:
                    data = json.load(f)
                file_name = data.get("file_name", jf.stem)
                file_path = data.get("file_path", file_name)
                sha256 = data.get("sha256", "")
                vt_link = data.get("virus_total_link", "")

                # 每个文件只上传一次到 GitHub
                if file_path not in uploaded_files:
                    github_link = gfe.upload_to_github(file_path, project_name)
                    uploaded_files[file_path] = github_link

                for det in data.get("detections", []):
                    engine = det.get("engine", "Unknown")
                    threat = det.get("name", "Unknown")
                    body, recipient = gfe.generate_email(file_name, sha256, vt_link, engine, threat,
                                                         github_link=uploaded_files[file_path])
                    if body is None:
                        print(f"  [{engine}] 跳过 (无邮箱)")
                        continue
                    email_queue.append({
                        "file_name": file_name,
                        "file_path": file_path,
                        "engine": engine,
                        "threat": threat,
                        "sha256": sha256,
                        "vt_link": vt_link,
                        "recipient": recipient,
                        "body": body,
                    })

            ts = target.name.split("_", 1)[-1] if "_" in target.name \
                else datetime.now().strftime("%Y%m%d_%H%M%S")
        else:
            print(f"错误: 路径不存在或不是 JSON 文件/目录 - {target}")
            return

        if not email_queue:
            print("没有可生成的邮件（所有引擎均无邮箱联系方式）。")
            return

        # v3.0: 过滤已申诉记录，避免重复发送
        skipped_declared = 0
        filtered_queue = []
        for em in email_queue:
            if is_declared(em["sha256"], em["engine"]):
                skipped_declared += 1
            else:
                filtered_queue.append(em)

        if skipped_declared > 0:
            print(f"\n📌 跳过 {skipped_declared} 条已申诉记录（declared_cache.json）\n")
        email_queue = filtered_queue

        if not email_queue:
            print("所有报毒引擎均已申诉过，无需重复发送。")
            return

        print(f"\n共 {len(email_queue)} 封待确认邮件：\n")

        confirmed = []
        confirm_all = False
        for i, em in enumerate(email_queue):
            if confirm_all:
                confirmed.append(em)
                print(f"  [{i+1}/{len(email_queue)}] 已确认  {em['file_name']} → {em['engine']} → {em['recipient']}")
                continue

            # 展示邮件信息
            print("-" * 60)
            print(f"  [{i+1}/{len(email_queue)}]")
            print(f"  文件:   {em['file_path']}")
            print(f"  SHA256: {em['sha256']}")
            print(f"  引擎:   {em['engine']}")
            print(f"  报毒:   {em['threat']}")
            print(f"  收件人: {em['recipient']}")
            print(f"  VT链接: {em['vt_link']}")
            print("-" * 60)
            print(em['body'])
            print("-" * 60)

            while True:
                choice = input("  [y]确认 [n]跳过 [a]全部确认 [q]退出: ").strip().lower()
                if choice == "y":
                    confirmed.append(em)
                    break
                elif choice == "n":
                    print(f"  → 已跳过\n")
                    break
                elif choice == "a":
                    confirmed.append(em)
                    confirm_all = True
                    break
                elif choice == "q":
                    print(f"\n  已退出，共确认 {len(confirmed)}/{len(email_queue)} 封。")
                    break
                else:
                    print("  请输入 y / n / a / q")
            if choice == "q":
                break

        if not confirmed:
            print("没有确认的邮件，退出。")
            return

        # 写入确认的邮件并发送
        output_dir = target.parent / f"emails_{ts}"
        output_dir.mkdir(parents=True, exist_ok=True)

        send_results = []
        for em in confirmed:
            safe_file = "".join(c if c.isalnum() or c in "._- " else "_" for c in em["file_name"])
            safe_engine = "".join(c if c.isalnum() or c in "._- " else "_" for c in em["engine"])
            email_path = output_dir / f"{safe_file}__{safe_engine}.txt"
            with open(email_path, "w", encoding="utf-8") as f:
                f.write(f"To: {em['recipient']}\n")
                f.write(f"Subject: VirusTotal False Positive Report\n")
                f.write(f"{'=' * 60}\n\n")
                f.write(em["body"])

            # SMTP 发送
            subject = f"False Positive Report - {em['engine']} - {em['file_name']}"
            ok, err = gfe.send_fp_email(em["recipient"], subject, em["body"])
            if ok:
                mark_declared(em["sha256"], em["engine"], em["file_path"],
                              project=target.parent.name)
                status = "已发送"
            else:
                status = f"失败: {err}"
            send_results.append({**em, "status": status})
            print(f"  [{em['engine']}] {status}")

        # 汇总清单
        summary_path = output_dir / "_summary.txt"
        with open(summary_path, "w", encoding="utf-8") as f:
            for em in confirmed:
                f.write(f"[{em['file_name']}] {em['engine']}: {em['threat']} → {em['recipient']}\n")

        # 生成已申诉文件 MD 文档
        md_path = output_dir / "_sent.md"
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(f"# 误报申诉发送记录\n\n")
            f.write(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"| # | 文件 | SHA256 | 引擎 | 报毒名 | 收件人 | 状态 |\n")
            f.write(f"|---|------|--------|------|--------|--------|------|\n")
            for idx, sr in enumerate(send_results, 1):
                sha_short = sr["sha256"][:12] + "..." if len(sr["sha256"]) > 12 else sr["sha256"]
                f.write(f"| {idx} | {sr['file_path']} | {sha_short} | {sr['engine']} | {sr['threat']} | {sr['recipient']} | {sr['status']} |\n")
            sent_cnt = sum(1 for sr in send_results if sr["status"] == "已发送")
            f.write(f"\n共 **{len(confirmed)}** 封申诉邮件，已发送 **{sent_cnt}** 封。\n")

        print(f"\n{'=' * 60}")
        sent_cnt = sum(1 for sr in send_results if sr["status"] == "已发送")
        print(f"  已确认 {len(confirmed)}/{len(email_queue)} 封，成功发送 {sent_cnt} 封")
        print(f"  邮件目录: {output_dir}")
        print(f"  汇总清单: {summary_path}")
        print(f"  申诉记录: {md_path}")
        print(f"{'=' * 60}")
        return

    # ----- 导出报毒 Excel 命令 ----

    if args.excel:
        json_path = Path(args.excel)
        if not json_path.exists():
            print(f"错误: 文件不存在 - {json_path}")
            return
        output_path = json_path.parent / f"报毒清单_{json_path.stem}.xlsx"
        export_excel(json_path, output_path)
        return

    # ----- 扫描流程 -----

    print("\n" + "=" * 60)
    print("   VirusTotal 批量文件扫描工具 v3.0")
    print("=" * 60)

    # Step 1: 处理 Key
    if args.key:
        key_mgr.add_key(args.key, label="cli-temp", save=args.save_key)
        key_mgr.active_idx = len(key_mgr.keys) - 1
        key_mgr._save()

    api_key = key_mgr.current_key()
    if not api_key:
        print("\n[提示] Key 池为空。")
        print("  方式1: python virus_scanner.py -k YOUR_KEY")
        print("  方式2: python virus_scanner.py --add-key")
        print("  方式3: python virus_scanner.py --key-file keys.txt")
        print("\n  指定目标:")
        print("  python virus_scanner.py -p file.exe folder1 file2.dll (混合文件和文件夹)")
        print("  python virus_scanner.py -f D:\\Downloads              (指定文件夹)")
        print("\n  获取 Key: https://www.virustotal.com → 注册/登录 → API key")
        sys.exit(1)

    print(f"[API 配额] {key_mgr.quota_status()}")
    if len(key_mgr.keys) > 1:
        print(f"[Key 池] 共 {len(key_mgr.keys)} 个 Key，配额耗尽自动切换")

    # Step 2: 确定扫描目标
    if args.path:
        files, skipped_text = collect_targets(args.path)
        source_desc = ", ".join(str(Path(p).name) for p in args.path[:5])
        if len(args.path) > 5:
            source_desc += f" 等 {len(args.path)} 项"
    elif args.folder:
        folder = Path(args.folder)
        if not folder.is_dir():
            print(f"\n[错误] 指定路径不是有效目录: {args.folder}")
            sys.exit(1)
        files, skipped_text = scan_folder(folder)
        source_desc = folder.name
    else:
        folder = select_folder()
        files, skipped_text = scan_folder(folder)
        source_desc = folder.name

    print(f"  找到 {len(files)} 个待扫描文件，跳过 {len(skipped_text)} 个文本类文件")
    sort_by_priority(files)

    if not files:
        print("\n  未发现需要扫描的文件，程序退出。")
        return

    # Step 2.5: 创建/复用项目文件夹
    project_name = args.project_name or source_desc
    safe_pn = "".join(c if c.isalnum() or c in "._-" else "_" for c in project_name)
    output_dir = PROJECTS_DIR / safe_pn
    output_dir.mkdir(parents=True, exist_ok=True)

    json_path = output_dir / "scan_data.json"
    report_path = output_dir / "report.html"
    project_rel = f"projects\\{safe_pn}"

    print(f"\n[项目目录] {output_dir}")

    # Step 3: 配额预估（区分新文件 vs 缓存命中）
    cache = load_scan_cache()
    cached_count = 0
    new_files = []
    for f in files:
        sha = file_sha256(f)
        if not args.no_cache and sha in cache:
            cached_count += 1
        else:
            new_files.append(f)
    print(f"  缓存命中: {cached_count}  需扫描: {len(new_files)}")

    est_calls = len(new_files) * EST_CALLS_PER_FILE
    daily_r = key_mgr.daily_remaining()
    print(f"[配额预估] 约需 {est_calls} 次 API 调用（每文件 ~{EST_CALLS_PER_FILE} 次）")
    print(f"  当前 Key 日剩余: {daily_r}  月剩余: {key_mgr.monthly_remaining()}")

    if est_calls > daily_r and len(key_mgr.keys) < 2:
        print(f"\n  ⚠ 预估调用量 ({est_calls}) 超过当前 Key 日剩余配额 ({daily_r})")
        print(f"  建议: --add-key 添加更多 Key 实现自动切换，或等到配额重置")
        confirm = input("\n  是否仍要继续？[y/N]: ").strip().lower()
        if confirm != "y":
            print("  已取消扫描。")
            return

    print(f"\n预计耗时: 约 {len(new_files) * RATE_LIMIT_INTERVAL / 60:.1f} 分钟")
    print(f"速率限制: {RATE_LIMIT_PER_MINUTE} 次/分钟  |  日配额: {DAILY_QUOTA} 次  |  月配额: {MONTHLY_QUOTA/1000:.0f}K 次\n")

    # Step 4: 逐个扫描
    results = []
    skip_results = []  # 从缓存复用的历史结果
    pause_ctrl = PauseController()
    pause_ctrl.start()

    def _refresh_report():
        all_results = skip_results + results
        html = generate_html_report(all_results, source_desc, len(skipped_text))
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html)
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(all_results, f, indent=2, ensure_ascii=False)

    def _record_result(result):
        results.append(result)
        _refresh_report()

    # 先处理缓存命中的文件
    for file_path in files:
        sha = file_sha256(file_path)
        entry = cache.get(sha)
        if not entry:
            continue
        if args.no_cache:
            continue
        skip_results.append({
            "filename": file_path.name, "filepath": str(file_path),
            "sha256": sha,
            "malicious": entry.get("malicious", 0),
            "suspicious": entry.get("suspicious", 0),
            "undetected": 0, "harmless": 0, "engines": {},
            "status": "cached",
        })
        m = entry.get("malicious", 0)
        s = entry.get("suspicious", 0)
        color = RED if m > 0 else (YELLOW if s > 0 else "")
        rcol = RESET if color else ""
        print(f"  [缓存] {file_path.name} → {color}恶意:{m} 可疑:{s}{rcol}")

    _refresh_report()

    # 扫描需上传的文件
    for i, file_path in enumerate(files, 1):
        pause_ctrl.wait_if_paused()
        sha = file_sha256(file_path)
        if sha in cache and not args.no_cache:
            continue  # 已在 skip_results 中

        api_key = key_mgr.current_key()
        total = len(files)
        print(f"[{i}/{total}] {file_path.name} ...", end=" ", flush=True)

        try:
            sha256 = sha

            existing = check_existing_report(api_key, sha256, key_mgr, file_path.name, no_cache=args.no_cache)
            if existing:
                # 本地缓存命中（cache_lookup）或 VT 已有报告
                if isinstance(existing, dict) and "malicious" in existing:
                    # 本地缓存命中
                    m = existing.get("malicious", 0)
                    s = existing.get("suspicious", 0)
                    cache_put(sha256, str(file_path), file_path.name, project_rel, m, s)
                    _record_result({
                        "filename": file_path.name, "filepath": str(file_path),
                        "sha256": sha256, "malicious": m, "suspicious": s,
                        "undetected": 0, "harmless": 0, "engines": {},
                        "status": "cached",
                    })
                    color = RED if m > 0 else (YELLOW if s > 0 else "")
                    rcol = RESET if color else ""
                    print(f"→ 缓存 {color}恶意:{m} 可疑:{s}{rcol}")
                else:
                    # VT API 返回的已有报告
                    attrs = existing.get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    engines = attrs.get("last_analysis_results", {})
                    m = stats.get("malicious", 0)
                    s = stats.get("suspicious", 0)
                    cache_put(sha256, str(file_path), file_path.name, project_rel, m, s)
                    _record_result({
                        "filename": file_path.name, "filepath": str(file_path),
                        "sha256": sha256,
                        "malicious": m, "suspicious": s,
                        "undetected": stats.get("undetected", 0),
                        "harmless": stats.get("harmless", 0),
                        "engines": {k: {"category": v.get("category", ""), "result": v.get("result", "")}
                                    for k, v in engines.items()},
                        "status": "existing_report",
                    })
                    color = RED if m > 0 else (YELLOW if s > 0 else "")
                    rcol = RESET if color else ""
                    print(f"→ 已有报告 {color}恶意:{m} 可疑:{s}{rcol}")
                continue

            # 上传
            api_key = key_mgr.current_key()
            upload_resp = upload_file(api_key, file_path, key_mgr)
            analysis_id = upload_resp.get("data", {}).get("id", "")
            if not analysis_id:
                _record_result({
                    "filename": file_path.name, "filepath": str(file_path),
                    "sha256": sha256, "malicious": 0, "suspicious": 0,
                    "undetected": 0, "harmless": 0, "engines": {}, "status": "upload_failed",
                })
                print("上传失败: 未获取到分析 ID")
                continue

            # 等待分析
            print("分析中", end="", flush=True)
            api_key = key_mgr.current_key()
            analysis = get_analysis(api_key, analysis_id, key_mgr)

            if analysis:
                attrs = analysis.get("data", {}).get("attributes", {})
                stats = attrs.get("stats", {})
                engines = attrs.get("results", {})
                m = stats.get("malicious", 0)
                s = stats.get("suspicious", 0)
                cache_put(sha256, str(file_path), file_path.name, project_rel, m, s)
                flag = RED + "!!" if m > 0 else (YELLOW + "?" if s > 0 else GREEN + "OK")
                flag += RESET
                color = RED if m > 0 else (YELLOW if s > 0 else "")
                rcol = RESET if color else ""
                _record_result({
                    "filename": file_path.name, "filepath": str(file_path),
                    "sha256": sha256,
                    "malicious": m, "suspicious": s,
                    "undetected": stats.get("undetected", 0),
                    "harmless": stats.get("harmless", 0),
                    "engines": {k: {"category": v.get("category", ""), "result": v.get("result", "")}
                                for k, v in engines.items()},
                    "status": "scanned",
                })
                print(f"→ {flag} {color}恶意:{m} 可疑:{s}{rcol}")
            else:
                _record_result({
                    "filename": file_path.name, "filepath": str(file_path),
                    "sha256": sha256, "malicious": 0, "suspicious": 0,
                    "undetected": 0, "harmless": 0, "engines": {}, "status": "timeout",
                })
                print("→ 分析超时")

        except Exception as e:
            err_msg = str(e)
            if "配额耗尽" in err_msg:
                _record_result({
                    "filename": file_path.name, "filepath": str(file_path),
                    "sha256": sha, "malicious": 0, "suspicious": 0,
                    "undetected": 0, "harmless": 0, "engines": {},
                    "status": "quota_exhausted",
                })
                print(f"\n\n  === 配额耗尽，扫描中断 ===")
                print(f"  已扫描: {len(results)}/{len(new_files)} 个文件（不含缓存）")
                break
            _record_result({
                "filename": file_path.name, "filepath": str(file_path),
                "sha256": sha, "malicious": 0, "suspicious": 0,
                "undetected": 0, "harmless": 0, "engines": {}, "status": "error",
            })
            print(f"→ 错误: {err_msg}")

    # Step 5: 最终汇总
    all_results = skip_results + results
    _refresh_report()

    det_dir, det_count = generate_detection_reports(all_results, output_dir)

    completed = len(all_results) >= len(files)
    skipped_scan = len(skip_results)

    print(f"\n{'=' * 60}")
    print(f"  {'扫描完成！' if completed else '扫描中断（配额耗尽）'}")
    print(f"  总计: {len(files)} 个文件  |  缓存复用: {skipped_scan}  |  本次扫描: {len(results)}")
    print(f"  {RED}恶意: {sum(1 for r in all_results if r.get('malicious', 0) > 0)}{RESET}")
    print(f"  {YELLOW}可疑: {sum(1 for r in all_results if r.get('malicious', 0) == 0 and r.get('suspicious', 0) > 0)}{RESET}")
    print(f"  {GREEN}安全: {sum(1 for r in all_results if r.get('malicious', 0) == 0 and r.get('suspicious', 0) == 0)}{RESET}")
    print(f"  ─────────────────────────────")
    print(f"  {key_mgr.quota_status()}")
    print(f"  项目目录: {output_dir}")
    print(f"  HTML 报告: {report_path}")
    print(f"  JSON 数据: {json_path}")
    if det_count > 0:
        print(f"  报毒详情: {det_dir}")
    print(f"{'=' * 60}\n")

    pause_ctrl.stop()


if __name__ == "__main__":
    main()
