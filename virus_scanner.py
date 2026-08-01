#!/usr/bin/env python3
"""
VirusTotal 批量扫描工具 v2.0
手动选择文件夹 → 过滤病毒载体文件 → 上传 VirusTotal 扫描 → 生成 HTML 报告
优化：本地缓存 + 免费操作不计配额 + 渐进式轮询 + 首请求免空等

功能：
  - 支持多 API Key 池，配额耗尽自动切换
  - 支持 Key 文档（每行一个 key），自动加载
  - 严格的速率限制 & 日/月配额管控

依赖: pip install requests

用法:
  python virus_scanner.py                              # 交互模式
  python virus_scanner.py -k YOUR_KEY                  # 临时 key
  python virus_scanner.py -k YOUR_KEY --save-key       # 添加 key 到池
  python virus_scanner.py --add-key                    # 交互添加 key
  python virus_scanner.py --add-key YOUR_KEY            # 命令行添加 key
  python virus_scanner.py --key-file keys.txt           # 从文件加载 key 池
  python virus_scanner.py --list-keys                   # 查看 key 池状态
  python virus_scanner.py -f "D:\Downloads"             # 直接指定文件夹
"""

import os
import sys
import json
import time
import hashlib
import argparse
from datetime import datetime
from pathlib import Path

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
SCAN_CACHE_FILE = CONFIG_DIR / "scan_cache.json"     # v2.0: 本地扫描缓存
OUTPUT_DIR = CONFIG_DIR / "scan_reports"

VT_API_BASE = "https://www.virustotal.com/api/v3"

# ===== VirusTotal 公共 API 配额（官方限制）=====
RATE_LIMIT_PER_MINUTE = 4             # 每分钟 4 次查询
RATE_LIMIT_INTERVAL = 60.0 / RATE_LIMIT_PER_MINUTE  # 每次请求间隔 15 秒
DAILY_QUOTA = 500                     # 每日 500 次查询（每个 key）
MONTHLY_QUOTA = 155_000               # 每月 15.5 万次查询（每个 key）
MAX_FILE_SIZE = 32 * 1024 * 1024      # 32MB，超过需用 upload_url
EST_CALLS_PER_FILE = 1                # v2.0: 仅查报告扣配额，上传和轮询免费
CACHE_VALID_DAYS = 30                 # v2.0: 本地缓存有效期（天）

# v2.0: 渐进式轮询间隔（秒），最多轮询次数 = 列表长度
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


# ========== v2.0: 本地扫描缓存 ==========

def load_scan_cache():
    """加载本地扫描缓存 {sha256: {filename, result, timestamp}}"""
    if SCAN_CACHE_FILE.is_file():
        try:
            with open(SCAN_CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
    return {}

def save_scan_cache(cache):
    """保存扫描缓存到文件"""
    with open(SCAN_CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2, ensure_ascii=False)

def cache_get(sha256):
    """查缓存，返回有效结果或 None"""
    cache = load_scan_cache()
    entry = cache.get(sha256)
    if not entry:
        return None
    ts = entry.get("timestamp", 0)
    age_days = (time.time() - ts) / 86400
    if age_days > CACHE_VALID_DAYS:
        # 过期，删除并返回 None
        del cache[sha256]
        save_scan_cache(cache)
        return None
    return entry.get("result")

def cache_put(sha256, filename, result):
    """写入缓存"""
    cache = load_scan_cache()
    cache[sha256] = {
        "filename": filename,
        "result": result,
        "timestamp": time.time()
    }
    save_scan_cache(cache)


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


def check_existing_report(api_key, sha256_hash, key_mgr, filename=""):
    """检查文件是否已有分析报告（先本地缓存，再 VT API）"""
    # v2.0: 优先查本地缓存
    cached = cache_get(sha256_hash)
    if cached:
        return cached

    try:
        resp = vt_request("GET", f"/files/{sha256_hash}", api_key, key_mgr)
        if resp.status_code == 200:
            data = resp.json()
            # 写入缓存
            cache_put(sha256_hash, filename, data)
            return data
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

def generate_detection_reports(results, output_dir, timestamp):
    """为每个报毒文件生成独立的 JSON 和 MD 文件"""
    detections_dir = output_dir / f"detections_{timestamp}"
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
    parser.add_argument("--report-filter", default=None, metavar="SCAN_DATA_JSON",
                        help="从已有 scan_data JSON 筛选报毒文件，生成仅含报毒项的 HTML 报告")
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

    # ----- 扫描流程 -----

    print("\n" + "=" * 60)
    print("   VirusTotal 批量文件扫描工具")
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
        # 混合模式：-p 可指定文件和文件夹
        print(f"\n[扫描目标] 共 {len(args.path)} 个路径")
        files, skipped_text = collect_targets(args.path)
        source_desc = ", ".join(str(Path(p).name) for p in args.path[:5])
        if len(args.path) > 5:
            source_desc += f" 等 {len(args.path)} 项"
    elif args.folder:
        folder = Path(args.folder)
        if not folder.is_dir():
            print(f"\n[错误] 指定路径不是有效目录: {args.folder}")
            sys.exit(1)
        print(f"\n[扫描目录] {folder}")
        files, skipped_text = scan_folder(folder)
        source_desc = folder.name
    else:
        folder = select_folder()
        print(f"\n[扫描目录] {folder}")
        files, skipped_text = scan_folder(folder)
        source_desc = folder.name
    print(f"  找到 {len(files)} 个待扫描文件，跳过 {len(skipped_text)} 个文本类文件")

    # 按优先级排序：exe > dll > bin > ...
    sort_by_priority(files)

    if not files:
        print("\n  未发现需要扫描的文件，程序退出。")
        return

    # Step 3.5: 配额预估
    est_calls = len(files) * EST_CALLS_PER_FILE
    daily_r = key_mgr.daily_remaining()
    monthly_r = key_mgr.monthly_remaining()
    print(f"\n[配额预估] 约需 {est_calls} 次 API 调用（每文件 ~{EST_CALLS_PER_FILE} 次）")
    print(f"  当前 Key 日剩余: {daily_r}  月剩余: {monthly_r}")

    if est_calls > daily_r and len(key_mgr.keys) < 2:
        print(f"\n  ⚠ 预估调用量 ({est_calls}) 超过当前 Key 日剩余配额 ({daily_r})")
        print(f"  建议: --add-key 添加更多 Key 实现自动切换，或等到配额重置")
        confirm = input("\n  是否仍要继续？[y/N]: ").strip().lower()
        if confirm != "y":
            print("  已取消扫描。")
            return

    # 列出待扫描文件
    print("\n待扫描文件列表:")
    for i, f in enumerate(files, 1):
        size_kb = f.stat().st_size / 1024
        print(f"  {i:>3}. {f.name} ({size_kb:.1f} KB)")
    print(f"\n预计耗时: 约 {len(files) * RATE_LIMIT_INTERVAL / 60:.1f} 分钟（仅报告查询，上传和轮询不计入 API 配额）")
    print(f"速率限制: {RATE_LIMIT_PER_MINUTE} 次/分钟  |  日配额: {DAILY_QUOTA} 次  |  月配额: {MONTHLY_QUOTA/1000:.0f}K 次\n")

    # Step 4: 逐个扫描（实时更新报告）
    results = []
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = OUTPUT_DIR / f"scan_data_{timestamp}.json"
    report_path = OUTPUT_DIR / f"scan_report_{timestamp}.html"
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    def _refresh_report():
        """每扫完一个文件立即刷新报告，确保中断时不留空白"""
        html = generate_html_report(results, source_desc, len(skipped_text))
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html)
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

    def _record_result(result, msg=""):
        results.append(result)
        print(msg, flush=True)
        _refresh_report()

    for i, file_path in enumerate(files, 1):
        api_key = key_mgr.current_key()
        print(f"[{i}/{len(files)}] {file_path.name} ...", end=" ", flush=True)

        try:
            sha256 = file_sha256(file_path)

            # 先查已有报告
            existing = check_existing_report(api_key, sha256, key_mgr, file_path.name)
            if existing:
                attrs = existing.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                engines = attrs.get("last_analysis_results", {})
                _record_result({
                    "filename": file_path.name, "filepath": str(file_path),
                    "sha256": sha256,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "undetected": stats.get("undetected", 0),
                    "harmless": stats.get("harmless", 0),
                    "engines": {k: {"category": v.get("category", ""), "result": v.get("result", "")}
                                for k, v in engines.items()},
                    "status": "existing_report",
                }, f"已有报告 → 恶意:{stats.get('malicious', 0)} 可疑:{stats.get('suspicious', 0)}")
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
                }, "上传失败: 未获取到分析 ID")
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
                flag = "!!" if m > 0 else ("?" if s > 0 else "OK")
                _record_result({
                    "filename": file_path.name, "filepath": str(file_path),
                    "sha256": sha256,
                    "malicious": m, "suspicious": s,
                    "undetected": stats.get("undetected", 0),
                    "harmless": stats.get("harmless", 0),
                    "engines": {k: {"category": v.get("category", ""), "result": v.get("result", "")}
                                for k, v in engines.items()},
                    "status": "scanned",
                }, f"→ {flag} 恶意:{m} 可疑:{s}")
            else:
                _record_result({
                    "filename": file_path.name, "filepath": str(file_path),
                    "sha256": sha256, "malicious": 0, "suspicious": 0,
                    "undetected": 0, "harmless": 0, "engines": {}, "status": "timeout",
                }, "→ 分析超时")

        except Exception as e:
            err_msg = str(e)
            if "配额耗尽" in err_msg:
                _record_result({
                    "filename": file_path.name, "filepath": str(file_path),
                    "sha256": sha256 if 'sha256' in dir() else "", "malicious": 0, "suspicious": 0,
                    "undetected": 0, "harmless": 0, "engines": {},
                    "status": "quota_exhausted",
                })
                print(f"\n\n  === 配额耗尽，扫描中断 ===")
                print(f"  已扫描: {len(results)}/{len(files)} 个文件")
                remaining = len(files) - i
                if remaining > 0:
                    print(f"  未扫描: {remaining} 个文件")
                break
            _record_result({
                "filename": file_path.name, "filepath": str(file_path),
                "sha256": sha256 if 'sha256' in dir() else "", "malicious": 0, "suspicious": 0,
                "undetected": 0, "harmless": 0, "engines": {}, "status": "error",
            }, f"→ 错误: {err_msg}")

    # Step 5: 生成报毒详情（报告已在 Step 4 中实时更新）
    print("\n[生成报毒详情] ...")

    det_dir, det_count = generate_detection_reports(results, OUTPUT_DIR, timestamp)

    completed = len(results) >= len(files)
    print(f"\n{'=' * 60}")
    print(f"  {'扫描完成！' if completed else '扫描中断（配额耗尽）'}")
    print(f"  已扫描: {len(results)}/{len(files)} 个文件")
    print(f"  恶意文件: {sum(1 for r in results if r.get('malicious', 0) > 0)}")
    print(f"  可疑文件: {sum(1 for r in results if r.get('malicious', 0) == 0 and r.get('suspicious', 0) > 0)}")
    print(f"  安全文件: {sum(1 for r in results if r.get('malicious', 0) == 0 and r.get('suspicious', 0) == 0)}")
    if not completed:
        print(f"  未扫描: {len(files) - len(results)} 个（添加 Key 后重跑可续扫）")
    print(f"  ─────────────────────────────")
    print(f"  {key_mgr.quota_status()}")
    print(f"  HTML 报告: {report_path}")
    print(f"  JSON 数据: {json_path}")
    if det_count > 0:
        print(f"  报毒详情: {det_dir}")
    print(f"{'=' * 60}\n")


if __name__ == "__main__":
    main()
