#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VirusTotal Scanner GUI —— 商业化桌面客户端
整合 virus_scanner.py 与 generate_fp_emails.py 全部功能：
扫描、Key 管理、报告、Excel 导出、申诉邮件、缓存管理。

运行: python virus_gui.py
打包: pyinstaller --onefile --windowed --name "VirusTotalScanner" virus_gui.py
"""

import io
import os
import sys
import json
import queue
import time
import threading
import webbrowser
from datetime import datetime
from pathlib import Path

# ---- 确保同目录模块可导入（开发模式与打包模式均适用）----
if getattr(sys, "frozen", False):
    _APP_DIR = Path(sys.executable).parent
    sys.path.insert(0, str(_APP_DIR))
else:
    _APP_DIR = Path(__file__).parent
    sys.path.insert(0, str(_APP_DIR))

import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import virus_scanner as vs
import generate_fp_emails as gfe

# ============ 配色常量（Notion 风格）============
COLOR_PRIMARY = "#2383e2"        # Notion 蓝（链接/强调）
COLOR_PRIMARY_HOVER = "#1a6fc0"
COLOR_SIDEBAR = "#f7f7f5"        # 侧栏浅灰白
COLOR_SIDEBAR_HOVER = "#efefec"  # 侧栏悬停
COLOR_BG = "#ffffff"             # 页面背景（白）
COLOR_CARD = "#ffffff"           # 卡片背景
COLOR_CARD_ALT = "#fbfbfa"       # 卡片浅灰底（callout 风格）
COLOR_TEXT = "#37352f"           # Notion 主文字
COLOR_TEXT_MUTED = "#787774"     # Notion 次级文字
COLOR_DANGER = "#d44c47"
COLOR_WARNING = "#dfab2e"
COLOR_SUCCESS = "#448361"

APP_NAME = "VirusTotal Scanner"
APP_VERSION = "v5.0"



class _QueueStream(io.StringIO):
    """把后台线程中的 print 输出重定向到 GUI 日志队列"""

    def __init__(self, queue_ref):
        super().__init__()
        self._q = queue_ref

    def write(self, s):
        if s and s.strip():
            self._q.put(("log", s, None))
        return len(s)

    def flush(self):
        pass


class VirusScannerGUI:
    def __init__(self, root: ttk.Window):
        self.root = root
        self.log_q = queue.Queue()
        self.progress_q = queue.Queue()
        self.worker = None
        self.pause_event = threading.Event()
        self.pause_event.set()          # set = 运行
        self.stop_event = threading.Event()

        # 扫描状态
        self.scan_running = False
        self.scan_paused = False
        self.current_scan_paths = []
        self.current_results = []
        self.current_output_dir = None
        self.current_no_cache = False
        self.current_full_scan = False

        # 邮件状态
        self.email_queue = []           # 待发送邮件列表
        self.email_running = False

        # 报告预览状态：刷新项目列表期间屏蔽选中事件，避免重复生成
        self._refreshing_projects = False

        self._init_window()
        self._build_sidebar()
        self._build_pages()
        self._bind_events()
        self._refresh_quota_bar()
        self.refresh_keys()
        self.refresh_projects()
        self.refresh_cache_stats()
        self._poll_queues()

    # ============================================================
    #  窗口与布局
    # ============================================================
    def _init_window(self):
        self.root.title(f"{APP_NAME} {APP_VERSION}")
        self.root.geometry("1320x860")
        self.root.minsize(1120, 720)
        self.root.style.theme_use("flatly")
        self.root.configure(bg=COLOR_BG)
        self._style_widgets()

    def _style_widgets(self):
        style = self.root.style
        style.configure("Sidebar.TFrame", background=COLOR_SIDEBAR)
        style.configure("Card.TFrame", background=COLOR_CARD)
        style.configure("CardAlt.TFrame", background=COLOR_CARD_ALT)
        style.configure("CardTitle.TLabel", background=COLOR_CARD, foreground=COLOR_TEXT,
                        font=("Segoe UI", 14, "bold"))
        style.configure("CardSub.TLabel", background=COLOR_CARD, foreground=COLOR_TEXT_MUTED,
                        font=("Segoe UI", 9))
        style.configure("PageTitle.TLabel", background=COLOR_BG, foreground=COLOR_TEXT,
                        font=("Segoe UI", 26, "bold"))
        style.configure("PageSub.TLabel", background=COLOR_BG, foreground=COLOR_TEXT_MUTED,
                        font=("Segoe UI", 11))

        # 侧边导航：浅色悬停/选中
        style.configure("Nav.TButton", font=("Segoe UI", 11),
                        padding=(14, 9), anchor="w", background=COLOR_SIDEBAR,
                        foreground=COLOR_TEXT, borderwidth=0)
        style.map("Nav.TButton",
                  background=[("active", COLOR_SIDEBAR_HOVER)],
                  foreground=[("active", COLOR_TEXT)])
        style.configure("NavActive.TButton", font=("Segoe UI", 11, "bold"),
                        padding=(14, 9), anchor="w", background=COLOR_SIDEBAR_HOVER,
                        foreground=COLOR_TEXT, borderwidth=0)
        style.map("NavActive.TButton",
                  background=[("active", COLOR_SIDEBAR_HOVER)],
                  foreground=[("active", COLOR_TEXT)])

        # 按钮：主操作为 Notion 黑底白字，次级为浅灰
        style.configure("Primary.TButton", font=("Segoe UI", 10, "bold"),
                        padding=(16, 8), background="#37352f", foreground="#ffffff", borderwidth=0)
        style.map("Primary.TButton",
                  background=[("active", "#2f2c28"), ("disabled", "#d3d1cb")],
                  foreground=[("active", "#ffffff"), ("disabled", "#ffffff")])
        style.configure("Outline.TButton", font=("Segoe UI", 10),
                        padding=(12, 8), background=COLOR_SIDEBAR_HOVER,
                        foreground=COLOR_TEXT, borderwidth=0)
        style.map("Outline.TButton",
                  background=[("active", "#e4e4e0")],
                  foreground=[("active", COLOR_TEXT)])

        style.configure("NavTitle.TLabel", background=COLOR_SIDEBAR, foreground=COLOR_TEXT_MUTED,
                        font=("Segoe UI", 9))
        style.configure("LogoIcon.TLabel", background=COLOR_SIDEBAR, foreground=COLOR_TEXT,
                        font=("Segoe UI", 17, "bold"))
        style.configure("LogoText.TLabel", background=COLOR_SIDEBAR, foreground=COLOR_TEXT,
                        font=("Segoe UI", 14, "bold"))

        style.configure("Quota.TLabel", background=COLOR_BG, foreground=COLOR_TEXT_MUTED,
                        font=("Segoe UI", 9))
        style.configure("QuotaGood.TLabel", background=COLOR_BG, foreground=COLOR_TEXT,
                        font=("Segoe UI", 9, "bold"))
        style.configure("QuotaWarn.TLabel", background=COLOR_BG, foreground=COLOR_WARNING,
                        font=("Segoe UI", 9, "bold"))

        style.configure("Stat.TLabel", background=COLOR_CARD, foreground=COLOR_TEXT,
                        font=("Segoe UI", 26, "bold"))
        style.configure("StatTitle.TLabel", background=COLOR_CARD, foreground=COLOR_TEXT_MUTED,
                        font=("Segoe UI", 9))
        style.configure("StatBox.TFrame", background=COLOR_CARD_ALT, padding=14)

        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"),
                        background=COLOR_BG, foreground=COLOR_TEXT_MUTED)
        style.configure("Treeview", font=("Segoe UI", 9), rowheight=28,
                        background=COLOR_BG, fieldbackground=COLOR_BG, foreground=COLOR_TEXT)

    def _build_sidebar(self):
        self.sidebar = ttk.Frame(self.root, width=240, style="Sidebar.TFrame")
        self.sidebar.pack(side=LEFT, fill=Y)
        self.sidebar.pack_propagate(False)

        # Logo 区
        logo = ttk.Frame(self.sidebar, style="Sidebar.TFrame")
        logo.pack(fill=X, padx=20, pady=(26, 20))
        ttk.Label(logo, text="VT", style="LogoIcon.TLabel").pack(side=LEFT)
        ttk.Label(logo, text="Scanner Pro", style="LogoText.TLabel").pack(side=LEFT, padx=(12, 0))

        ttk.Label(self.sidebar, text="批量扫描 · 误报申诉 · 报告管理",
                  style="NavTitle.TLabel").pack(anchor=W, padx=24, pady=(0, 14))

        self.nav_buttons = {}
        nav_items = [
            ("dashboard", "工作台"),
            ("scan", "扫描中心"),
            ("report", "报告中心"),
            ("email", "邮件申诉"),
            ("keys", "密钥管理"),
            ("cache", "缓存设置"),
        ]
        for key, text in nav_items:
            btn = ttk.Button(self.sidebar, text=text, style="Nav.TButton",
                             command=lambda k=key: self.show_page(k))
            btn.pack(fill=X, padx=12, pady=3)
            self.nav_buttons[key] = btn

        ttk.Label(self.sidebar, text=f"{APP_NAME} {APP_VERSION}",
                  style="NavTitle.TLabel").pack(side=BOTTOM, pady=16)

        # 顶部配额条
        self.quota_bar = ttk.Frame(self.root, style="Card.TFrame")
        self.quota_bar.pack(side=TOP, fill=X, padx=20, pady=(14, 4))
        self.quota_label = ttk.Label(self.quota_bar, text="", style="Quota.TLabel")
        self.quota_label.pack(side=LEFT, padx=16, pady=9)

        self.page_container = ttk.Frame(self.root, style="Card.TFrame")
        self.page_container.pack(side=TOP, fill=BOTH, expand=True, padx=20, pady=(6, 20))

    def _build_pages(self):
        """构建所有功能页面（含工作台）"""
        self.pages = {}
        self._build_dashboard_page()
        self._build_scan_page()
        self._build_keys_page()
        self._build_report_page()
        self._build_email_page()
        self._build_cache_page()
        self.show_page("dashboard")

    def _new_page(self):
        """创建一个占满容器的页面 Frame"""
        frame = ttk.Frame(self.page_container, style="Card.TFrame")
        frame.pack(fill=BOTH, expand=True)
        return frame

    def _card(self, parent, padding=16):
        """创建卡片容器"""
        card = ttk.Frame(parent, style="Card.TFrame", padding=padding,
                         bootstyle="secondary")
        return card

    # ============================================================
    #  工作台（Dashboard）
    # ============================================================
    def _build_dashboard_page(self):
        page = self._new_page()
        self.pages["dashboard"] = page

        ttk.Label(page, text="工作台", style="PageTitle.TLabel").pack(anchor=W, padx=20, pady=(18, 2))
        ttk.Label(page, text="批量文件检测与误报申诉，一站式完成", style="PageSub.TLabel").pack(anchor=W, padx=20)

        # 统计卡
        stats = ttk.Frame(page, style="Card.TFrame")
        stats.pack(fill=X, padx=20, pady=(16, 10))
        stat_items = [
            ("stat_keys", "API Key 数"),
            ("stat_quota", "今日剩余配额"),
            ("stat_projects", "扫描项目"),
            ("stat_cache", "缓存文件"),
        ]
        self.stat_labels = {}
        for idx, (attr, title) in enumerate(stat_items):
            box = ttk.Frame(stats, style="StatBox.TFrame", bootstyle="secondary")
            box.pack(side=LEFT, fill=X, expand=True, padx=(0, 10) if idx < 3 else 0)
            lbl = ttk.Label(box, text="-", style="Stat.TLabel")
            lbl.pack(anchor=W)
            ttk.Label(box, text=title, style="StatTitle.TLabel").pack(anchor=W, pady=(4, 0))
            self.stat_labels[attr] = lbl

        # 快速开始 + 最近项目
        row = ttk.Frame(page, style="Card.TFrame")
        row.pack(fill=BOTH, expand=True, padx=20, pady=(0, 10))

        quick = ttk.Frame(row, style="CardAlt.TFrame", padding=16)
        quick.pack(side=LEFT, fill=Y, padx=(0, 10), expand=False)
        ttk.Label(quick, text="快速开始", style="CardTitle.TLabel").pack(anchor=W)
        ttk.Label(quick, text="添加文件或文件夹，开始批量 VirusTotal 检测。\n报毒文件可一键生成厂商申诉邮件。",
                  style="CardSub.TLabel", justify=LEFT).pack(anchor=W, pady=(8, 14))
        ttk.Button(quick, text="▶ 前往扫描中心", style="Primary.TButton",
                   command=lambda: self.show_page("scan")).pack(anchor=W, pady=(0, 8))
        ttk.Button(quick, text="打开报告目录", style="Outline.TButton",
                   command=self.open_output_dir).pack(anchor=W)

        recent = ttk.Frame(row, style="CardAlt.TFrame", padding=16)
        recent.pack(side=LEFT, fill=BOTH, expand=True)
        rhead = ttk.Frame(recent, style="Card.TFrame")
        rhead.pack(fill=X)
        ttk.Label(rhead, text="最近项目", style="CardTitle.TLabel").pack(side=LEFT)
        ttk.Button(rhead, text="查看全部", style="Outline.TButton",
                   command=lambda: self.show_page("report")).pack(side=RIGHT)
        self.dash_recent_label = ttk.Label(recent, text="暂无扫描项目",
                                           style="CardSub.TLabel", justify=LEFT)
        self.dash_recent_label.pack(anchor=W, pady=(10, 0))

    def _refresh_dashboard(self):
        """刷新工作台统计与最近项目"""
        try:
            km = vs.ApiKeyManager()
            self.stat_labels["stat_keys"].configure(text=str(len(km.keys)))
            if km.keys:
                daily_total = 0
                for k in km.keys:
                    q = km._get_quota(k["key_id"])
                    daily_total += max(0, vs.DAILY_QUOTA - q["daily"]["count"])
                self.stat_labels["stat_quota"].configure(text=str(daily_total))
            else:
                self.stat_labels["stat_quota"].configure(text="0")
        except Exception:
            self.stat_labels["stat_quota"].configure(text="-")
        try:
            projects = []
            if vs.PROJECTS_DIR.is_dir():
                projects = [p for p in vs.PROJECTS_DIR.iterdir()
                            if p.is_dir() and (p / "scan_data.json").is_file()]
            self.stat_labels["stat_projects"].configure(text=str(len(projects)))
            if projects:
                recent = sorted(projects, key=lambda p: p.stat().st_mtime, reverse=True)[:5]
                txt_lines = []
                for p in recent:
                    try:
                        with open(p / "scan_data.json", "r", encoding="utf-8") as f:
                            data = json.load(f)
                        m = sum(1 for r in data if r.get("malicious", 0) > 0)
                        s = sum(1 for r in data if r.get("malicious", 0) == 0 and r.get("suspicious", 0) > 0)
                        mt = datetime.fromtimestamp(p.stat().st_mtime).strftime("%m-%d %H:%M")
                        badge = f"  {m}恶意/{s}可疑" if (m or s) else "  全部安全"
                        txt_lines.append(f"●  {p.name}  ·  {len(data)} 个文件{badge}  ·  {mt}")
                    except Exception:
                        continue
                self.dash_recent_label.configure(text="\n".join(txt_lines[:5]) if txt_lines else "暂无扫描项目")
            else:
                self.dash_recent_label.configure(text="暂无扫描项目")
        except Exception:
            self.stat_labels["stat_projects"].configure(text="-")
        try:
            self.stat_labels["stat_cache"].configure(text=str(len(vs.load_scan_cache())))
        except Exception:
            self.stat_labels["stat_cache"].configure(text="-")

    # ============================================================
    #  扫描中心
    # ============================================================
    def _build_scan_page(self):
        page = self._new_page()
        self.pages["scan"] = page

        ttk.Label(page, text="扫描中心", style="PageTitle.TLabel").pack(anchor=W, padx=20, pady=(18, 2))
        ttk.Label(page, text="选择待扫描文件或文件夹，批量上传 VirusTotal 检测", style="PageSub.TLabel").pack(anchor=W, padx=20)

        # 目标选择卡片
        card = self._card(page)
        card.pack(fill=X, padx=20, pady=(16, 10))
        top = ttk.Frame(card, style="Card.TFrame")
        top.pack(fill=X)
        ttk.Label(top, text="扫描目标", style="CardTitle.TLabel").pack(side=LEFT)
        ttk.Button(top, text="+ 添加文件夹", style="Outline.TButton",
                   command=self.add_folder).pack(side=RIGHT, padx=(6, 0))
        ttk.Button(top, text="+ 添加文件", style="Outline.TButton",
                   command=self.add_files).pack(side=RIGHT, padx=(6, 0))
        ttk.Button(top, text="移除选中", style="Outline.TButton",
                   command=self.remove_selected_target).pack(side=RIGHT, padx=(6, 0))
        ttk.Button(top, text="清空", style="Outline.TButton",
                   command=self.clear_targets).pack(side=RIGHT)

        cols = ("path", "type", "size")
        self.target_tree = ttk.Treeview(card, columns=cols, show="headings", height=5,
                                        bootstyle="light")
        for c, t, w, an in [("path", "路径", 620, W), ("type", "类型", 90, CENTER),
                            ("size", "大小", 110, E)]:
            self.target_tree.heading(c, text=t)
            self.target_tree.column(c, width=w, anchor=an)
        self.target_tree.pack(fill=X, pady=(10, 6))

        # 选项行
        opt = ttk.Frame(card, style="Card.TFrame")
        opt.pack(fill=X, pady=(4, 0))
        ttk.Label(opt, text="项目名称", style="CardSub.TLabel").pack(side=LEFT)
        self.project_var = ttk.StringVar()
        self._auto_project_name = ""   # 上次自动生成的项目名，用于判断用户是否手动改过
        self._proj_entry = ttk.Entry(opt, textvariable=self.project_var, width=30)
        self._proj_entry.pack(side=LEFT, padx=(8, 24))
        self.no_cache_var = ttk.BooleanVar(value=False)
        self.no_cache_chk = ttk.Checkbutton(opt, text="忽略本地缓存，强制重新扫描",
                                            variable=self.no_cache_var, bootstyle="round-toggle")
        self.no_cache_chk.pack(side=LEFT)
        self.full_scan_var = ttk.BooleanVar(value=False)
        self.full_scan_chk = ttk.Checkbutton(opt, text="全量扫描（含文本类文件）",
                                             variable=self.full_scan_var, bootstyle="round-toggle",
                                             command=self._on_full_scan_toggle)
        self.full_scan_chk.pack(side=LEFT, padx=(22, 0))

        # 操作区
        action = ttk.Frame(page, style="Card.TFrame")
        action.pack(fill=X, padx=20, pady=(0, 10))
        self.start_btn = ttk.Button(action, text="开始扫描", style="Primary.TButton",
                                    command=self.start_scan)
        self.start_btn.pack(side=LEFT)
        self.pause_btn = ttk.Button(action, text="暂停", style="Outline.TButton",
                                    command=self.pause_scan, state=DISABLED)
        self.pause_btn.pack(side=LEFT, padx=(10, 0))
        self.stop_btn = ttk.Button(action, text="停止", style="Outline.TButton",
                                   command=self.stop_scan, state=DISABLED)
        self.stop_btn.pack(side=LEFT, padx=(10, 0))
        ttk.Button(action, text="打开报告目录", style="Outline.TButton",
                   command=self.open_output_dir).pack(side=RIGHT)

        # 进度
        prog_card = self._card(page)
        prog_card.pack(fill=X, padx=20, pady=(0, 10))
        self.progress_bar = ttk.Progressbar(prog_card, maximum=100, value=0,
                                            bootstyle="primary-striped")
        self.progress_bar.pack(fill=X)
        self.status_label = ttk.Label(prog_card, text="就绪", style="CardSub.TLabel")
        self.status_label.pack(anchor=W, pady=(6, 0))

        # 日志区
        log_card = self._card(page)
        log_card.pack(fill=BOTH, expand=True, padx=20)
        log_head = ttk.Frame(log_card, style="Card.TFrame")
        log_head.pack(fill=X)
        ttk.Label(log_head, text="实时日志", style="CardTitle.TLabel").pack(side=LEFT)
        ttk.Button(log_head, text="清空日志", style="Outline.TButton",
                   command=self.clear_log).pack(side=RIGHT)
        self.log_text = ttk.Text(log_card, height=10, font=("Cascadia Mono", 9),
                                 wrap="word", state=DISABLED, background="#f7f7f5",
                                 foreground="#37352f")
        self.log_text.pack(fill=BOTH, expand=True, pady=(8, 0))

    # ============================================================
    #  密钥管理
    # ============================================================
    def _build_keys_page(self):
        page = self._new_page()
        self.pages["keys"] = page
        ttk.Label(page, text="密钥管理", style="PageTitle.TLabel").pack(anchor=W, padx=20, pady=(18, 2))
        ttk.Label(page, text="管理 VirusTotal API Key 池，配额耗尽自动切换", style="PageSub.TLabel").pack(anchor=W, padx=20)

        card = self._card(page)
        card.pack(fill=X, padx=20, pady=(16, 10))
        top = ttk.Frame(card, style="Card.TFrame")
        top.pack(fill=X)
        ttk.Label(top, text="添加 Key", style="CardTitle.TLabel").pack(side=LEFT)
        self.key_entry = ttk.Entry(top, width=56)
        self.key_entry.pack(side=LEFT, padx=(12, 8))
        ttk.Button(top, text="添加", style="Primary.TButton", command=self.add_key).pack(side=LEFT)
        ttk.Button(top, text="从文件加载", style="Outline.TButton", command=self.load_key_file).pack(side=LEFT, padx=(8, 0))

        self.key_tree = ttk.Treeview(card, columns=("idx", "label", "keyid", "daily", "monthly", "active"),
                                     show="headings", height=7, bootstyle="light")
        for c, t, w in [("idx", "#", 40), ("label", "标签", 120), ("keyid", "Key ID", 130),
                        ("daily", "今日剩余", 100), ("monthly", "本月剩余", 110), ("active", "状态", 80)]:
            self.key_tree.heading(c, text=t)
            self.key_tree.column(c, width=w, anchor=CENTER if c in ("idx", "active") else W)
        self.key_tree.pack(fill=X, pady=(10, 6))

        btns = ttk.Frame(card, style="Card.TFrame")
        btns.pack(fill=X)
        ttk.Button(btns, text="设为当前", style="Outline.TButton", command=self.set_active_key).pack(side=LEFT)
        ttk.Button(btns, text="删除选中", style="Outline.TButton", command=self.remove_key).pack(side=LEFT, padx=(8, 0))
        ttk.Button(btns, text="刷新状态", style="Outline.TButton", command=self.refresh_keys).pack(side=LEFT, padx=(8, 0))

        tip = self._card(page)
        tip.pack(fill=X, padx=20, pady=(0, 10))
        ttk.Label(tip, text="提示：VirusTotal 免费 API Key 限额为 500 次/天、15.5 万次/月、4 次/分钟。多 Key 池可在单个 Key 限速时自动切换，提升扫描吞吐。",
                  style="CardSub.TLabel").pack(anchor=W)

    # ============================================================
    #  报告中心
    # ============================================================
    def _build_report_page(self):
        page = self._new_page()
        self.pages["report"] = page
        ttk.Label(page, text="报告中心", style="PageTitle.TLabel").pack(anchor=W, padx=20, pady=(18, 2))
        ttk.Label(page, text="查看历史扫描项目，导出报毒清单与筛选报告", style="PageSub.TLabel").pack(anchor=W, padx=20)

        card = self._card(page)
        card.pack(fill=X, padx=20, pady=(16, 10))
        top = ttk.Frame(card, style="Card.TFrame")
        top.pack(fill=X)
        ttk.Label(top, text="扫描项目", style="CardTitle.TLabel").pack(side=LEFT)
        ttk.Button(top, text="刷新", style="Outline.TButton", command=self.refresh_projects).pack(side=RIGHT)

        cols = ("name", "files", "mal", "sus", "safe", "time", "path")
        self.project_tree = ttk.Treeview(card, columns=cols, show="headings", height=8,
                                         bootstyle="light")
        for c, t, w in [("name", "项目", 160), ("files", "文件数", 70), ("mal", "恶意", 60),
                        ("sus", "可疑", 60), ("safe", "安全", 60), ("time", "更新时间", 140),
                        ("path", "目录", 320)]:
            self.project_tree.heading(c, text=t)
            self.project_tree.column(c, width=w, anchor=CENTER if c in ("files", "mal", "sus", "safe") else W)
        self.project_tree.pack(fill=X, pady=(10, 6))
        self.project_tree.bind("<Double-1>", lambda e: self.open_project_dir())
        self.project_tree.bind("<<TreeviewSelect>>", lambda e: self.text_report(auto=True))

        btns = ttk.Frame(card, style="Card.TFrame")
        btns.pack(fill=X)
        ttk.Button(btns, text="打开 HTML 报告", style="Primary.TButton", command=self.open_html_report).pack(side=LEFT)
        ttk.Button(btns, text="打开项目目录", style="Outline.TButton", command=self.open_project_dir).pack(side=LEFT, padx=(8, 0))
        ttk.Button(btns, text="导出报毒 Excel", style="Outline.TButton", command=self.export_excel).pack(side=LEFT, padx=(8, 0))
        ttk.Button(btns, text="生成报毒筛选报告", style="Outline.TButton", command=self.filter_report).pack(side=LEFT, padx=(8, 0))
        ttk.Button(btns, text="生成报毒测试报告", style="Outline.TButton", command=self.text_report).pack(side=LEFT, padx=(8, 0))

        detail_card = self._card(page)
        detail_card.pack(fill=BOTH, expand=True, padx=20)
        detail_head = ttk.Frame(detail_card, style="Card.TFrame")
        detail_head.pack(fill=X)
        ttk.Label(detail_head, text="报毒测试报告预览", style="CardTitle.TLabel").pack(side=LEFT)
        self.report_meta_label = ttk.Label(detail_head, text="", style="CardSub.TLabel")
        self.report_meta_label.pack(side=RIGHT)

        detail_body = ttk.Frame(detail_card, style="Card.TFrame")
        detail_body.pack(fill=BOTH, expand=True, pady=(8, 0))
        self.report_text = ttk.Text(detail_body, height=12, font=("Cascadia Mono", 9),
                                    wrap="word", state=DISABLED, background="#f7f7f5",
                                    foreground="#37352f", borderwidth=0)
        report_scroll = ttk.Scrollbar(detail_body, orient="vertical", command=self.report_text.yview)
        self.report_text.configure(yscrollcommand=report_scroll.set)
        self.report_text.pack(side=LEFT, fill=BOTH, expand=True)
        report_scroll.pack(side=RIGHT, fill=Y)
        self._set_report_preview("从上方列表选择一个扫描项目，这里会自动生成报毒测试报告。\n")

    # ============================================================
    #  邮件申诉
    # ============================================================
    def _build_email_page(self):
        page = self._new_page()
        self.pages["email"] = page
        ttk.Label(page, text="误报申诉邮件", style="PageTitle.TLabel").pack(anchor=W, padx=20, pady=(18, 2))
        ttk.Label(page, text="从扫描结果生成厂商申诉邮件，支持 GitHub 样本上传与 SMTP 发送", style="PageSub.TLabel").pack(anchor=W, padx=20)

        # SMTP 配置卡片
        card = self._card(page)
        card.pack(fill=X, padx=20, pady=(16, 10))
        ttk.Label(card, text="SMTP 配置", style="CardTitle.TLabel").pack(anchor=W)
        row1 = ttk.Frame(card, style="Card.TFrame")
        row1.pack(fill=X, pady=(8, 4))
        ttk.Label(row1, text="服务器", style="CardSub.TLabel").pack(side=LEFT)
        self.smtp_host = ttk.Entry(row1, width=28)
        self.smtp_host.pack(side=LEFT, padx=(8, 24))
        ttk.Label(row1, text="端口", style="CardSub.TLabel").pack(side=LEFT)
        self.smtp_port = ttk.Entry(row1, width=10)
        self.smtp_port.pack(side=LEFT, padx=(8, 24))
        ttk.Label(row1, text="授权码", style="CardSub.TLabel").pack(side=LEFT)
        self.smtp_auth = ttk.Entry(row1, width=32, show="*")
        self.smtp_auth.pack(side=LEFT, padx=(8, 10))
        ttk.Button(row1, text="保存", style="Outline.TButton", command=self.save_smtp_config).pack(side=LEFT)

        # 数据源与生成
        card2 = self._card(page)
        card2.pack(fill=X, padx=20, pady=(0, 10))
        ttk.Label(card2, text="生成邮件队列", style="CardTitle.TLabel").pack(anchor=W)
        row2 = ttk.Frame(card2, style="Card.TFrame")
        row2.pack(fill=X, pady=(8, 6))
        ttk.Label(row2, text="数据源", style="CardSub.TLabel").pack(side=LEFT)
        self.email_src_entry = ttk.Entry(row2, width=70)
        self.email_src_entry.pack(side=LEFT, padx=(8, 8))
        ttk.Button(row2, text="选择", style="Outline.TButton", command=self.choose_email_source).pack(side=LEFT)
        ttk.Button(row2, text="生成邮件队列", style="Primary.TButton", command=self.generate_emails).pack(side=LEFT, padx=(8, 0))

        cols = ("sel", "file", "engine", "threat", "recipient", "status")
        self.email_tree = ttk.Treeview(card2, columns=cols, show="headings", height=5,
                                       bootstyle="light")
        for c, t, w in [("sel", "发送", 50), ("file", "文件", 200), ("engine", "引擎", 130),
                        ("threat", "报毒名", 180), ("recipient", "收件人", 220), ("status", "状态", 90)]:
            self.email_tree.heading(c, text=t)
            self.email_tree.column(c, width=w, anchor=CENTER if c in ("sel", "status") else W)
        self.email_tree.pack(fill=X, pady=(6, 6))
        self.email_tree.bind("<Button-1>", self._on_email_tree_click)

        row3 = ttk.Frame(card2, style="Card.TFrame")
        row3.pack(fill=X)
        ttk.Button(row3, text="一键申诉（生成+上传+发送）", style="Primary.TButton",
                   command=self.one_click_appeal).pack(side=LEFT)
        ttk.Button(row3, text="全选 / 取消全选", style="Outline.TButton",
                   command=self.toggle_all_emails).pack(side=LEFT, padx=(8, 0))
        ttk.Button(row3, text="发送选中邮件", style="Outline.TButton",
                   command=self.send_selected_emails).pack(side=LEFT, padx=(8, 0))
        ttk.Button(row3, text="仅生成文件（不发送）", style="Outline.TButton",
                   command=self.export_email_files).pack(side=LEFT, padx=(8, 0))

        # 申诉进度：GitHub 样本上传 / 邮件发送共用
        prog_row = ttk.Frame(card2, style="Card.TFrame")
        prog_row.pack(fill=X, pady=(10, 0))
        self.email_progress = ttk.Progressbar(prog_row, maximum=100, value=0,
                                              bootstyle="primary-striped")
        self.email_progress.pack(fill=X)
        self.email_status_label = ttk.Label(prog_row, text="就绪", style="CardSub.TLabel")
        self.email_status_label.pack(anchor=W, pady=(4, 0))

        log_card = self._card(page)
        log_card.pack(fill=BOTH, expand=True, padx=20)
        ttk.Label(log_card, text="邮件日志", style="CardTitle.TLabel").pack(anchor=W)
        self.email_log = ttk.Text(log_card, height=8, font=("Cascadia Mono", 9),
                                  wrap="word", state=DISABLED, background="#f7f7f5",
                                  foreground="#37352f")
        self.email_log.pack(fill=BOTH, expand=True, pady=(8, 0))

    # ============================================================
    #  缓存与设置
    # ============================================================
    def _build_cache_page(self):
        page = self._new_page()
        self.pages["cache"] = page
        ttk.Label(page, text="缓存与设置", style="PageTitle.TLabel").pack(anchor=W, padx=20, pady=(18, 2))
        ttk.Label(page, text="管理本地扫描缓存与申诉记录", style="PageSub.TLabel").pack(anchor=W, padx=20)

        card = self._card(page)
        card.pack(fill=X, padx=20, pady=(16, 10))
        ttk.Label(card, text="扫描缓存（scan_cache.json）", style="CardTitle.TLabel").pack(anchor=W)
        self.cache_stats_label = ttk.Label(card, text="", style="CardSub.TLabel")
        self.cache_stats_label.pack(anchor=W, pady=(8, 4))
        row = ttk.Frame(card, style="Card.TFrame")
        row.pack(fill=X)
        ttk.Button(row, text="刷新统计", style="Outline.TButton", command=self.refresh_cache_stats).pack(side=LEFT)
        ttk.Button(row, text="清空扫描缓存", style="Outline.TButton", command=self.clear_scan_cache).pack(side=LEFT, padx=(8, 0))

        card2 = self._card(page)
        card2.pack(fill=X, padx=20, pady=(0, 10))
        ttk.Label(card2, text="已申诉记录（declared_cache.json）", style="CardTitle.TLabel").pack(anchor=W)
        self.declared_stats_label = ttk.Label(card2, text="", style="CardSub.TLabel")
        self.declared_stats_label.pack(anchor=W, pady=(8, 4))
        row2 = ttk.Frame(card2, style="Card.TFrame")
        row2.pack(fill=X)
        ttk.Button(row2, text="刷新统计", style="Outline.TButton", command=self.refresh_cache_stats).pack(side=LEFT)
        ttk.Button(row2, text="清空已申诉记录", style="Outline.TButton", command=self.clear_declared).pack(side=LEFT, padx=(8, 0))

        about = self._card(page)
        about.pack(fill=X, padx=20)
        ttk.Label(about, text="关于", style="CardTitle.TLabel").pack(anchor=W)
        ttk.Label(about, text=f"{APP_NAME} {APP_VERSION}\n"
                              "基于 VirusTotal Public API 的批量文件扫描与误报申诉工具。\n"
                              "数据目录：扫描项目保存在本程序目录下的 projects/，配置保存在程序目录。",
                  style="CardSub.TLabel", justify=LEFT).pack(anchor=W, pady=(8, 0))

    # ============================================================
    #  页面切换
    # ============================================================
    def show_page(self, key):
        for k, page in self.pages.items():
            page.pack_forget()
        self.pages[key].pack(fill=BOTH, expand=True)
        for k, btn in self.nav_buttons.items():
            btn.configure(style="Nav.TButton")
        self.nav_buttons[key].configure(style="NavActive.TButton")
        if key == "dashboard":
            self._refresh_dashboard()
        elif key == "keys":
            self.refresh_keys()
        elif key == "report":
            self.refresh_projects()
        elif key == "cache":
            self.refresh_cache_stats()

    def _bind_events(self):
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def _log(self, text, tag=None):
        """向主日志区追加文本"""
        self.log_q.put(("log", text, tag))

    def _email_log_line(self, text, tag=None):
        self.log_q.put(("email_log", text, tag))

    def _log_append(self, widget, text, tag=None):
        widget.configure(state=NORMAL)
        widget.insert(END, text, tag)
        # 限制日志长度：长时间扫描后文本控件会越来越卡，只保留最近 3000 行
        try:
            lines = int(str(widget.index("end-1c")).split(".")[0])
            if lines > 4000:
                widget.delete("1.0", f"{lines - 3000}.0")
        except Exception:
            pass
        widget.see(END)
        widget.configure(state=DISABLED)

    def clear_log(self):
        self.log_text.configure(state=NORMAL)
        self.log_text.delete("1.0", END)
        self.log_text.configure(state=DISABLED)

    def _poll_queues(self):
        """周期消费后台队列，更新 UI。

        关键约束：任何单条消息处理失败都不能中断轮询，否则日志/进度会永久停在第一条。
        因此逐条 try/except，并把重新排程放在 finally 里无条件执行。
        """
        try:
            # ---- 日志队列 ----
            while True:
                try:
                    item = self.log_q.get_nowait()
                except queue.Empty:
                    break
                try:
                    kind, payload, tag = item
                    if kind == "log":
                        self._log_append(self.log_text, payload, tag)
                    elif kind == "email_log":
                        self._log_append(self.email_log, payload, tag)
                    elif kind == "email_progress":
                        done, total, text = payload
                        pct = int(done / total * 100) if total else 0
                        self.email_progress.configure(value=pct)
                        if text:
                            self.email_status_label.configure(text=text)
                    elif kind == "email_status":
                        self.email_status_label.configure(text=str(payload))
                    elif kind == "email_confirm":
                        title, message = payload[0], payload[1]
                        ret = ttk.Messagebox.show_question(
                            title, message, buttons=["查看并发送", "稍后发送"], parent=self.root)
                        if ret == "查看并发送":
                            self._start_send_all()
                    elif kind == "email_msgbox":
                        title, message, mtype = payload
                        if mtype == "warning":
                            ttk.Messagebox.show_warning(title, message, parent=self.root)
                        else:
                            ttk.Messagebox.show_info(title, message, parent=self.root)
                    elif kind == "email_tree_insert_all":
                        for values in payload:
                            self.email_tree.insert("", END, values=values)
                    elif kind == "email_tree_update":
                        it, values = payload
                        self.email_tree.item(it, values=values)
                    elif kind == "status":
                        self.status_label.configure(text=payload)
                except Exception as e:
                    # 兜底：格式不匹配也照原样落到日志，绝不吞掉内容
                    try:
                        self._log_append(self.log_text, f"{item}\n", None)
                        self._log_append(self.log_text, f"[界面提示] 该条消息解析失败（已跳过）: {e}\n", None)
                    except Exception:
                        pass

            # ---- 进度队列 ----
            while True:
                try:
                    item = self.progress_q.get_nowait()
                except queue.Empty:
                    break
                try:
                    kind = item[0]
                    if kind == "progress":
                        # 兼容历史 4 元组 ("progress", done, total, name) 与 2 元组 ("progress", (done, total, name))
                        if len(item) >= 4:
                            done, total, name = item[1], item[2], item[3]
                        else:
                            done, total, name = item[1]
                        pct = int(done / total * 100) if total else 0
                        self.progress_bar.configure(value=pct, maximum=100)
                        self.status_label.configure(text=f"扫描中 {done}/{total}: {name}")
                    elif kind == "done":
                        self.progress_bar.configure(value=100)
                    elif kind == "reset":
                        self.progress_bar.configure(value=0)
                    elif kind == "status":
                        self.status_label.configure(text=str(item[1]))
                    elif kind == "finished":
                        self._scan_finished()
                except Exception as e:
                    try:
                        self._log_append(self.log_text, f"[界面提示] 进度消息处理失败（已跳过）: {e}\n", None)
                    except Exception:
                        pass
        finally:
            self.root.after(100, self._poll_queues)

    def _refresh_quota_bar(self):
        try:
            km = vs.ApiKeyManager()
            if km.keys:
                txt = f"当前 Key: [{km.current_label()}]  {km.quota_status()}"
                self.quota_label.configure(text=txt, style="QuotaGood.TLabel")
            else:
                self.quota_label.configure(text="未配置 API Key，请前往「密钥管理」添加",
                                           style="QuotaWarn.TLabel")
        except Exception:
            pass
        try:
            self._refresh_dashboard()
        except Exception:
            pass
        self.root.after(15000, self._refresh_quota_bar)


    def _run_thread(self, target):
        """启动后台线程"""
        self.worker = threading.Thread(target=target, daemon=True)
        self.worker.start()

    def _redirect_stdout(self):
        """在后台线程中重定向 stdout 到日志队列"""
        self._old_stdout = sys.stdout
        sys.stdout = _QueueStream(self.log_q)

    def _restore_stdout(self):
        sys.stdout = self._old_stdout

    def _tag(self, line):
        """根据日志内容自动配色"""
        if "恶意" in line or "失败" in line or "错误" in line or "429" in line or "限速" in line or "耗尽" in line:
            return "danger"
        if "可疑" in line or "警告" in line or "跳过" in line:
            return "warning"
        if "完成" in line or "成功" in line or "安全" in line or "OK" in line:
            return "success"
        return None

    # ============================================================
    #  扫描中心
    # ============================================================
    def _on_full_scan_toggle(self):
        """全量扫描开关：开启时强制忽略本地缓存，并禁用缓存开关避免语义冲突"""
        if self.full_scan_var.get():
            self._no_cache_saved = self.no_cache_var.get()
            self.no_cache_var.set(True)
            self.no_cache_chk.configure(state=DISABLED)
        else:
            self.no_cache_chk.configure(state=NORMAL)
            self.no_cache_var.set(getattr(self, "_no_cache_saved", False))

    def _derive_project_name(self):
        """按当前目标列表推导项目名：优先第一个文件夹名，否则取第一个文件名"""
        first_folder = None
        first_file = None
        for item in self.target_tree.get_children():
            values = self.target_tree.item(item, "values")
            if not values:
                continue
            path = Path(str(values[0]))
            kind = str(values[1]) if len(values) > 1 else ""
            if kind == "文件夹" or path.is_dir():
                if first_folder is None:
                    first_folder = path
            elif first_file is None:
                first_file = path
        target = first_folder or first_file
        return target.name if target else ""

    def _sync_project_name(self):
        """目标变化后同步项目名：字段为空或仍是上次自动值时跟随目标更新，用户自定义过则保留"""
        derived = self._derive_project_name()
        current = self.project_var.get().strip()
        if not current or current == self._auto_project_name:
            if current != derived:
                self.project_var.set(derived)
            self._auto_project_name = derived

    def add_folder(self):
        from tkinter import filedialog
        folder = filedialog.askdirectory(title="选择要扫描的文件夹")
        if folder:
            p = Path(folder)
            size = self._dir_size(p)
            self.target_tree.insert("", END, values=(str(p), "文件夹", self._fmt_size(size)))
            self._sync_project_name()

    def add_files(self):
        from tkinter import filedialog
        files = filedialog.askopenfilenames(title="选择要扫描的文件")
        for f in files:
            p = Path(f)
            self.target_tree.insert("", END, values=(str(p), "文件", self._fmt_size(p.stat().st_size)))
        if files:
            self._sync_project_name()

    @staticmethod
    def _dir_size(path: Path):
        total = 0
        try:
            for f in path.rglob("*"):
                if f.is_file():
                    total += f.stat().st_size
        except Exception:
            pass
        return total

    @staticmethod
    def _fmt_size(n):
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024:
                return f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} TB"

    def remove_selected_target(self):
        for item in self.target_tree.selection():
            self.target_tree.delete(item)
        self._sync_project_name()

    def clear_targets(self):
        for item in self.target_tree.get_children():
            self.target_tree.delete(item)
        self._sync_project_name()

    def _get_target_paths(self):
        paths = []
        for item in self.target_tree.get_children():
            values = self.target_tree.item(item, "values")
            paths.append(values[0])
        return paths

    def start_scan(self):
        if self.scan_running:
            return
        paths = self._get_target_paths()
        if not paths:
            ttk.Messagebox.show_info("请先添加扫描目标", "添加文件或文件夹后开始扫描", parent=self.root)
            return
        km = vs.ApiKeyManager()
        if not km.keys:
            ttk.Messagebox.show_info("未配置 API Key", "请先在「API Key 管理」中添加 VirusTotal API Key", parent=self.root)
            self.show_page("keys")
            return

        # 目标收集与配额预估（主线程快速执行）
        # force_files=True：用户显式添加的单个文件强制扫描，不受扩展名白名单限制
        # full_scan=True：不按扩展名过滤，目录下全部非空文件纳入
        full_scan = self.full_scan_var.get()
        files, skipped = vs.collect_targets(paths, force_files=True, full_scan=full_scan)
        vs.sort_by_priority(files)
        if not files:
            reason = ("目标中没有可扫描的文件（0 字节文件已跳过）" if full_scan
                      else "目标中没有符合扫描条件的文件（已排除文本类扩展名）")
            ttk.Messagebox.show_info("没有可扫描的文件", reason, parent=self.root)
            return

        no_cache = self.no_cache_var.get() or full_scan
        cache = vs.load_scan_cache()
        new_files = [f for f in files if no_cache or vs.file_sha256(f) not in cache]
        est = len(new_files) * vs.EST_CALLS_PER_FILE
        daily_r = km.daily_remaining()
        if est > daily_r and len(km.keys) < 2:
            ret = ttk.Messagebox.show_question(
                "配额预估不足",
                f"预计需要 {est} 次 API 调用，当前 Key 日剩余 {daily_r} 次。\n\n是否仍要继续？",
                buttons=["是", "否"],
                parent=self.root)
            if ret != "是":
                return

        # 扫描前兜底同步项目名，保证界面显示与实际落盘目录一致
        self._sync_project_name()
        if not self.project_var.get().strip():
            self.project_var.set(Path(paths[0]).name)
        project_name = self.project_var.get().strip() or "未命名项目"
        self.current_scan_paths = list(files)
        self.current_skipped = skipped
        self.current_project_name = project_name
        self.current_no_cache = no_cache
        self.current_full_scan = full_scan
        self.current_results = []
        self.scan_running = True
        self.scan_paused = False
        self.pause_event.set()
        self.stop_event.clear()
        self.start_btn.configure(state=DISABLED)
        self.pause_btn.configure(state=NORMAL, text="暂停")
        self.stop_btn.configure(state=NORMAL)
        self.clear_log()
        self.progress_q.put(("reset", None))
        mode = "全量扫描" if full_scan else ("忽略缓存" if no_cache else "增量扫描")
        self._log(f"[开始扫描] 目标: {project_name} | 待扫描: {len(files)} 个文件 | 缓存命中: {len(files) - len(new_files)} | 模式: {mode}\n", "success")
        self._run_thread(self._scan_worker)

    def pause_scan(self):
        if not self.scan_running:
            return
        if self.scan_paused:
            self.pause_event.set()
            self.scan_paused = False
            self.pause_btn.configure(text="暂停")
            self._log("[提示] 扫描继续\n", "warning")
        else:
            self.pause_event.clear()
            self.scan_paused = True
            self.pause_btn.configure(text="继续")
            self._log("[提示] 扫描已暂停，点击「继续」恢复\n", "warning")

    def stop_scan(self):
        if not self.scan_running:
            return
        ret = ttk.Messagebox.show_question("停止扫描", "确定停止当前扫描？已扫描结果会保留。", buttons=["是", "否"], parent=self.root)
        if ret != "是":
            return
        self.stop_event.set()
        self.pause_event.set()
        self._log("[提示] 正在停止扫描...\n", "warning")

    def _scan_worker(self):
        self._redirect_stdout()
        try:
            vs_mod = vs
            km = vs_mod.ApiKeyManager()
            files = self.current_scan_paths
            skipped_text = self.current_skipped
            no_cache = self.current_no_cache
            project_name = self.current_project_name

            safe_pn = "".join(c if c.isalnum() or c in "._-" else "_" for c in project_name)
            output_dir = vs_mod.PROJECTS_DIR / safe_pn
            output_dir.mkdir(parents=True, exist_ok=True)
            self.current_output_dir = output_dir

            json_path = output_dir / "scan_data.json"
            report_path = output_dir / "report.html"
            project_rel = f"projects\\{safe_pn}"

            self.progress_q.put(("status", "准备扫描..."))
            self._log(f"[项目目录] {output_dir}\n")
            if self.current_full_scan:
                self._log("[模式] 全量扫描：忽略本地缓存，不按扩展名过滤\n", "warning")

            cache = vs_mod.load_scan_cache()
            new_files = [f for f in files if no_cache or vs_mod.file_sha256(f) not in cache]
            cached_count = len(files) - len(new_files)
            self._log(f"[缓存] 命中 {cached_count} 个，需扫描 {len(new_files)} 个\n")

            results = []
            skip_results = []

            def _refresh_report():
                all_results = skip_results + results
                html = vs_mod.generate_html_report(all_results, project_name, len(skipped_text))
                with open(report_path, "w", encoding="utf-8") as f:
                    f.write(html)
                with open(json_path, "w", encoding="utf-8") as f:
                    json.dump(all_results, f, indent=2, ensure_ascii=False)

            def _record_result(result):
                results.append(result)
                _refresh_report()

            # 缓存命中先入列
            for file_path in files:
                sha = vs_mod.file_sha256(file_path)
                entry = cache.get(sha)
                if entry and not no_cache:
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
                    self._log(f"  [缓存] {file_path.name} → 恶意:{m} 可疑:{s}\n", self._tag("缓存"))
            _refresh_report()

            total = len(files)
            done = len(skip_results)
            rate_limited = quota_hit = False

            for i, file_path in enumerate(files, 1):
                if self.stop_event.is_set():
                    self._log("\n[已停止] 用户终止扫描\n", "warning")
                    break
                self.pause_event.wait()
                sha = vs_mod.file_sha256(file_path)
                if sha in cache and not no_cache:
                    continue

                try:
                    size_mb = file_path.stat().st_size / (1024 * 1024)
                except OSError:
                    size_mb = 0.0
                self._log(f"[{i}/{total}] 开始: {file_path.name} ({size_mb:.2f} MB, SHA256: {sha[:12]}...)\n")
                file_t0 = time.time()

                done = len(skip_results) + len(results)
                self.progress_q.put(("progress", (done, total, file_path.name)))

                try:
                    api_key = km.current_key()
                    existing = vs_mod.check_existing_report(api_key, sha, km, file_path.name, no_cache=no_cache)
                    if existing:
                        if isinstance(existing, dict) and "malicious" in existing:
                            m = existing.get("malicious", 0)
                            s = existing.get("suspicious", 0)
                            vs_mod.cache_put(sha, str(file_path), file_path.name, project_rel, m, s)
                            _record_result({
                                "filename": file_path.name, "filepath": str(file_path),
                                "sha256": sha, "malicious": m, "suspicious": s,
                                "undetected": 0, "harmless": 0, "engines": {},
                                "status": "cached",
                            })
                            self._log(f"[{i}/{total}] {file_path.name} → 缓存 恶意:{m} 可疑:{s}\n",
                                      self._tag(f"恶意:{m} 可疑:{s}"))
                        else:
                            attrs = existing.get("data", {}).get("attributes", {})
                            stats = attrs.get("last_analysis_stats", {})
                            engines = attrs.get("last_analysis_results", {})
                            m = stats.get("malicious", 0)
                            s = stats.get("suspicious", 0)
                            vs_mod.cache_put(sha, str(file_path), file_path.name, project_rel, m, s)
                            _record_result({
                                "filename": file_path.name, "filepath": str(file_path),
                                "sha256": sha,
                                "malicious": m, "suspicious": s,
                                "undetected": stats.get("undetected", 0),
                                "harmless": stats.get("harmless", 0),
                                "engines": {k: {"category": v.get("category", ""), "result": v.get("result", "")}
                                            for k, v in engines.items()},
                                "status": "existing_report",
                            })
                            self._log(f"[{i}/{total}] {file_path.name} → 已有报告 恶意:{m} 可疑:{s}\n",
                                      self._tag(f"恶意:{m} 可疑:{s}"))
                        continue

                    api_key = km.current_key()
                    self._log(f"[{i}/{total}] 上传: {file_path.name} ...\n")
                    t_up = time.time()
                    upload_resp = vs_mod.upload_file(api_key, file_path, km)
                    analysis_id = upload_resp.get("data", {}).get("id", "")
                    if not analysis_id:
                        _record_result({
                            "filename": file_path.name, "filepath": str(file_path),
                            "sha256": sha, "malicious": 0, "suspicious": 0,
                            "undetected": 0, "harmless": 0, "engines": {}, "status": "upload_failed",
                        })
                        self._log(f"[{i}/{total}] {file_path.name} → 上传失败\n", "danger")
                        continue
                    self._log(f"[{i}/{total}] 上传完成 ({time.time() - t_up:.1f}s)，等待分析结果...\n", "success")

                    api_key = km.current_key()
                    analysis = vs_mod.get_analysis(api_key, analysis_id, km)
                    if analysis:
                        attrs = analysis.get("data", {}).get("attributes", {})
                        stats = attrs.get("stats", {})
                        engines = attrs.get("results", {})
                        m = stats.get("malicious", 0)
                        s = stats.get("suspicious", 0)
                        vs_mod.cache_put(sha, str(file_path), file_path.name, project_rel, m, s)
                        _record_result({
                            "filename": file_path.name, "filepath": str(file_path),
                            "sha256": sha,
                            "malicious": m, "suspicious": s,
                            "undetected": stats.get("undetected", 0),
                            "harmless": stats.get("harmless", 0),
                            "engines": {k: {"category": v.get("category", ""), "result": v.get("result", "")}
                                        for k, v in engines.items()},
                            "status": "scanned",
                        })
                        flag = "!!" if m > 0 else ("?" if s > 0 else "OK")
                        self._log(f"[{i}/{total}] {file_path.name} → {flag} 恶意:{m} 可疑:{s} (耗时 {time.time() - file_t0:.1f}s)\n",
                                  self._tag(f"恶意:{m} 可疑:{s}"))
                    else:
                        _record_result({
                            "filename": file_path.name, "filepath": str(file_path),
                            "sha256": sha, "malicious": 0, "suspicious": 0,
                            "undetected": 0, "harmless": 0, "engines": {}, "status": "timeout",
                        })
                        self._log(f"[{i}/{total}] {file_path.name} → 分析超时\n", "warning")

                except vs_mod.AllKeysExhaustedError:
                    _record_result({
                        "filename": file_path.name, "filepath": str(file_path),
                        "sha256": sha, "malicious": 0, "suspicious": 0,
                        "undetected": 0, "harmless": 0, "engines": {},
                        "status": "rate_limited",
                    })
                    rate_limited = True
                    self._log("\n=== 所有 API Key 均触发 429 限速，扫描终止 ===\n", "danger")
                    break
                except Exception as e:
                    err = str(e)
                    if "配额耗尽" in err:
                        _record_result({
                            "filename": file_path.name, "filepath": str(file_path),
                            "sha256": sha, "malicious": 0, "suspicious": 0,
                            "undetected": 0, "harmless": 0, "engines": {},
                            "status": "quota_exhausted",
                        })
                        quota_hit = True
                        self._log("\n=== 配额耗尽，扫描中断 ===\n", "danger")
                        break
                    _record_result({
                        "filename": file_path.name, "filepath": str(file_path),
                        "sha256": sha, "malicious": 0, "suspicious": 0,
                        "undetected": 0, "harmless": 0, "engines": {}, "status": "error",
                    })
                    self._log(f"[{i}/{total}] {file_path.name} → 错误: {err}\n", "danger")

            # Step 5 汇总
            all_results = skip_results + results
            _refresh_report()
            det_dir, det_count = vs_mod.generate_detection_reports(all_results, output_dir)

            m_cnt = sum(1 for r in all_results if r.get("malicious", 0) > 0)
            s_cnt = sum(1 for r in all_results if r.get("malicious", 0) == 0 and r.get("suspicious", 0) > 0)
            safe_cnt = sum(1 for r in all_results if r.get("malicious", 0) == 0 and r.get("suspicious", 0) == 0)

            if rate_limited:
                status = "扫描中断（所有 Key 429 限速）"
            elif quota_hit:
                status = "扫描中断（配额耗尽）"
            elif len(all_results) >= len(files):
                status = "扫描完成"
            else:
                status = "扫描中断"

            self._log(f"\n{'='*56}\n  {status}\n"
                      f"  总计: {len(files)} 个文件 | 缓存复用: {len(skip_results)} | 本次扫描: {len(results)}\n"
                      f"  恶意: {m_cnt} | 可疑: {s_cnt} | 安全: {safe_cnt}\n"
                      f"  {km.quota_status()}\n"
                      f"  HTML 报告: {report_path}\n"
                      f"  JSON 数据: {json_path}\n"
                      f"{'='*56}\n", "success" if "完成" in status else "warning")

            self.current_results = all_results
            self.progress_q.put(("done", None))
            self.progress_q.put(("status", f"{status} | 恶意 {m_cnt} · 可疑 {s_cnt} · 安全 {safe_cnt}"))
            self.progress_q.put(("finished", None))
        except Exception as e:
            self._log(f"[致命错误] {e}\n", "danger")
            self.progress_q.put(("finished", None))
        finally:
            self._restore_stdout()

    def _scan_finished(self):
        self.scan_running = False
        self.scan_paused = False
        self.start_btn.configure(state=NORMAL)
        self.pause_btn.configure(state=DISABLED, text="暂停")
        self.stop_btn.configure(state=DISABLED)
        self._refresh_quota_bar()
        self.refresh_projects()

    def open_output_dir(self):
        if self.current_output_dir and self.current_output_dir.is_dir():
            os.startfile(str(self.current_output_dir))
        else:
            projects = vs.PROJECTS_DIR
            if projects.is_dir():
                os.startfile(str(projects))

    # ============================================================
    #  Key 管理
    # ============================================================
    def refresh_keys(self):
        km = vs.ApiKeyManager()
        for item in self.key_tree.get_children():
            self.key_tree.delete(item)
        now = datetime.now()
        today = now.strftime("%Y-%m-%d")
        for i, k in enumerate(km.keys):
            q = km._get_quota(k["key_id"])
            daily_r = vs.DAILY_QUOTA - q["daily"]["count"]
            monthly_r = vs.MONTHLY_QUOTA - q["monthly"]["count"]
            active = "当前" if i == km.active_idx else ""
            self.key_tree.insert("", END, values=(i, k["label"], k["key_id"], daily_r, monthly_r, active))

    def add_key(self):
        key = self.key_entry.get().strip()
        if not key:
            ttk.Messagebox.show_info("请输入 Key", "请输入 VirusTotal API Key", parent=self.root)
            return
        km = vs.ApiKeyManager()
        ok, msg = km.add_key(key, label=f"gui-{len(km.keys)+1}", save=True)
        ttk.Messagebox.show_info("添加 Key", msg, parent=self.root)
        if ok:
            self.key_entry.delete(0, END)
            self.refresh_keys()
            self._refresh_quota_bar()

    def load_key_file(self):
        from tkinter import filedialog
        path = filedialog.askopenfilename(title="选择 Key 文件", filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")])
        if path:
            km = vs.ApiKeyManager()
            ok, msg = km.load_keys_from_file(path)
            ttk.Messagebox.show_info("加载 Key 文件", msg, parent=self.root)
            self.refresh_keys()
            self._refresh_quota_bar()

    def _selected_key_index(self):
        sel = self.key_tree.selection()
        if not sel:
            ttk.Messagebox.show_info("请先选择", "请先在列表中选择 Key", parent=self.root)
            return None
        values = self.key_tree.item(sel[0], "values")
        return int(values[0])

    def set_active_key(self):
        idx = self._selected_key_index()
        if idx is None:
            return
        km = vs.ApiKeyManager()
        if idx < len(km.keys):
            km.active_idx = idx
            km._save()
            self.refresh_keys()
            self._refresh_quota_bar()
            ttk.Messagebox.show_info("切换成功", f"当前 Key 已切换为 [{km.keys[idx]['label']}]", parent=self.root)

    def remove_key(self):
        idx = self._selected_key_index()
        if idx is None:
            return
        km = vs.ApiKeyManager()
        if idx < len(km.keys):
            label = km.keys[idx]["label"]
            ret = ttk.Messagebox.show_question("删除 Key", f"确定删除 Key [{label}]？", buttons=["是", "否"], parent=self.root)
            if ret != "是":
                return
            del km.keys[idx]
            if km.active_idx >= len(km.keys):
                km.active_idx = max(0, len(km.keys) - 1)
            km._save()
            self.refresh_keys()
            self._refresh_quota_bar()

    # ============================================================
    #  报告中心
    # ============================================================
    def refresh_projects(self):
        self._refreshing_projects = True
        try:
            for item in self.project_tree.get_children():
                self.project_tree.delete(item)
            projects = vs.PROJECTS_DIR
            if not projects.is_dir():
                projects = None
            if projects:
                for proj in sorted(projects.iterdir(), key=lambda p: p.stat().st_mtime if p.is_dir() else 0, reverse=True):
                    if not proj.is_dir():
                        continue
                    json_path = proj / "scan_data.json"
                    if not json_path.is_file():
                        continue
                    try:
                        with open(json_path, "r", encoding="utf-8") as f:
                            data = json.load(f)
                    except Exception:
                        continue
                    m = sum(1 for r in data if r.get("malicious", 0) > 0)
                    s = sum(1 for r in data if r.get("malicious", 0) == 0 and r.get("suspicious", 0) > 0)
                    safe = sum(1 for r in data if r.get("malicious", 0) == 0 and r.get("suspicious", 0) == 0)
                    mtime = datetime.fromtimestamp(proj.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
                    self.project_tree.insert("", END, values=(proj.name, len(data), m, s, safe, mtime, str(proj)))
        finally:
            self._refreshing_projects = False

        children = self.project_tree.get_children()
        if children:
            # 自动选中最新项目，触发预览生成
            self.project_tree.selection_set(children[0])
            self.project_tree.focus(children[0])
            self.text_report(auto=True)
        else:
            self.report_meta_label.configure(text="")
            self._set_report_preview("还没有可用的扫描项目。\n请先在「扫描中心」完成一次扫描，结果会自动出现在这里。\n")

    def _current_project_dir(self):
        """返回当前选中项目目录；无选中返回 None（不弹窗）"""
        sel = self.project_tree.selection()
        if not sel:
            return None
        values = self.project_tree.item(sel[0], "values")
        if len(values) < 7:
            return None
        return Path(values[6])

    def _selected_project_dir(self):
        proj = self._current_project_dir()
        if not proj:
            ttk.Messagebox.show_info("请先选择项目", "请先在列表中选择一个扫描项目", parent=self.root)
            return None
        return proj

    def open_html_report(self):
        proj = self._selected_project_dir()
        if not proj:
            return
        html = proj / "report.html"
        if html.is_file():
            webbrowser.open(html.as_uri())
        else:
            ttk.Messagebox.show_info("报告不存在", "该项目没有 HTML 报告", parent=self.root)

    def open_project_dir(self):
        proj = self._selected_project_dir()
        if not proj:
            return
        os.startfile(str(proj))

    def export_excel(self):
        proj = self._selected_project_dir()
        if not proj:
            return
        json_path = proj / "scan_data.json"
        if not json_path.is_file():
            ttk.Messagebox.show_info("无数据", "该项目没有 scan_data.json", parent=self.root)
            return
        out = proj / f"报毒清单_{json_path.stem}.xlsx"
        self._run_thread(self._export_excel_worker, )
        self._excel_export_path = out
        self._excel_export_json = json_path
        self._log(f"[导出] 正在生成 Excel...\n")

    def _export_excel_worker(self):
        self._redirect_stdout()
        try:
            vs.export_excel(self._excel_export_json, self._excel_export_path)
            self._log(f"[导出完成] {self._excel_export_path}\n", "success")
        except Exception as e:
            self._log(f"[导出失败] {e}\n", "danger")
        finally:
            self._restore_stdout()

    def filter_report(self):
        proj = self._selected_project_dir()
        if not proj:
            return
        json_path = proj / "scan_data.json"
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            filtered = [r for r in data if r.get("malicious", 0) > 0 or r.get("suspicious", 0) > 0]
            if not filtered:
                ttk.Messagebox.show_info("无报毒文件", "该项目没有报毒或可疑文件", parent=self.root)
                return
            html = vs.generate_html_report(filtered, f"{proj.name}（仅报毒）", 0)
            out = proj / f"{proj.name}_detections_only.html"
            with open(out, "w", encoding="utf-8") as f:
                f.write(html)
            webbrowser.open(out.as_uri())
        except Exception as e:
            ttk.Messagebox.show_error("生成失败", str(e), parent=self.root)

    def _set_report_preview(self, text):
        """统一写入预览区：切可写 -> 替换 -> 置只读 -> 回到顶部"""
        self.report_text.configure(state=NORMAL)
        self.report_text.delete("1.0", END)
        if text:
            self.report_text.insert(END, text)
        self.report_text.configure(state=DISABLED)
        self.report_text.see("1.0")

    def text_report(self, auto=False):
        """生成报毒测试报告预览。

        auto=True 表示由列表选中事件自动触发：无选中时静默显示占位提示，不弹窗。
        """
        if self._refreshing_projects:
            return
        proj = self._current_project_dir()
        if not proj:
            self.report_meta_label.configure(text="")
            if auto:
                self._set_report_preview("从上方列表选择一个扫描项目，这里会自动生成报毒测试报告。\n")
            else:
                ttk.Messagebox.show_info("请先选择项目", "请先在列表中选择一个扫描项目", parent=self.root)
            return

        json_path = proj / "scan_data.json"
        if not json_path.is_file():
            self.report_meta_label.configure(text=proj.name)
            self._set_report_preview(
                f"项目：{proj.name}\n目录：{proj}\n\n该项目目录下没有 scan_data.json，无法生成报告。\n"
            )
            return
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            if auto:
                self._set_report_preview(f"读取 {json_path.name} 失败：{e}\n")
            else:
                ttk.Messagebox.show_error("生成失败", str(e), parent=self.root)
            return

        total = len(data)
        det = [r for r in data if r.get("malicious", 0) > 0 or r.get("suspicious", 0) > 0]
        mal = sum(1 for r in data if r.get("malicious", 0) > 0)
        sus = sum(1 for r in data if r.get("malicious", 0) == 0 and r.get("suspicious", 0) > 0)
        safe_n = total - len(det)
        mtime = datetime.fromtimestamp(proj.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
        vendors = sorted({en for r in det for en, info in (r.get("engines") or {}).items()
                          if info.get("category") in ("malicious", "suspicious")})

        bar = "=" * 64
        if vendors:
            vendor_line = f"检出厂商   : {len(vendors)} 个（{', '.join(vendors[:8])}{'...' if len(vendors) > 8 else ''}）"
        elif det:
            vendor_line = "检出厂商   : 明细未缓存（结果为聚合计数，重扫可获取具体厂商）"
        else:
            vendor_line = "检出厂商   : 无"
        lines = [
            f"报毒测试报告 — {proj.name}",
            bar,
            f"扫描目录   : {proj}",
            f"更新时间   : {mtime}",
            f"文件统计   : 共 {total} 个（恶意 {mal} · 可疑 {sus} · 安全 {safe_n}）",
            f"报毒占比   : {(len(det) / total * 100 if total else 0):.1f}%",
            vendor_line,
            "-" * 64,
        ]

        if not det:
            lines.append(f"本次扫描的 {total} 个文件全部判定为安全，未发现恶意或可疑文件。")
            lines.append("")
            lines.append("如仍需向厂商提交排查，可从该项目的扫描明细中挑选文件单独申诉。")
        else:
            lines.append(f"共 {len(det)} 个文件被标记，明细如下：")
            for idx, r in enumerate(det, 1):
                fp = r.get("filepath") or r.get("filename") or "?"
                sha = r.get("sha256") or "?"
                m = r.get("malicious", 0)
                s = r.get("suspicious", 0)
                lines.append("")
                lines.append(f"[{idx}] {fp}")
                lines.append(f"    SHA256 : {sha}")
                lines.append(f"    判定   : 恶意 {m} · 可疑 {s}")
                engines = r.get("engines") or {}
                hits = [(en, info) for en, info in sorted(engines.items())
                        if info.get("category") in ("malicious", "suspicious")]
                for ename, info in hits:
                    cat = info.get("category")
                    threat = info.get("result") or cat or "?"
                    lines.append(f"    [{'M' if cat == 'malicious' else 'S'}] {ename}: {threat}")
                if not hits:
                    lines.append("    （无引擎具名检出，仅聚合计数异常）")

        self.report_meta_label.configure(
            text=f"{proj.name} · 共 {total} 个文件 · 报毒 {len(det)} 个"
        )
        self._set_report_preview("\n".join(lines) + "\n")

    # ============================================================
    #  邮件申诉
    # ============================================================
    def save_smtp_config(self):
        cfg = {
            "host": self.smtp_host.get().strip() or "smtp.qq.com",
            "port": int(self.smtp_port.get().strip() or 587),
            "auth_code": self.smtp_auth.get().strip(),
        }
        gfe.save_smtp_config(cfg)
        self._email_log_line(f"[SMTP] 配置已保存: {cfg['host']}:{cfg['port']}\n", "success")

    def _load_smtp_to_ui(self):
        cfg = gfe.load_smtp_config()
        self.smtp_host.delete(0, END)
        self.smtp_host.insert(0, cfg.get("host", "smtp.qq.com"))
        self.smtp_port.delete(0, END)
        self.smtp_port.insert(0, str(cfg.get("port", 587)))
        self.smtp_auth.delete(0, END)
        self.smtp_auth.insert(0, cfg.get("auth_code", ""))

    def choose_email_source(self):
        from tkinter import filedialog
        path = filedialog.askopenfilename(
            title="选择 scan_data.json 或 detections 目录下的 JSON",
            filetypes=[("JSON", "*.json"), ("所有文件", "*.*")])
        if path:
            self.email_src_entry.delete(0, END)
            self.email_src_entry.insert(0, path)

    def generate_emails(self):
        if self.email_running:
            return
        src = self.email_src_entry.get().strip()
        if not src:
            ttk.Messagebox.show_info("请选择数据源", "请选择 scan_data.json 或 detections 目录", parent=self.root)
            return
        self._email_src = src
        self.email_running = True
        self.email_tree.delete(*self.email_tree.get_children())
        self.email_progress.configure(value=0)
        self._email_status("准备生成邮件队列...")
        self._email_log_line(f"[生成] 数据源: {src}\n")
        self._run_thread(self._email_gen_worker)

    # ---------- 一键申诉 ----------

    def one_click_appeal(self):
        """一键申诉：生成队列 → 上传报毒样本到 GitHub → 确认后全量发送"""
        if self.email_running:
            return
        src = self.email_src_entry.get().strip()
        if not src:
            ttk.Messagebox.show_info("请选择数据源", "请选择 scan_data.json 或 detections 目录", parent=self.root)
            return
        cfg = gfe.load_smtp_config()
        if not cfg.get("auth_code"):
            ttk.Messagebox.show_info("SMTP 未配置", "请先在上方配置 SMTP 授权码", parent=self.root)
            return
        ret = ttk.Messagebox.show_question(
            "一键申诉",
            "将依次执行：\n"
            "  1. 读取扫描结果生成申诉邮件\n"
            "  2. 自动上传报毒样本到 GitHub 仓库\n"
            "  3. 生成完成后确认，再把全部邮件发送出去\n\n"
            "是否开始？",
            buttons=["开始", "取消"], parent=self.root)
        if ret != "开始":
            return

        self._email_src = src
        self.email_running = True
        self.email_tree.delete(*self.email_tree.get_children())
        self.email_progress.configure(value=0)
        self._email_status("一键申诉：准备中...")
        self._email_log_line(f"[一键申诉] 数据源: {src}\n", "success")
        self._run_thread(self._one_click_worker)

    def _one_click_worker(self):
        """一键申诉：只负责生成队列，发送交给主线程确认后启动"""
        try:
            count = self._generate_queue()
            if count > 0:
                self.log_q.put(("email_confirm",
                                ("邮件已生成",
                                 f"已生成 {count} 封申诉邮件（样本已上传 GitHub）。\n\n"
                                 f"接下来确认发送内容：可逐封确认，也可一键全部确认。", None),
                                None))
            elif count == 0:
                self._email_status("没有可发送的邮件")
        finally:
            self.email_running = False

    def _start_send_all(self):
        """主线程：打开确认窗，逐封/一键确认后再发送（一键申诉生成完成后调用）"""
        pending = []
        for item in self.email_tree.get_children():
            values = self.email_tree.item(item, "values")
            try:
                row_idx = self.email_tree.index(item)
            except Exception:
                row_idx = -1
            pending.append((item, row_idx, values))
        if not pending:
            ttk.Messagebox.show_info("没有待发送邮件", "邮件队列为空。", parent=self.root)
            return
        self._confirm_email_send(pending)

    # ---------- 队列生成 ----------

    def _email_set_progress(self, done, total, text=None):
        self.log_q.put(("email_progress", (done, total, text), None))

    def _email_status(self, text):
        self.log_q.put(("email_status", text, None))

    @staticmethod
    def _normalize_record(raw, json_file: Path):
        """把 scan_data 汇总记录 / detections 单文件记录统一成同一结构"""
        file_name = raw.get("file_name") or raw.get("filename") or json_file.stem
        file_path = raw.get("file_path") or raw.get("filepath") or file_name
        sha256 = raw.get("sha256", "") or ""
        vt_link = raw.get("virus_total_link") or raw.get("vt_link") or (
            f"https://www.virustotal.com/gui/file/{sha256}" if sha256 else "")
        dets = []
        if raw.get("detections"):
            for det in raw["detections"]:
                dets.append((det.get("engine", "Unknown"), det.get("name", "Unknown")))
        else:
            for ename, info in (raw.get("engines") or {}).items():
                if info.get("category") in ("malicious", "suspicious"):
                    dets.append((ename, info.get("result") or info.get("category", "?")))
        return {"file_name": file_name, "file_path": file_path, "sha256": sha256,
                "vt_link": vt_link, "dets": dets}

    def _iter_scan_records(self, target: Path):
        """读取数据源，兼容：scan_data 汇总数组 / detections 单文件字典 / 目录两种格式"""
        records = []
        if target.is_file() and target.suffix.lower() == ".json":
            with open(target, "r", encoding="utf-8") as f:
                data = json.load(f)
            raw_list = data if isinstance(data, list) else [data]
            records = [self._normalize_record(r, target) for r in raw_list if isinstance(r, dict)]
        elif target.is_dir():
            json_files = sorted(target.glob("*.json")) or sorted(target.glob("detections/*.json"))
            if not json_files:
                raise FileNotFoundError(f"目录下没有 JSON 文件: {target}")
            for jf in json_files:
                with open(jf, "r", encoding="utf-8") as f:
                    data = json.load(f)
                raw_list = data if isinstance(data, list) else [data]
                records.extend(self._normalize_record(r, jf) for r in raw_list if isinstance(r, dict))
        else:
            raise FileNotFoundError(f"路径不存在或不是 JSON/目录: {target}")
        return records

    def _build_email_queue(self, records, project_name):
        """上传报毒样本到 GitHub 并生成申诉邮件，返回 (邮件队列, 无邮箱条数)"""
        uploaded = {}
        unique_paths = []
        sha_by_path = {}
        for rec in records:
            fp = rec["file_path"]
            sha_by_path.setdefault(fp, rec.get("sha256", ""))
            if fp not in uploaded:
                uploaded[fp] = None
                unique_paths.append(fp)

        total_files = len(unique_paths)
        for idx, fp in enumerate(unique_paths, 1):
            name = Path(fp).name
            self._email_set_progress(idx - 1, max(total_files, 1),
                                     f"上传样本 {idx}/{total_files}: {name}")
            self._email_log_line(f"[GitHub] 上传中 {idx}/{total_files}: {name}\n")
            url = gfe.upload_to_github(fp, project_name, sha_by_path.get(fp, ""))
            uploaded[fp] = url
            if url:
                self._email_log_line(f"[GitHub] 已就绪: {url}\n", "success")
            else:
                self._email_log_line(f"[GitHub] 上传失败（样本不存在或 Git 操作失败），该邮件不带样本链接: {fp}\n", "warning")

        email_queue = []
        no_email_count = 0
        for rec in records:
            for engine, threat in rec["dets"]:
                body, recipient = gfe.generate_email(rec["file_name"], rec["sha256"], rec["vt_link"],
                                                     engine, threat,
                                                     github_link=uploaded.get(rec["file_path"]))
                if body is None:
                    no_email_count += 1
                    contact = (recipient or "").strip()
                    if contact.startswith("http"):
                        self._email_log_line(f"[跳过] {engine}: 无邮箱，需网页表单申报 → {contact}\n", "warning")
                    else:
                        self._email_log_line(f"[跳过] {engine}: 未收录公开联系方式\n")
                    continue
                email_queue.append({
                    "file_name": rec["file_name"], "file_path": rec["file_path"], "engine": engine,
                    "threat": threat, "sha256": rec["sha256"], "vt_link": rec["vt_link"],
                    "recipient": recipient, "body": body,
                    "github_link": uploaded.get(rec["file_path"]),
                })
        return email_queue, no_email_count

    def _generate_queue(self):
        """生成邮件队列并写入表格，返回有效邮件数（失败返回 -1）"""
        self._redirect_stdout()
        try:
            src = getattr(self, "_email_src", "") or self.email_src_entry.get().strip()
            target = Path(src)
            if not target.exists():
                self._email_log_line(f"[错误] 路径不存在: {src}\n", "danger")
                self._email_set_progress(0, 1, "生成失败：路径不存在")
                return -1

            self._email_status("解析扫描结果...")
            records = self._iter_scan_records(target)
            self._email_log_line(f"[解析] 报毒记录 {len(records)} 条\n")

            project_name = target.parent.name
            email_queue, no_email_count = self._build_email_queue(records, project_name)

            skipped = 0
            filtered = []
            for em in email_queue:
                if vs.is_declared(em["sha256"], em["engine"]):
                    skipped += 1
                else:
                    filtered.append(em)
            if skipped:
                self._email_log_line(f"[去重] 跳过 {skipped} 条已申诉记录\n", "warning")

            self.email_queue = filtered
            rows = [("", em["file_name"], em["engine"], em["threat"],
                     em["recipient"], "待发送") for em in filtered]
            self.log_q.put(("email_tree_insert_all", rows, None))
            self._email_log_line(f"[完成] 共生成 {len(filtered)} 封待发送邮件"
                                 f"（无邮箱跳过 {no_email_count} 条，已申诉跳过 {skipped} 条）\n", "success")
            self._email_set_progress(1, 1, f"已生成 {len(filtered)} 封待发送邮件")

            if not filtered:
                if no_email_count or skipped:
                    self.log_q.put(("email_msgbox",
                                    ("未生成可发送邮件",
                                     f"未找到可发送的邮件队列：\n无邮箱/表单联系方式的报毒 {no_email_count} 条\n已申诉过的 {skipped} 条\n请更换数据源或检查报毒引擎是否有公开联系方式。",
                                     "warning"), None))
                else:
                    self.log_q.put(("email_msgbox",
                                    ("未生成可发送邮件", "数据源中没有报毒/可疑记录，未生成邮件队列。", "warning"), None))
            return len(filtered)
        except Exception as e:
            self._email_log_line(f"[生成失败] {e}\n", "danger")
            self._email_set_progress(0, 1, f"生成失败: {e}")
            return -1
        finally:
            self._restore_stdout()

    def _email_gen_worker(self):
        try:
            count = self._generate_queue()
            if count > 0:
                self.log_q.put(("email_msgbox",
                                ("邮件队列已生成", f"共生成 {count} 封待发送邮件，勾选后可发送。", "info"), None))
        finally:
            self.email_running = False

    def _on_email_tree_click(self, event):
        """点击首列切换勾选状态"""
        region = self.email_tree.identify("region", event.x, event.y)
        if region != "cell":
            return
        col = self.email_tree.identify_column(event.x)
        if col != "#1":
            return
        item = self.email_tree.identify_row(event.y)
        if not item:
            return
        values = list(self.email_tree.item(item, "values"))
        values[0] = "✓" if values[0] != "✓" else ""
        self.email_tree.item(item, values=values)

    def toggle_all_emails(self):
        children = self.email_tree.get_children()
        if not children:
            return
        first = self.email_tree.item(children[0], "values")[0]
        new_val = "" if first == "✓" else "✓"
        for item in children:
            values = list(self.email_tree.item(item, "values"))
            values[0] = new_val
            self.email_tree.item(item, values=values)

    def _selected_email_items(self):
        items = []
        for item in self.email_tree.get_children():
            values = self.email_tree.item(item, "values")
            if values[0] == "✓":
                items.append((item, values))
        return items

    def send_selected_emails(self):
        if self.email_running:
            return
        selected = self._selected_email_items()
        if not selected:
            ttk.Messagebox.show_info("未选择邮件", "请先勾选要发送的邮件（点击首列）", parent=self.root)
            return
        cfg = gfe.load_smtp_config()
        if not cfg.get("auth_code"):
            ttk.Messagebox.show_info("SMTP 未配置", "请先在上方配置 SMTP 授权码", parent=self.root)
            return
        # 主线程预取行数据，避免子线程直接读取 Tk 组件
        pending = []
        for item, values in selected:
            try:
                row_idx = self.email_tree.index(item)
            except Exception:
                row_idx = -1
            pending.append((item, row_idx, values))
        # CLI 式确认：展示每封邮件详情后确认
        self._confirm_email_send(pending)

    def _confirm_email_send(self, pending):
        """发送前确认窗：逐封展示正文，可单封确认，也可一键全部确认。

        逐封模式：确认本封 → 自动翻到下一封；跳过本封 → 不发送并翻页。
        全部确认：把当前及剩余邮件一次性加入发送队列。
        """
        import tkinter as tk

        total = len(pending)
        confirmed = []
        state = {"idx": 0, "skipped": 0}

        win = ttk.Toplevel(self.root)
        win.title(f"确认发送邮件（共 {total} 封）")
        win.geometry("900x680")
        win.transient(self.root)
        win.grab_set()

        head = ttk.Frame(win)
        head.pack(fill=X, padx=16, pady=(14, 4))
        title_label = ttk.Label(head, text="", style="PageTitle.TLabel",
                                font=("Segoe UI", 12, "bold"))
        title_label.pack(side=LEFT)
        counter_label = ttk.Label(head, text="", style="CardSub.TLabel")
        counter_label.pack(side=RIGHT)

        info_label = ttk.Label(win, text="", style="CardSub.TLabel", justify=LEFT,
                               wraplength=850)
        info_label.pack(anchor=W, padx=16, pady=(0, 8))

        body_frame = ttk.Frame(win)
        body_frame.pack(fill=BOTH, expand=True, padx=16)
        preview = tk.Text(body_frame, wrap="word", font=("Consolas", 10),
                          bg="#fbfbfa", fg="#37352f",
                          relief="flat", padx=12, pady=12)
        scroll = ttk.Scrollbar(body_frame, orient="vertical", command=preview.yview)
        preview.configure(yscrollcommand=scroll.set)
        preview.pack(side=LEFT, fill=BOTH, expand=True)
        scroll.pack(side=RIGHT, fill=Y)

        btns = ttk.Frame(win)
        btns.pack(fill=X, padx=16, pady=(10, 14))
        skip_btn = ttk.Button(btns, text="跳过本封", style="Outline.TButton")
        skip_btn.pack(side=LEFT)
        confirm_all_btn = ttk.Button(btns, text="一键全部确认并发送", style="Outline.TButton")
        confirm_all_btn.pack(side=RIGHT, padx=(8, 0))
        next_btn = ttk.Button(btns, text="确认并发送本封", style="Primary.TButton")
        next_btn.pack(side=RIGHT)
        ttk.Button(btns, text="取消", style="Outline.TButton", width=10,
                   command=win.destroy).pack(side=RIGHT, padx=(8, 0))

        def finish():
            if not confirmed:
                ttk.Messagebox.show_info("未确认任何邮件", "已跳过全部邮件，本次没有发送。",
                                         parent=self.root)
                win.destroy()
                return
            confirmed_ids = {c[0] for c in confirmed}
            for item, row_idx, values in pending:
                if item not in confirmed_ids:
                    new_values = list(values)
                    new_values[5] = "已跳过"
                    self.log_q.put(("email_tree_update", (item, new_values), None))
            self._start_email_send(win, confirmed)

        def render():
            if state["idx"] >= total:
                finish()
                return
            item, row_idx, values = pending[state["idx"]]
            if row_idx < 0 or row_idx >= len(self.email_queue):
                state["idx"] += 1
                render()
                return
            em = self.email_queue[row_idx]
            title_label.configure(text=f"邮件 {state['idx'] + 1}/{total}")
            counter_label.configure(
                text=f"已确认 {len(confirmed)} · 已跳过 {state['skipped']}")
            info_label.configure(
                text=(f"收件人: {em['recipient']}\n"
                      f"主题: False Positive Report - {em['engine']} - {em['file_name']}\n"
                      f"报毒: {em['threat']}    样本: {em['file_path']}\n"
                      f"申报: {em.get('github_link') or '未上传到 GitHub'}"))
            preview.configure(state=NORMAL)
            preview.delete("1.0", END)
            preview.insert(END, em["body"])
            preview.yview_moveto(0)
            preview.configure(state=DISABLED)
            next_btn.configure(text="确认并发送本封" if state["idx"] < total - 1 else "确认并完成发送")

        def confirm_current():
            confirmed.append(pending[state["idx"]])
            state["idx"] += 1
            render()

        def skip_current():
            state["skipped"] += 1
            state["idx"] += 1
            render()

        def confirm_all():
            confirmed.extend(pending[state["idx"]:])
            state["idx"] = total
            finish()

        next_btn.configure(command=confirm_current)
        skip_btn.configure(command=skip_current)
        confirm_all_btn.configure(command=confirm_all)
        win.bind("<Escape>", lambda _e: win.destroy())

        render()

    def _start_email_send(self, win, pending):
        win.destroy()
        self._send_pending = pending
        self.email_running = True
        self._run_thread(self._email_send_worker)

    def _email_send_worker(self):
        self._redirect_stdout()
        ok_count = 0
        fail_count = 0
        fail_details = []
        total_pending = len(self._send_pending)
        try:
            for idx, (item, row_idx, values) in enumerate(self._send_pending, 1):
                if row_idx < 0 or row_idx >= len(self.email_queue):
                    continue
                em = self.email_queue[row_idx]
                subject = f"False Positive Report - {em['engine']} - {em['file_name']}"
                self._email_set_progress(idx - 1, total_pending,
                                         f"发送 {idx}/{total_pending}: {em['file_name']} → {em['engine']}")
                self._email_log_line(f"[发送 {idx}/{total_pending}] {em['file_name']} → {em['engine']} → {em['recipient']}\n")
                ok, err = gfe.send_fp_email(em["recipient"], subject, em["body"])
                if ok:
                    ok_count += 1
                    vs.mark_declared(em["sha256"], em["engine"], em["file_path"],
                                     project=em["file_path"].split("projects")[-1].lstrip("\\/") if "projects" in em["file_path"] else "")
                    new_values = list(values)
                    new_values[5] = "已发送"
                    self.log_q.put(("email_tree_update", (item, new_values), None))
                    self._email_log_line(f"  → 已发送\n", "success")
                else:
                    fail_count += 1
                    fail_details.append(f"{em['file_name']}（{em['engine']}）: {err}")
                    new_values = list(values)
                    new_values[5] = "失败"
                    self.log_q.put(("email_tree_update", (item, new_values), None))
                    self._email_log_line(f"  → 失败: {err}\n", "danger")
        except Exception as e:
            fail_count += 1
            fail_details.append(f"发送异常: {e}")
            self._email_log_line(f"[发送异常] {e}\n", "danger")

        # 汇总回执：日志 + 弹框
        total = ok_count + fail_count
        if fail_count:
            summary = f"发送完成：共 {total} 封，成功 {ok_count} 封，失败 {fail_count} 封"
            self._email_log_line(f"[汇总] {summary}\n", "danger")
            for d in fail_details:
                self._email_log_line(f"  - {d}\n", "danger")
            self.log_q.put(("email_msgbox",
                            ("发送完成（部分失败）", summary + "\n\n" + "\n".join(fail_details), "warning"), None))
            self._email_set_progress(total, max(total, 1), summary)
        else:
            summary = f"发送完成：共 {total} 封，全部发送成功"
            self._email_log_line(f"[汇总] {summary}\n", "success")
            self.log_q.put(("email_msgbox", ("发送完成", summary, "info"), None))
            self._email_set_progress(1, 1, summary)

        self._restore_stdout()
        self.email_running = False

    def export_email_files(self):
        """仅生成邮件 txt 文件，不发送"""
        if not self.email_queue:
            ttk.Messagebox.show_info("队列为空", "请先生成邮件队列", parent=self.root)
            return
        out_dir = Path(self.email_src_entry.get().strip()).parent / f"emails_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        out_dir.mkdir(parents=True, exist_ok=True)
        n = 0
        for em in self.email_queue:
            safe_file = "".join(c if c.isalnum() or c in "._- " else "_" for c in em["file_name"])
            safe_engine = "".join(c if c.isalnum() or c in "._- " else "_" for c in em["engine"])
            path = out_dir / f"{safe_file}__{safe_engine}.txt"
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"To: {em['recipient']}\n")
                f.write("Subject: VirusTotal False Positive Report\n")
                f.write("=" * 60 + "\n\n")
                f.write(em["body"])
            n += 1
        ttk.Messagebox.show_info("生成完成", f"已生成 {n} 封邮件文件到:\n{out_dir}", parent=self.root)
        os.startfile(str(out_dir))

    # ============================================================
    #  缓存与设置
    # ============================================================
    def refresh_cache_stats(self):
        self.cache_stats_label.configure(text=vs.cache_stats())
        self.declared_stats_label.configure(text=vs.declared_stats())

    def clear_scan_cache(self):
        ret = ttk.Messagebox.show_question("清空扫描缓存",
                                           "确定清空所有扫描缓存？下次扫描将重新上传所有文件。",
                                           buttons=["是", "否"],
                                           parent=self.root)
        if ret == "是":
            vs.clear_scan_cache()
            self.refresh_cache_stats()
            ttk.Messagebox.show_info("完成", "扫描缓存已清空", parent=self.root)

    def clear_declared(self):
        ret = ttk.Messagebox.show_question("清空已申诉记录",
                                           "确定清空已申诉记录？之后可对同一引擎重复生成申诉邮件。",
                                           buttons=["是", "否"],
                                           parent=self.root)
        if ret == "是":
            vs.clear_declared_cache()
            self.refresh_cache_stats()
            ttk.Messagebox.show_info("完成", "已申诉记录已清空", parent=self.root)

    # ============================================================
    #  退出
    # ============================================================
    def on_close(self):
        if self.scan_running:
            ret = ttk.Messagebox.show_question("扫描进行中",
                                               "扫描仍在进行，确定退出？未完成的结果将丢失。",
                                               buttons=["是", "否"],
                                               parent=self.root)
            if ret != "是":
                return
            self.stop_event.set()
        self.root.destroy()


def main():
    root = ttk.Window(themename="flatly")
    app = VirusScannerGUI(root)
    # SMTP 配置回填
    try:
        cfg = gfe.load_smtp_config()
        app.smtp_host.insert(0, cfg.get("host", "smtp.qq.com"))
        app.smtp_port.insert(0, str(cfg.get("port", 587)))
        app.smtp_auth.insert(0, cfg.get("auth_code", ""))
    except Exception:
        pass
    root.mainloop()


if __name__ == "__main__":
    main()
