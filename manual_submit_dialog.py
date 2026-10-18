# -*- coding: utf-8 -*-
"""人工提交向导窗口。

给「无法自动上传」的厂商（论坛 / 工单 / 只收 URL / Cloudflare 拦截）提供一个
逐项走查的窗口：展示厂商、网址、文件、报毒信息，一键打开上传页面，
人工传完后点「已上传」确认，再点「下一个」继续。
"""

from __future__ import annotations

import tkinter as tk
import webbrowser
from pathlib import Path

import ttkbootstrap as ttk
from ttkbootstrap.constants import *

KIND_TEXT = {
    "file_form": "网页表单（可传文件）",
    "hash_form": "网页表单（提交哈希）",
    "url_form": "仅受理 URL / 域名",
    "forum": "官方论坛发帖",
    "ticket": "工单系统（需登录）",
    "blocked": "人机验证拦截",
    "guide": "官方说明页",
    "unknown": "未知方式",
}

KIND_HINT = {
    "file_form": "在该页面选择文件并上传，填好邮箱与误报说明后提交。若要求登录，先登录再传。",
    "hash_form": "只需填 SHA256 与误报说明，不必上传文件本体；提交后留意邮箱回执。",
    "url_form": "该厂商只处理 URL / 域名类误报，文件样本可能不受理；可附上 SHA256 说明来源。",
    "forum": "需注册账号后发帖，正文附文件名、SHA256、VT 链接与误报说明。",
    "ticket": "需登录工单系统后新建请求，把 SHA256 与样本链接填进描述。",
    "blocked": "页面有人机验证，脚本无法直接访问；在浏览器里过验证后即可正常提交。",
    "guide": "这是官方说明页，请按页面指引进入实际的样本提交入口再上传。",
}


class ManualSubmitDialog:
    """逐项人工提交向导。

    entries: [{
        "engine","url","file_name","file_path","sha256","threat","kind","note","prefilled"
    }]
    on_done: 关闭时回调，参数 {index: "submitted"|"skipped"}
    """

    def __init__(self, parent, entries, on_done=None, title="人工提交向导"):
        self.parent = parent
        self.entries = list(entries)
        self.idx = 0
        self.results: dict[int, str] = {}
        self.on_done = on_done
        self._closed = False

        self.top = ttk.Toplevel(parent)
        self.top.title(title)
        self.top.geometry("900x600")
        self.top.minsize(820, 560)
        self.top.transient(parent)
        self.top.protocol("WM_DELETE_WINDOW", self._finish)
        self.top.bind("<Escape>", lambda e: self._finish())

        self._build()
        self._render()
        self._fit()

    def _fit(self):
        """按内容高度收紧窗口，避免大片空白。"""
        try:
            self.top.update_idletasks()
            need = self.top.winfo_reqheight()
            self.top.geometry(f"900x{min(max(need, 500), 700)}")
        except Exception:
            pass

    # ---------------- UI ----------------

    def _build(self):
        self.top.configure(bg="#ffffff")

        head = ttk.Frame(self.top, padding=(20, 16, 20, 4))
        head.pack(fill=X)
        ttk.Label(head, text="人工提交向导", style="PageTitle.TLabel").pack(side=LEFT)
        self.progress_label = ttk.Label(head, text="", style="PageSub.TLabel")
        self.progress_label.pack(side=RIGHT)

        ttk.Label(
            self.top,
            text="这些厂商没有邮箱、也无法自动上传。点「打开上传页面」在浏览器里手动提交，"
                 "传完回来点「已上传」，再点「下一个」继续。",
            style="PageSub.TLabel", wraplength=860, justify=LEFT
        ).pack(fill=X, padx=20, pady=(0, 12))

        card = ttk.Frame(self.top, padding=(18, 16), style="Card.TFrame")
        card.pack(fill=X, padx=20)

        # 厂商名 + 提交方式徽标
        title_row = ttk.Frame(card, style="Card.TFrame")
        title_row.grid(row=0, column=0, columnspan=2, sticky=EW, pady=(0, 10))
        self.vendor_label = ttk.Label(title_row, text="", style="CardTitle.TLabel",
                                      font=("微软雅黑", 16, "bold"))
        self.vendor_label.pack(side=LEFT)
        self.kind_label = ttk.Label(title_row, text="", style="CardSub.TLabel")
        self.kind_label.pack(side=LEFT, padx=(12, 0), pady=(4, 0))

        ttk.Separator(card, orient=HORIZONTAL).grid(
            row=1, column=0, columnspan=2, sticky=EW, pady=(0, 12))

        self.info = {}
        rows = [
            ("url", "上传网址", "copy_open"),
            ("file_name", "文件名", None),
            ("file_path", "文件路径", "copy"),
            ("sha256", "SHA256", "copy"),
            ("threat", "报毒信息", None),
        ]
        for i, (key, label, action) in enumerate(rows):
            r = i + 2
            ttk.Label(card, text=label, style="CardSub.TLabel",
                      width=10, anchor=E).grid(row=r, column=0, sticky=NE, pady=6, padx=(0, 10))
            if action:
                wrap = ttk.Frame(card, style="Card.TFrame")
                wrap.grid(row=r, column=1, sticky=EW, pady=6)
                var = tk.StringVar()
                ttk.Entry(wrap, textvariable=var, state="readonly",
                          font=("Cascadia Mono", 9)).pack(side=LEFT, fill=X, expand=True)
                if action == "copy_open":
                    ttk.Button(wrap, text="打开", width=6, style="Outline.TButton",
                               command=self._open_current).pack(side=LEFT, padx=(6, 0))
                ttk.Button(wrap, text="复制", width=6, style="Outline.TButton",
                           command=lambda v=var: self._copy(v.get())).pack(side=LEFT, padx=(6, 0))
                self.info[key] = var
            else:
                var = tk.StringVar()
                ttk.Label(card, textvariable=var, style="CardTitle.TLabel",
                          wraplength=680, justify=LEFT).grid(row=r, column=1, sticky=W, pady=6)
                self.info[key] = var

        ttk.Separator(card, orient=HORIZONTAL).grid(
            row=7, column=0, columnspan=2, sticky=EW, pady=(12, 10))

        ttk.Label(card, text="说明", style="CardSub.TLabel",
                  width=10, anchor=E).grid(row=8, column=0, sticky=NE, padx=(0, 10))
        note_box = ttk.Frame(card, style="CardAlt.TFrame", padding=10)
        note_box.grid(row=8, column=1, sticky=EW)
        self.note_label = ttk.Label(note_box, text="—", style="CardSub.TLabel",
                                    wraplength=640, justify=LEFT)
        self.note_label.pack(fill=X)

        card.columnconfigure(1, weight=1)

        hint_box = ttk.Frame(self.top, style="Card.TFrame")
        hint_box.pack(fill=X, padx=20, pady=(12, 0))
        self.hint_label = ttk.Label(hint_box, text="", style="CardSub.TLabel",
                                    wraplength=820, justify=LEFT)
        self.hint_label.pack(fill=X)

        self.status = ttk.Label(self.top, text="", style="PageSub.TLabel")
        self.status.pack(fill=X, padx=20, pady=(8, 0))

        btns = ttk.Frame(self.top, padding=(20, 10, 20, 16))
        btns.pack(fill=X)
        ttk.Button(btns, text="打开上传页面", style="Primary.TButton",
                   command=self._open_current).pack(side=LEFT)
        ttk.Button(btns, text="已上传，下一个", style="Success.TButton",
                   command=self._confirm).pack(side=LEFT, padx=(8, 0))
        self.next_btn = ttk.Button(btns, text="下一个（跳过）", style="Outline.TButton",
                                   command=self._skip)
        self.next_btn.pack(side=LEFT, padx=(8, 0))
        ttk.Button(btns, text="结束", style="Outline.TButton",
                   command=self._finish).pack(side=RIGHT)

    # ---------------- 行为 ----------------

    def _copy(self, text):
        if not text or text == "—":
            return
        try:
            self.top.clipboard_clear()
            self.top.clipboard_append(text)
            self.status.configure(text="已复制到剪贴板")
        except Exception as exc:
            self.status.configure(text=f"复制失败：{exc}")

    def _current(self):
        return self.entries[self.idx] if 0 <= self.idx < len(self.entries) else None

    def _open_current(self):
        e = self._current()
        if not e or not e.get("url"):
            self.status.configure(text="该条目没有可打开的网址")
            return
        try:
            webbrowser.open(e["url"])
            self.status.configure(text=f"已在浏览器打开：{e['url']}")
        except Exception as exc:
            self.status.configure(text=f"打开失败：{exc}")

    def _confirm(self):
        self.results[self.idx] = "submitted"
        self._advance()

    def _skip(self):
        self.results[self.idx] = "skipped"
        self._advance()

    def _advance(self):
        if self.idx + 1 < len(self.entries):
            self.idx += 1
            self._render()
        else:
            self.status.configure(text="已是最后一项，点「结束」收尾")
            self._render()

    def _render(self):
        e = self._current()
        if not e:
            return
        total = len(self.entries)
        done = sum(1 for v in self.results.values() if v == "submitted")
        self.progress_label.configure(
            text=f"第 {self.idx + 1} / {total} 项　·　已确认 {done}")
        self.vendor_label.configure(text=e.get("engine", ""))
        self.kind_label.configure(
            text=KIND_TEXT.get(e.get("kind", ""), e.get("kind", "")))
        self.info["url"].set(e.get("url", "") or "—")
        self.info["file_name"].set(e.get("file_name", "") or "—")
        self.info["file_path"].set(e.get("file_path", "") or "—")
        self.info["sha256"].set(e.get("sha256", "") or "—")
        self.info["threat"].set(e.get("threat", "") or "—")

        note = e.get("note") or ""
        if e.get("prefilled"):
            note = (note + "　该页面已由程序打开并预填，可直接在浏览器完成验证码后提交").strip()
        self.note_label.configure(text=note or "—")
        self.hint_label.configure(
            text="提示：" + KIND_HINT.get(e.get("kind", ""),
                                         "按页面要求填写并提交，完成后回到此窗口确认。"))

        last = self.idx + 1 >= total
        self.next_btn.configure(text="完成" if last else "下一个（跳过）",
                                command=self._finish if last else self._skip)
        mark = self.results.get(self.idx)
        if mark == "submitted":
            self.status.configure(text="本项已标记为「已上传」")
        elif mark == "skipped":
            self.status.configure(text="本项已标记为「跳过」")
        else:
            self.status.configure(text="")

    def _finish(self):
        if self._closed:
            return
        self._closed = True
        try:
            self.top.destroy()
        except Exception:
            pass
        if self.on_done:
            self.on_done(dict(self.results))
