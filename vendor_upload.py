# -*- coding: utf-8 -*-
"""误报样本自动提交引擎。

给「没有邮箱、只能走网页表单」的厂商补一条自动上传通道。三层降级：

1. http    —— 厂商开放了无需验证码的上传接口，requests multipart 直传
2. browser —— Playwright 打开提交页，启发式填好文件 / SHA256 / 邮箱 / 描述；
              有验证码或登录墙时停在提交前，把窗口留给人工点两下
3. manual  —— 实在无法自动的，写进待提交清单（厂商 / 链接 / 文件 / SHA256）

依赖：requests 为必需；playwright 为可选，缺失时自动退化为 http + manual。
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Callable

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None


# ------------------------------------------------------------------
# 结果模型
# ------------------------------------------------------------------

STATUS_TEXT = {
    "submitted": "已提交",
    "needs_manual": "待人工提交",
    "unsupported": "不支持文件提交",
    "skipped": "已跳过",
    "failed": "失败",
}

# 只能人工提交的厂商类型（论坛 / 工单 / 只收 URL / 被人机验证拦）
MANUAL_KINDS = {"url_form", "forum", "ticket", "guide", "blocked"}


@dataclass
class SubmitResult:
    engine: str
    file_name: str
    file_path: str
    sha256: str
    status: str
    method: str = "none"
    url: str = ""
    detail: str = ""
    ts: str = ""

    def __post_init__(self):
        if not self.ts:
            self.ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    @property
    def ok(self) -> bool:
        return self.status in ("submitted", "needs_manual")

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status_text"] = STATUS_TEXT.get(self.status, self.status)
        return d


# ------------------------------------------------------------------
# 浏览器填表的启发式选择器
# ------------------------------------------------------------------

# 给页面元素打标记的脚本：按 name/id/placeholder/type 猜字段用途
_JS_MARK_FIELDS = r"""
() => {
  const all = [...document.querySelectorAll('input, textarea')];
  const vis = e => {
    const s = getComputedStyle(e);
    const r = e.getBoundingClientRect();
    return s.display !== 'none' && s.visibility !== 'hidden' && (r.width > 0 || r.height > 0);
  };
  const meta = e => ((e.name || '') + ' ' + (e.id || '') + ' ' + (e.placeholder || '') + ' ' +
                     (e.getAttribute('aria-label') || '')).toLowerCase();
  const SKIP = ['hidden', 'submit', 'button', 'checkbox', 'radio', 'file', 'range', 'color'];
  const pick = (re, mark) => {
    const cands = all.filter(e => !e.hasAttribute('data-vtu') && SKIP.indexOf(e.type) < 0);
    const hit = cands.find(e => re.test(meta(e)) && vis(e)) || cands.find(e => re.test(meta(e)));
    if (hit) { hit.setAttribute('data-vtu', mark); return true; }
    return false;
  };
  const out = {};
  // 文件
  const f = all.find(e => e.type === 'file' && !e.hasAttribute('data-vtu'));
  if (f) { f.setAttribute('data-vtu', 'file'); out.file = true; }
  // SHA256 / 哈希
  out.hash = pick(/sha256|sha-256|sha\b|hash|md5|checksum/, 'hash');
  // 邮箱
  out.email = pick(/mail/, 'email');
  // 说明 / 描述
  const ta = all.find(e => e.tagName === 'TEXTAREA' && vis(e) && !e.hasAttribute('data-vtu'))
          || all.find(e => e.tagName === 'TEXTAREA' && !e.hasAttribute('data-vtu'));
  if (ta) { ta.setAttribute('data-vtu', 'note'); out.note = true; }
  // 文件名 / 名称（仅在没匹配到 note 时补）
  if (!out.note) out.name = pick(/file.?name|sample|名称/, 'name');
  return out;
}
"""

_JS_CAPTCHA = r"""
() => {
  const hit = sel => !!document.querySelector(sel);
  const marks = [];
  if (hit("iframe[src*='recaptcha']") || hit("div.g-recaptcha")) marks.push('reCAPTCHA');
  if (hit("iframe[src*='hcaptcha']") || hit("div.h-captcha")) marks.push('hCaptcha');
  if (hit("div[class*='turnstile']") || hit("iframe[src*='challenges.cloudflare']")) marks.push('Turnstile');
  const body = (document.body ? document.body.innerText : '').toLowerCase();
  if (/verify you are (a )?human|not a robot|请输入验证码|图形验证码/.test(body)) marks.push('验证码');
  if (/sign in to (continue|submit)|log in to (continue|submit)|请先登录/.test(body)) marks.push('需登录');
  return marks;
}
"""

_COOKIE_TEXTS = (
    "Accept all", "Accept All", "Accept", "I agree", "Agree", "Got it", "OK",
    "同意", "全部接受", "接受全部", "我知道了",
)

_SUCCESS_HINTS = (
    "thank you", "thanks", "received", "success", "submitted", "has been submitted",
    "已收到", "已提交", "感谢",
)


class VendorSubmitter:
    """按厂商逐个提交样本，自动选择 http / browser / manual 三条路径。"""

    def __init__(
        self,
        *,
        email: str = "",
        name: str = "cattle_chen",
        headless: bool = False,
        timeout: int = 25,
        dry_run: bool = False,
        on_manual: Callable[[str, str, dict], bool] | None = None,
        on_progress: Callable[[str, str], None] | None = None,
        log: Callable[..., None] = print,
        registry: dict | None = None,
    ):
        self.email = email
        self.name = name
        self.headless = headless
        self.timeout = timeout
        self.dry_run = dry_run
        self.on_manual = on_manual
        self.on_progress = on_progress
        self.log = log

        if registry is None:
            from vendor_registry import get_registry
            registry = get_registry()
        self.registry = registry

        self._pw = None
        self._browser = None
        self._context = None

    # ---------------- 浏览器生命周期 ----------------

    def _ensure_browser(self):
        if self._browser is not None:
            return self._browser
        try:
            from playwright.sync_api import sync_playwright
        except Exception as exc:
            raise RuntimeError(f"playwright 不可用：{exc}") from exc

        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(
            headless=self.headless,
            args=["--disable-blink-features=AutomationControlled"],
        )
        self._context = self._browser.new_context(
            user_agent=("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"),
            locale="en-US",
            viewport={"width": 1280, "height": 900},
        )
        self._context.set_default_timeout(self.timeout * 1000)
        return self._browser

    def close(self):
        for obj in (self._context, self._browser):
            try:
                obj and obj.close()
            except Exception:
                pass
        try:
            self._pw and self._pw.stop()
        except Exception:
            pass
        self._pw = self._browser = self._context = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # ---------------- 对外主入口 ----------------

    def submit_one(self, engine: str, file_path: str, sha256: str, threat: str = "") -> SubmitResult:
        file_path = str(file_path)
        name = Path(file_path).name if file_path else "?"
        info = self.registry.get(engine) or {}
        kind = info.get("kind", "unknown")
        url = info.get("url", "")

        if kind not in ("file_form", "hash_form"):
            return SubmitResult(engine, name, file_path, sha256, "needs_manual",
                                method="manual", url=url,
                                detail=info.get("note") or "该厂商需人工在网站上提交")

        # hash_form 不传文件，文件不存在也能提交
        if kind == "file_form" and not Path(file_path).is_file():
            return SubmitResult(engine, name, file_path, sha256, "failed",
                                method="none", url=url, detail="本地文件不存在，无法上传")

        # 1) HTTP 直传
        http_cfg = info.get("http")
        if http_cfg:
            res = self._try_http(engine, file_path, sha256, threat, http_cfg, url)
            if res and res.status == "submitted":
                return res
            self.log(f"  [{engine}] HTTP 直传未成功（{res.detail if res else '无响应'}），改用浏览器")

        # 2) 浏览器填表
        res = self._try_browser(engine, file_path, sha256, threat, info)
        if res:
            return res

        # 3) 兜底
        return SubmitResult(engine, name, file_path, sha256, "needs_manual",
                            method="manual", url=url, detail="浏览器不可用，请按链接手工提交")

    def submit_batch(self, tasks: list[dict]) -> list[SubmitResult]:
        """tasks: [{engine, file_path, sha256, threat, mode}]；只跑 mode=auto 的条目。"""
        results: list[SubmitResult] = []
        auto_tasks = [t for t in tasks if t.get("mode", "auto") == "auto"]
        total = len(auto_tasks)
        for idx, t in enumerate(auto_tasks, 1):
            engine = t.get("engine", "?")
            fname = Path(t.get("file_path", "")).name
            if self.on_progress:
                self.on_progress(f"提交 {idx}/{total}",
                                 f"{engine} · {fname}")
            self.log(f"[{idx}/{total}] {engine} ← {fname}")
            try:
                r = self.submit_one(engine, t.get("file_path", ""), t.get("sha256", ""),
                                    t.get("threat", ""))
            except Exception as exc:
                r = SubmitResult(engine, fname, t.get("file_path", ""), t.get("sha256", ""),
                                 "failed", detail=f"{type(exc).__name__}: {exc}"[:200])
            results.append(r)
            self.log(f"  → {STATUS_TEXT.get(r.status, r.status)}"
                     + (f"：{r.detail}" if r.detail else ""))
        return results

    # ---------------- 第一层：HTTP 直传 ----------------

    def _try_http(self, engine, file_path, sha256, threat, cfg, page_url) -> SubmitResult | None:
        if requests is None:
            return None
        name = Path(file_path).name
        endpoint = cfg.get("endpoint")
        if not endpoint:
            return None
        field = cfg.get("file_field", "file")
        data = {"sha256": sha256, "threat": threat, "name": self.name}
        if self.email:
            data["email"] = self.email
        data.update(cfg.get("fields") or {})
        try:
            with open(file_path, "rb") as fh:
                files = {field: (name, fh, "application/octet-stream")}
                resp = requests.post(endpoint, data=data, files=files,
                                     timeout=cfg.get("timeout", 60),
                                     headers={"User-Agent": "VirusTotalScanner/5.0"})
        except Exception as exc:
            return SubmitResult(engine, name, file_path, sha256, "failed", method="http",
                                url=page_url, detail=f"HTTP 异常：{exc}"[:200])
        text = (resp.text or "").lower()
        if resp.status_code < 400 and any(h in text for h in _SUCCESS_HINTS):
            return SubmitResult(engine, name, file_path, sha256, "submitted", method="http",
                                url=page_url, detail=f"HTTP {resp.status_code}")
        return SubmitResult(engine, name, file_path, sha256, "failed", method="http",
                            url=page_url, detail=f"HTTP {resp.status_code}")

    # ---------------- 第二层：浏览器填表 ----------------

    def _try_browser(self, engine, file_path, sha256, threat, info) -> SubmitResult | None:
        name = Path(file_path).name if file_path else "?"
        url = info.get("url", "")
        kind = info.get("kind", "file_form")
        try:
            self._ensure_browser()
        except Exception as exc:
            return SubmitResult(engine, name, file_path, sha256, "needs_manual",
                                method="manual", url=url, detail=f"浏览器不可用：{exc}"[:120])

        page = self._context.new_page()
        keep = False
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=self.timeout * 1000)
            page.wait_for_timeout(1500)
            try:
                page.bring_to_front()   # 让窗口显示在最前，用户能看到填表过程
            except Exception:
                pass
            self._dismiss_cookies(page)

            marks = page.evaluate(_JS_MARK_FIELDS) or {}
            filled = []

            # --- 文件上传（file_form 必填）---
            if kind == "file_form":
                if not marks.get("file"):
                    keep = True
                    return self._hand_to_human(
                        engine, page, name, file_path, sha256,
                        "页面未找到文件上传框（可能需登录或页面结构变更）")
                try:
                    page.locator("[data-vtu='file']").first.set_input_files(file_path, timeout=20000)
                    filled.append("文件")
                except Exception as exc:
                    return SubmitResult(engine, name, file_path, sha256, "needs_manual",
                                        method="browser", url=page.url,
                                        detail=f"文件上传框写入失败：{exc}"[:160])

            # --- SHA256 ---
            if marks.get("hash"):
                try:
                    page.locator("[data-vtu='hash']").first.fill(sha256, timeout=5000)
                    filled.append("SHA256")
                except Exception:
                    pass

            # --- 邮箱 ---
            if marks.get("email") and self.email:
                try:
                    page.locator("[data-vtu='email']").first.fill(self.email, timeout=5000)
                    filled.append("邮箱")
                except Exception:
                    pass

            # --- 说明 ---
            if marks.get("note"):
                try:
                    note = (f"False positive report.\nFile: {name}\nSHA256: {sha256}\n"
                            f"Detection: {threat or engine}\nThis file is legitimate and "
                            f"contains no malicious behavior. Please re-verify.")
                    page.locator("[data-vtu='note']").first.fill(note, timeout=5000)
                    filled.append("说明")
                except Exception:
                    pass

            # hash_form 至少要有哈希框或说明框之一，否则无从提交
            if kind == "hash_form" and not (marks.get("hash") or marks.get("note")):
                keep = True
                return self._hand_to_human(engine, page, name, file_path, sha256,
                                           "页面未找到哈希或说明输入框，需人工填写")

            captcha = page.evaluate(_JS_CAPTCHA) or []
            detail_filled = "已填：" + "、".join(filled) if filled else "未填任何字段"

            # 试运行：只预填不提交，用于确认页面结构是否可自动
            if self.dry_run:
                keep = True
                return SubmitResult(
                    engine, name, file_path, sha256, "needs_manual", method="browser",
                    url=page.url,
                    detail=f"[试运行] {detail_filled}；"
                           f"验证码={'/'.join(captcha) if captcha else '未检测到'}")

            if captcha:
                keep = True
                return self._hand_to_human(engine, page, name, file_path, sha256,
                                           f"{detail_filled}；检测到 {'/'.join(captcha)}")

            # 无验证码 → 尝试自动提交
            clicked = self._click_submit(page)
            if not clicked:
                keep = True
                return self._hand_to_human(engine, page, name, file_path, sha256,
                                           f"{detail_filled}；未找到提交按钮")

            page.wait_for_timeout(3500)
            body = (page.content() or "").lower()
            if any(h in body for h in _SUCCESS_HINTS):
                keep = True   # 保留页面，用户可查看提交回执
                return SubmitResult(engine, name, file_path, sha256, "submitted",
                                    method="browser", url=page.url,
                                    detail=f"{detail_filled}；已自动提交并确认回执")
            keep = True
            return self._hand_to_human(engine, page, name, file_path, sha256,
                                       f"{detail_filled}；已点提交但未见回执，请人工确认")
        except Exception as exc:
            return SubmitResult(engine, name, file_path, sha256, "failed", method="browser",
                                url=url, detail=f"{type(exc).__name__}: {exc}"[:200])
        finally:
            if not keep:
                try:
                    page.close()
                except Exception:
                    pass

    def _hand_to_human(self, engine, page, name, file_path, sha256, detail) -> SubmitResult:
        """把已预填的页面交给人工：回调返回 True 视为已提交。"""
        url = page.url
        if self.on_manual:
            confirmed = self.on_manual(engine, url, {"file": file_path, "sha256": sha256})
            status = "submitted" if confirmed else "needs_manual"
        else:
            status = "needs_manual"
        return SubmitResult(engine, name, file_path, sha256, status, method="browser",
                            url=url, detail=detail)

    # ---------------- 页面交互小工具 ----------------

    @staticmethod
    def _dismiss_cookies(page):
        for text in _COOKIE_TEXTS:
            try:
                btn = page.get_by_role("button", name=text, exact=False)
                if btn.count() and btn.first.is_visible():
                    btn.first.click(timeout=2000)
                    page.wait_for_timeout(400)
                    return text
            except Exception:
                continue
        return ""

    @staticmethod
    def _click_submit(page) -> bool:
        candidates = [
            "button[type='submit']",
            "input[type='submit']",
            "button:has-text('Submit')",
            "button:has-text('提交')",
            "button:has-text('Upload')",
            "button:has-text('Send')",
            "button:has-text('Report')",
        ]
        for sel in candidates:
            try:
                loc = page.locator(sel)
                for i in range(min(loc.count(), 5)):
                    el = loc.nth(i)
                    if el.is_visible() and el.is_enabled():
                        el.click(timeout=4000)
                        return True
            except Exception:
                continue
        return False


# ------------------------------------------------------------------
# 从扫描记录生成任务
# ------------------------------------------------------------------

def build_tasks(records: list[dict], only_engines: set[str] | None = None,
                include_manual: bool = False) -> list[dict]:
    """把报毒记录展开成 (厂商, 文件) 任务。

    include_manual=True 时，连「只能人工提交」的厂商（论坛 / 工单 / 只收 URL / 被
    Cloudflare 拦）也一并生成，mode 标为 manual，供人工提交向导逐项走查。
    """
    from vendor_registry import get_registry

    reg = get_registry()
    tasks: list[dict] = []
    seen: set[tuple[str, str]] = set()

    for r in records:
        file_path = r.get("file_path") or r.get("filepath") or r.get("filename") or ""
        sha256 = r.get("sha256", "")
        dets = r.get("dets") or []
        if not dets:
            dets = [(en, info.get("result") or info.get("category") or "")
                    for en, info in (r.get("engines") or {}).items()
                    if info.get("category") in ("malicious", "suspicious")]
        for engine, threat in dets:
            info = reg.get(engine) or {}
            kind = info.get("kind")
            if kind in ("file_form", "hash_form"):
                mode = "auto"
            elif include_manual and kind in MANUAL_KINDS:
                mode = "manual"
            else:
                continue
            if only_engines and engine not in only_engines:
                continue
            # 传文件的按文件去重；只传哈希的按 SHA256 去重（同一文件只申一次）
            key = (engine, file_path) if kind == "file_form" else (engine, sha256)
            if key in seen:
                continue
            seen.add(key)
            tasks.append({
                "engine": engine,
                "file_path": file_path,
                "sha256": sha256,
                "threat": threat,
                "mode": mode,
                "kind": kind,
                "url": info.get("url", ""),
                "note": info.get("note", ""),
            })
    return tasks


# ------------------------------------------------------------------
# 报告落盘
# ------------------------------------------------------------------

def write_report(results: list[SubmitResult], out_dir: Path) -> dict:
    """写 _vendor_submit.md / _vendor_submit.json，返回统计。"""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    groups: dict[str, list[SubmitResult]] = {}
    for r in results:
        groups.setdefault(r.status, []).append(r)

    md = out_dir / "_vendor_submit.md"
    with open(md, "w", encoding="utf-8") as f:
        f.write("# 厂商网站自动提交记录\n\n")
        f.write(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for st in ("submitted", "needs_manual", "unsupported", "failed", "skipped"):
            items = groups.get(st) or []
            if items:
                f.write(f"- {STATUS_TEXT[st]}: **{len(items)}** 条\n")
        f.write("\n## 明细\n\n")
        f.write("| # | 厂商 | 文件 | SHA256 | 状态 | 方式 | 链接 | 说明 |\n")
        f.write("|---|------|------|--------|------|------|------|------|\n")
        for idx, r in enumerate(results, 1):
            sha_short = r.sha256[:12] + "..." if len(r.sha256) > 12 else r.sha256
            url = r.url or "—"
            f.write(f"| {idx} | {r.engine} | {r.file_name} | {sha_short} | "
                    f"{STATUS_TEXT.get(r.status, r.status)} | {r.method} | {url} | {r.detail} |\n")

        pending = groups.get("needs_manual") or []
        if pending:
            f.write("\n## 需人工完成的厂商\n\n")
            f.write("以下页面已自动打开并尽量预填，完成验证码后点提交即可：\n\n")
            by_engine: dict[str, list[SubmitResult]] = {}
            for r in pending:
                by_engine.setdefault(r.engine, []).append(r)
            for engine in sorted(by_engine):
                items = by_engine[engine]
                f.write(f"- **{engine}** — {items[0].url or '（无链接）'}"
                        f"（{len(items)} 个文件）\n")

    js = out_dir / "_vendor_submit.json"
    with open(js, "w", encoding="utf-8") as f:
        json.dump([r.to_dict() for r in results], f, ensure_ascii=False, indent=2)

    return {
        "total": len(results),
        "submitted": len(groups.get("submitted") or []),
        "needs_manual": len(groups.get("needs_manual") or []),
        "failed": len(groups.get("failed") or []),
        "md": str(md),
        "json": str(js),
    }
