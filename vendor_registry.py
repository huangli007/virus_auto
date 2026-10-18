# -*- coding: utf-8 -*-
"""厂商申报端点注册表。

把 `generate_fp_emails.VENDOR_CONTACTS`（141 家）升级成带提交能力的结构：
除了「有没有邮箱」，还描述「能不能自动上传文件」「提交页是什么形态」。

kind 取值：
  email      —— 有邮箱，走 SMTP 申诉链路（generate_fp_emails）
  file_form  —— 网页表单且含文件上传框，可自动上传样本
  hash_form  —— 网页表单只收 SHA256/哈希，不传文件也能自动提交
  url_form   —— 只受理 URL / 域名误报，与文件样本无关
  forum      —— 论坛帖 / 社区讨论区，只能人工发帖
  ticket     —— 工单系统，需登录
  blocked    —— Cloudflare Turnstile 人机验证拦住脚本访问，需人工打开
  guide      —— 厂商说明文档，本身没有提交入口

url 字段统一指向「人工或自动提交的落点」；contact 保留原始联系方式。
分类依据：2026-10 对全部 25 个无邮箱厂商页面做的实际探测（headless + headed 两轮）。
"""

from __future__ import annotations

from generate_fp_emails import VENDOR_CONTACTS

# ------------------------------------------------------------------
# 无邮箱厂商的提交能力（探测结果 + 人工校正）
# ------------------------------------------------------------------
_NO_EMAIL_PROFILE: dict[str, dict] = {
    # ---- 有真实文件上传框 ----
    "Symantec": {
        "kind": "file_form",
        "url": "https://symsubmit.symantec.com",
        "captcha": True,
        "note": "Symantec/Carbon Black FN-FP Submission Portal，3 个上传框，含 reCAPTCHA",
    },
    "Microsoft": {
        "kind": "file_form",
        "url": "https://www.microsoft.com/en-us/wdsi/filesubmission",
        "captcha": True,
        "login": True,
        "note": "WDSI 文件提交，需 Microsoft 账号登录后才有上传框",
    },
    "SecureAge": {
        "kind": "file_form",
        "url": "https://www.secureage.com/contact-us",
        "captcha": True,
        "note": "通用联系表单，含文件上传，Cloudflare Turnstile",
    },
    "APEX": {
        "kind": "file_form",
        "url": "https://www.secureage.com/contact-us",
        "captcha": True,
        "note": "与 SecureAge 同一表单（APEX 为 SecureAge 引擎名）",
    },
    "AVG": {
        "kind": "file_form",
        "url": "https://www.avg.com/en-us/submit-sample",
        "captcha": True,
        "note": "False Positive File Form，含文件上传框 + reCAPTCHA；无头浏览器会被拦，需可见模式",
    },

    # ---- Cloudflare Turnstile 拦住脚本访问，需人工打开 ----
    "ClamAV": {"kind": "blocked", "url": "https://www.clamav.net/reports/fp",
               "note": "Turnstile 人机验证拦截脚本，需人工打开；也可用官方 clamsubmit 命令行"},
    "Malwarebytes": {"kind": "forum",
                     "url": "https://forums.malwarebytes.com/forum/122-false-positives/",
                     "note": "官方论坛 False Positives 版块，需注册发帖（Turnstile 验证）"},
    "Spamhaus": {"kind": "url_form", "url": "https://www.spamhaus.org/dbl/removal/form/",
                 "note": "DBL 域名移除，非文件样本（Turnstile 验证）"},
    "Vipre": {"kind": "ticket", "url": "https://helpdesk.vipre.com/hc/en-us/requests/new",
              "note": "Zendesk 工单，需登录（Turnstile 验证）"},

    # ---- 只收哈希 / 只能网页表单，无文件上传框 ----
    "Fortinet": {
        "kind": "hash_form",
        "url": "https://www.fortiguard.com/faq/classificationdispute",
        "hash_field": "hash",
        "captcha": True,
        "note": "Classification Dispute Form：填 SHA256 + 说明即可，无需上传文件",
    },
    "GreenSnow": {
        "kind": "hash_form",
        "url": "https://greensnow.co/contact",
        "hash_field": "hash",
        "note": "联系表单含 hash 字段",
    },
    "CRDF": {
        "kind": "hash_form",
        "url": "https://threatcenter.crdf.fr/false_positive.html",
        "captcha": True,
        "note": "False positive 表单，含邮箱与说明",
    },

    # ---- 只受理 URL / 域名 ----
    "Netcraft": {"kind": "url_form", "url": "https://report.netcraft.com/report/mistake",
                 "note": "仅受理 URL/域名误判"},
    "PhishTank": {"kind": "url_form", "url": "https://www.phishtank.com/contact.php",
                  "note": "钓鱼站点申诉，非文件样本"},
    "Spam404": {"kind": "url_form", "url": "https://www.spam404.com/revision-request-domain.html",
                "note": "仅受理域名"},
    "Scumware.org": {"kind": "url_form", "url": "https://www.scumware.org/removals.php",
                     "note": "仅受理域名/URL"},
    "Stopforumspam": {"kind": "url_form", "url": "https://www.stopforumspam.com/removal",
                      "note": "垃圾邮件 IP/邮箱移除，非文件样本"},
    "Webroot": {"kind": "url_form",
                "url": "https://www.webroot.com/us/en/business/support/vendor-dispute-contact-us",
                "note": "厂商争议联系页，需人工沟通"},
    "Antivir": {"kind": "url_form", "url": "https://www.avira.com/en/analysis/submit-url",
                "note": "Avira 只受理可疑 URL（Submit suspicious URL），不接受文件样本"},

    # ---- 论坛 / 工单 / 说明页 ----
    "Elastic": {"kind": "forum",
                "url": "https://discuss.elastic.co/t/submitting-false-positives/232322",
                "note": "官方讨论区，按帖子流程提交"},
    "Prebytes": {"kind": "ticket", "url": "https://www.support.prebytes.com/helpcenter/removals/",
                 "note": "Jira Service Management 工单，需登录"},
    "Securolytics": {"kind": "ticket",
                     "url": "https://tickets.securolytics.io/portal/en/kb/securolytics-1",
                     "note": "工单门户，需登录"},
    "ESET": {"kind": "guide", "url": "https://support.eset.com/kb141/",
             "note": "官方说明页，实际提交需进入 ESET 样本提交系统"},
    "F-Secure": {"kind": "guide",
                 "url": "https://www.withsecure.com/en/support/contact-support/submit-a-sample",
                 "note": "说明页，提交入口在 WithSecure 支持系统内"},
    "GData": {"kind": "guide",
              "url": "https://www.gdata.de/help/en/general/GeneralInformation/submitFileAppURL/",
              "note": "说明页，表单在 GData 帮助中心内"},
}

# ------------------------------------------------------------------
# 可选：支持 HTTP 直传的接口（无验证码、可无人值守）
# 目前没有厂商公开这类接口，保留结构供后续补录。
# ------------------------------------------------------------------
_HTTP_ENDPOINTS: dict[str, dict] = {}


def _build() -> dict[str, dict]:
    reg: dict[str, dict] = {}
    for engine, contact in VENDOR_CONTACTS.items():
        contact = str(contact or "").strip()
        if contact.startswith("http"):
            profile = dict(_NO_EMAIL_PROFILE.get(engine) or {})
            profile.setdefault("kind", "url_form")
            profile.setdefault("url", contact)
            profile["contact"] = contact
            profile["has_email"] = False
        else:
            profile = {"kind": "email", "contact": contact, "has_email": bool(contact),
                       "url": ""}
        if engine in _HTTP_ENDPOINTS:
            profile["http"] = _HTTP_ENDPOINTS[engine]
        reg[engine] = profile
    return reg


_REGISTRY: dict[str, dict] | None = None


def get_registry() -> dict[str, dict]:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = _build()
    return _REGISTRY


def vendors_by_kind(kind: str) -> dict[str, dict]:
    return {k: v for k, v in get_registry().items() if v.get("kind") == kind}


def uploadable_vendors() -> dict[str, dict]:
    """能自动提交的厂商：file_form（传文件）+ hash_form（传哈希）。"""
    return {k: v for k, v in get_registry().items()
            if v.get("kind") in ("file_form", "hash_form")}


def summary() -> dict[str, int]:
    out: dict[str, int] = {}
    for v in get_registry().values():
        out[v.get("kind", "unknown")] = out.get(v.get("kind", "unknown"), 0) + 1
    return out


if __name__ == "__main__":
    reg = get_registry()
    print(f"厂商总数: {len(reg)}")
    for kind, n in sorted(summary().items(), key=lambda x: -x[1]):
        print(f"  {kind:12} {n}")
    print("\n可自动提交（file_form / hash_form）：")
    for k, v in uploadable_vendors().items():
        print(f"  {k:14} {v['kind']:10} {v['url']}")
