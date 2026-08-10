"""
误报申诉邮件生成器
读取 detections_* 目录下的报毒 JSON → 匹配厂家联系方式 → 按模板生成邮件

用法:
  python generate_fp_emails.py <detections目录路径>
  python generate_fp_emails.py scan_reports\detections_20260731_120000
"""

import json
import sys
from pathlib import Path

# ========== 厂家联系方式表（从 VirusTotal 误报联系方式汇总.md 提取） ==========
VENDOR_CONTACTS = {
    "360": "kefu@360.cn",
    "Abusix": "support@abusix.com",
    "Acronis": "virustotal-falsepositive@acronis.com",
    "ADMINUSLabs": "samples@adminus.net",
    "AegisLab": "support@aegislab.com",
    "Ahnlab": "v3sos@ahnlab.com",
    "AILabs": "aicc@monitorapp.com",
    "Alibaba": "virustotal@list.alibaba-inc.com",
    "AliCloud": "antivirus@alibabacloud.com",
    "AlienVault": "otx-support@alienvault.com",
    "AlphaMountain": "support@alphamountain.ai",
    "AlphaSOC": "virustotal@alphasoc.com",
    "Alyac": "esrc@estsecurity.com",
    "Antiy": "avlsdk_support@antiy.cn",
    "APEX": "https://www.secureage.com/contact-us",
    "Arcabit": "vt.fp@arcabit.pl",
    "ArcSight": "virustotalsupport@opentext.com",
    "AutoShun": "info@autoshun.org",
    "Avast": "DL-Virus@gendigital.com",
    "Baidu": "bav@baidu.com",
    "Blueliv": "klabs_services@outpost24.com",
    "BitDefender": "virus_submission@bitdefender.com",
    "Bkav": "fpreport@bkav.com",
    "Certego": "fp@certego.net",
    "ChainPatrol": "dispute@chainpatrol.io",
    "Chong Lua Dao": "info@chongluadao.vn",
    "Clean-MX": "abuse@clean-mx.de",
    "Cluster25": "threatintel@cluster25.io",
    "CMC": "PSIRT@cmccybersecurity.com",
    "Criminal IP": "support@aispera.com",
    "CrowdStrike": "VTscanner@crowdstrike.com",
    "CSIS": "abuse-reporting@csis.com",
    "CTX": "root@malwares.com",
    "CyanSecurity": "virustotal@cyansecurity.com",
    "Cybereason": "vt-feedback@cybereason.com",
    "Cyble": "cyblevt_patnership@cyble.com",
    "Cylance": "virustotal@arcticwolf.com",
    "Cynet": "soc@cynet.com",
    "CyRadar": "virustotal@cyradar.com",
    "Deep Instinct": "vt-fps-requests@deepinstinct.com",
    "Desenmascara.me": "vt-falsepositives@desenmascara.me",
    "DNS8": "dns8@layer8.pt",
    "DrWeb": "vms@drweb.com",
    "eGambit": "virus@tehtris.com",
    "Emsisoft": "submit@emsisoft.com",
    "EmergingThreats": "support@emergingthreats.net",
    "Ermes": "support-vt@ermes.company",
    "FireEye": "virustotal@fireeye.com",
    "F-Prot": "viruslab@f-prot.com",
    "Fortinet": "https://www.fortiguard.com/faq/classificationdispute",
    "GData": "https://www.gdata.de/help/en/general/GeneralInformation/submitFileAppURL/",
    "Google": "google-at-virustotal@google.com",
    "GreenSnow": "https://greensnow.co/contact",
    "Gridinsoft": "virus@gridinsoft.com",
    "Guardpot": "virustotal@guardpot.com",
    "Hacksoft": "virus@hacksoft.com.pe",
    "Hauri": "viruslab@hauri.co.kr",
    "Heimdal": "report-vt@heimdalsecurity.com",
    "Hunt.io": "k.lo@hunt.io",
    "Huorong": "seclab@huorong.cn",
    "Hoplite": "vt-info@hopliteindustries.com",
    "Ikarus": "fp@ikarus.at",
    "Inca": "virus_info@inca.co.kr",
    "Jiangmin": "support@jiangmin.com",
    "K7": "reportfp@labs.k7computing.com",
    "Kaspersky": "newvirus@kaspersky.com",
    "Kingsoft": "ti@mingting.cn",
    "Lionic": "support@lionic.com",
    "Lumu": "vt@lumu.io",
    "Malbeacon": "vtreport@malbeacon.com",
    "Malwares.com": "kog@stsc.com",
    "MalwarePatrol": "fp@malwarepatrol.net",
    "MalwareURL": "team@malwareurl.com",
    "MaxSecure": "tech@maxpcsecure.com",
    "McAfee": "virus_research@mcafee.com",
    "Microworld": "samples@escanav.com",
    "Mimecast": "bep-soc@mimecast.com",
    "NANO": "false@nanoav.ru",
    "Openphish": "support@openphish.com",
    "Palo Alto": "vt-pan-false-positive@paloaltonetworks.com",
    "Panda": "falsepositives@pandasecurity.com",
    "PhishLabs": "info@phishlabs.com",
    "Qihoo360": "support@360safe.com",
    "QuickHeal": "viruslab@quickheal.com",
    "Quttera": "support@quttera.com",
    "Rising": "fp@rising.com.cn",
    "SafeToOpen": "virustotal@safetoopen.com",
    "Sansec": "virustotal@sansec.io",
    "Sangfor": "virustotal@sangfor.com.cn",
    "Scantitan": "fp@scantitan.com",
    "Seclookup": "info@seclookup.com",
    "Sentinel One": "report@sentinelone.com",
    "Skyhigh": "GatewayAnti-Malware-SupportEscalations@SkyhighSecurity.com",
    "SOCRadar": "vt@socradar.io",
    "Sophos": "samples@sophos.com",
    "Sucuri": "soc@sucuri.net",
    "Tencent": "TAVfp@tencent.com",
    "TheHacker": "virus@hacksoft.com.pe",
    "ThreatHive": "adam@threathive.com",
    "Trapmine": "fp@trapmine.com",
    "Trellix": "datasubmission@trellix.com",
    "TrendMicro": "virus@trendmicro.com",
    "Trustwave": "LevelBlueVirusTotalEscalations@levelblue.com",
    "Trustlook": "bd@trustlook.com",
    "URLHaus": "vt-fp@abuse.ch",
    "URLQuery": "contact@urlquery.net",
    "Varist": "support@varist.com",
    "VBA32": "feedback@anti-virus.by",
    "Viettel": "cyberthreat@viettel.com.vn",
    "VirIT": "virustotal@viritpro.com",
    "VirusDie": "partners@virusdie.com",
    "Xcitium": "support@xcitium.com",
    "Yomi": "yomi-false-positives@yoroi.company",
    "Yandex": "yandex-antivir@support.yandex.ru",
    "ZeroFox": "ask@zerofox.com",
    "Zillya": "support@zillya.com",
    "ZoneAlarm": "zonealarm_VT_reports@checkpoint.com",
    "Zoner": "false@zonerantivirus.com",
    "Antivir": "https://www.avira.com/en/analysis/submit-url",
    "AVG": "http://www.avg.com/submit-sample",
    "ClamAV": "http://www.clamav.net/reports/fp",
    "CRDF": "https://threatcenter.crdf.fr/false_positive.html",
    "Elastic": "https://discuss.elastic.co/t/submitting-false-positives/232322",
    "ESET": "https://support.eset.com/kb141/",
    "F-Secure": "https://www.withsecure.com/en/support/contact-support/submit-a-sample",
    "Forcepoint": "reviewmysite@forcepoint.com",
    "Malwarebytes": "https://forums.malwarebytes.com/forum/122-false-positives/",
    "Microsoft": "https://www.microsoft.com/en-us/wdsi/filesubmission",
    "Netcraft": "https://report.netcraft.com/report/mistake",
    "PhishTank": "https://www.phishtank.com/contact.php",
    "Prebytes": "https://www.support.prebytes.com/helpcenter/removals/",
    "Scumware.org": "https://www.scumware.org/removals.php",
    "SecureAge": "https://www.secureage.com/contact-us",
    "Securolytics": "https://tickets.securolytics.io/portal/en/kb/securolytics-1",
    "Spam404": "https://www.spam404.com/revision-request-domain.html",
    "Stopforumspam": "https://www.stopforumspam.com/removal",
    "Spamhaus": "https://www.spamhaus.org/dbl/removal/form/",
    "Symantec": "https://symsubmit.symantec.com",
    "Vipre": "https://helpdesk.vipre.com/hc/en-us/requests/new",
    "Webroot": "https://www.webroot.com/us/en/business/support/vendor-dispute-contact-us",
    "WithSecure": "spyware-samples@f-secure.com",
}

SENDER_EMAIL = "1041032635@qq.com"
SENDER_NAME = "cattle_chen"

# ========== SMTP 配置 ==========
SMTP_CONFIG_FILE = Path(__file__).parent / "smtp_config.json"

SMTP_DEFAULTS = {
    "host": "smtp.qq.com",
    "port": 587,
    "auth_code": "",
}


def load_smtp_config():
    """加载 SMTP 配置，文件不存在则返回默认空配置"""
    if SMTP_CONFIG_FILE.exists():
        with open(SMTP_CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return dict(SMTP_DEFAULTS)


def save_smtp_config(config):
    """保存 SMTP 配置到文件"""
    SMTP_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(SMTP_CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)


def send_fp_email(recipient, subject, body, attachment_path=None):
    """通过 SMTP 发送误报申诉邮件，可选附件。返回 (成功, 错误信息)"""
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    from email.mime.base import MIMEBase
    from email import encoders

    config = load_smtp_config()
    auth_code = config.get("auth_code", "")
    if not auth_code:
        return False, "SMTP 授权码未配置"

    if attachment_path and Path(attachment_path).is_file():
        msg = MIMEMultipart()
        msg.attach(MIMEText(body, "plain", "utf-8"))
        with open(attachment_path, "rb") as af:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(af.read())
            encoders.encode_base64(part)
            part.add_header(
                "Content-Disposition",
                f'attachment; filename="{Path(attachment_path).name}"'
            )
            msg.attach(part)
    else:
        msg = MIMEText(body, "plain", "utf-8")

    msg["From"] = SENDER_EMAIL
    msg["To"] = recipient
    msg["Subject"] = subject

    try:
        server = smtplib.SMTP(config["host"], config["port"], timeout=30)
        server.starttls()
        server.login(SENDER_EMAIL, auth_code)
        server.sendmail(SENDER_EMAIL, [recipient], msg.as_string())
        server.quit()
        return True, None
    except smtplib.SMTPAuthenticationError:
        return False, "SMTP 认证失败：授权码无效"
    except smtplib.SMTPException as e:
        return False, str(e)
    except Exception as e:
        return False, str(e)


# ========== GitHub 误报仓库上传 ==========
FP_REPO_DIR = Path(__file__).parent.parent / "False-Positive-Report"
FP_REPO_URL = "https://github.com/huangli007/False-Positive-Report"


def upload_to_github(file_path, project_name):
    """将报毒文件上传到 GitHub 误报仓库，返回 GitHub 文件 URL 或 None"""
    import shutil
    import subprocess

    src = Path(file_path)
    if not src.is_file():
        return None

    if not FP_REPO_DIR.is_dir():
        return None

    # 目标目录: repo/project_name/
    dest_dir = FP_REPO_DIR / project_name
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / src.name

    # 避免同名覆盖：加序号
    if dest.exists():
        stem, suffix = dest.stem, dest.suffix
        i = 1
        while dest.exists():
            dest = dest_dir / f"{stem}_{i}{suffix}"
            i += 1

    shutil.copy2(src, dest)

    try:
        subprocess.run(["git", "pull", "--rebase"], cwd=FP_REPO_DIR,
                       capture_output=True, text=True, timeout=30)
        subprocess.run(["git", "add", str(dest.relative_to(FP_REPO_DIR))], cwd=FP_REPO_DIR,
                       capture_output=True, text=True, timeout=10)
        commit_msg = f"Add {project_name}/{dest.name}"
        subprocess.run(["git", "commit", "-m", commit_msg], cwd=FP_REPO_DIR,
                       capture_output=True, text=True, timeout=10)
        subprocess.run(["git", "push"], cwd=FP_REPO_DIR,
                       capture_output=True, text=True, timeout=60)
    except Exception:
        return None

    # 构造 GitHub raw URL
    branch = "main"
    rel = dest.relative_to(FP_REPO_DIR).as_posix()
    return f"{FP_REPO_URL}/blob/{branch}/{rel}"


def generate_email(file_name, sha256, vt_link, engine, threat, github_link=None):
    """按模板生成邮件正文，可选 GitHub 链接。无邮箱时返回 None"""
    contact = VENDOR_CONTACTS.get(engine, "")
    if not contact or contact.startswith("http"):
        return None, contact or "(未找到联系方式)"

    body = f"""I'm writing to report a false positive detection on my legitimate file.

1. File name: {file_name}
2. SHA256: {sha256}
3. VirusTotal link: {vt_link}
4. Detection engine: {engine}
5. Detection name: {threat}

This file is a false alarm file. It contains no malicious behavior. Please verify and correct this false alarm in your signature/database. Thank you for your support."""

    if github_link:
        body += f"""

Sample file has been uploaded to our GitHub repository for your convenience:
{github_link}"""

    body += f"""

BR,
{SENDER_NAME}
{SENDER_EMAIL}"""
    return body, contact


def main():
    if len(sys.argv) < 2:
        print("用法: python generate_fp_emails.py <detections目录路径>")
        sys.exit(1)

    det_dir = Path(sys.argv[1])
    if not det_dir.is_dir():
        print(f"[错误] 目录不存在: {det_dir}")
        sys.exit(1)

    json_files = sorted(det_dir.glob("*.json"))
    if not json_files:
        print(f"[错误] 目录下没有 JSON 文件: {det_dir}")
        sys.exit(1)

    output_dir = det_dir.parent / f"emails_{det_dir.name.split('_', 1)[-1]}"
    output_dir.mkdir(parents=True, exist_ok=True)

    all_emails = []

    for jf in json_files:
        with open(jf, "r", encoding="utf-8") as f:
            data = json.load(f)

        file_name = data.get("file_name", jf.stem)
        sha256 = data.get("sha256", "")
        vt_link = data.get("virus_total_link", "")
        detections = data.get("detections", [])

        for det in detections:
            engine = det.get("engine", "Unknown")
            threat = det.get("name", "Unknown")
            body, recipient = generate_email(file_name, sha256, vt_link, engine, threat)
            if body is None:
                print(f"  [{engine}] → 跳过 (无邮箱)")
                continue

            # 生成独立邮件文件
            safe_file = "".join(c if c.isalnum() or c in "._- " else "_" for c in file_name)
            safe_engine = "".join(c if c.isalnum() or c in "._- " else "_" for c in engine)
            email_path = output_dir / f"{safe_file}__{safe_engine}.txt"
            with open(email_path, "w", encoding="utf-8") as f:
                f.write(f"To: {recipient}\n")
                f.write(f"Subject: VirusTotal False Positive Report\n")
                f.write(f"{'=' * 60}\n\n")
                f.write(body)

            all_emails.append({
                "file": file_name,
                "engine": engine,
                "threat": threat,
                "recipient": recipient,
                "path": str(email_path),
            })

            print(f"  [{engine}] → {recipient}")

    # 汇总
    print(f"\n{'=' * 60}")
    print(f"  共生成 {len(all_emails)} 封邮件")
    print(f"  邮件目录: {output_dir}")

    summary_path = output_dir / "_summary.txt"
    with open(summary_path, "w", encoding="utf-8") as f:
        for e in all_emails:
            f.write(f"[{e['file']}] {e['engine']}: {e['threat']} → {e['recipient']}\n")
    print(f"  汇总清单: {summary_path}")
    print(f"{'=' * 60}\n")


if __name__ == "__main__":
    main()
