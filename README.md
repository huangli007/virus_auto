# VirusTotal 批量扫描 & 误报申诉工具 v5.0

基于 VirusTotal API 的自动化安全扫描工具，支持批量文件扫描、报毒详情提取、逐封确认生成误报申诉邮件。

v5.0 新增：桌面端 GUI（扫描中心 / Key 管理 / 报告中心 / 邮件申诉 / 缓存管理）、全量扫描、申诉邮件内容确认窗、无邮箱厂商的官网申报网址记录。

## 功能

| 简写 | 等价参数 | 功能 |
|------|----------|------|
| `scan <路径>` | `-f` / `-p` | 指定文件或文件夹 → SHA-256 缓存查重 → VT 扫描 → HTML + JSON 报告 |
| `submit [项目]` | `--submit-vendors` | 把报毒样本提交到厂商网页表单；省略项目则用最近的报毒项目 |
| `email [项目]` | `--gen-emails` | 筛选报毒项，逐封确认生成并发送申诉邮件 |
| `err <项目>` | `--err` | 输出终端文本报毒测试报告 |
| `excel <项目>` | `--excel` | 导出报毒清单 Excel |
| `filter <项目>` | `--report-filter` | 生成仅含报毒项的 HTML 报告 |
| `keys` | `--list-keys` | 查看 Key 池与配额 |
| `cache` | `--cache-stats` | 查看本地缓存统计 |
| `cache-clear` | `--clear-cache` | 清空本地扫描缓存 |

```bash
python virus_scanner.py scan "D:\Downloads"     # 扫描
python virus_scanner.py submit                  # 提交最新报毒项目到厂商网站
python virus_scanner.py submit --dry            # 只预填不提交
python virus_scanner.py email                   # 发申诉邮件
python virus_scanner.py keys                    # 看 Key 配额
```

原有长参数全部保留，两种写法等价。

### 核心特性

- **多 Key 池**：配额耗尽自动切换，支持 key 文件批量导入
- **类型优先级**：exe/dll/sys 优先扫描
- **配额管控**：严格遵守 VT 公共 API 限制（4次/分钟，500次/天，155K次/月）
- **项目分类**：每次扫描创建独立项目目录 `projects/<名称>_<时间戳>/`，所有产出内聚
- **本地缓存**：SHA-256 索引，已扫描文件自动跳过上传，大幅节省配额
- **强制重扫**：`--no-cache` 忽略缓存强制上传
- **全量扫描**：`--full-scan` 忽略缓存且不按扩展名过滤，文本/配置类文件一并纳入扫描
- **报毒详情**：为每个报毒文件生成独立 JSON + Markdown
- **逐封确认**：生成申诉邮件前先展示全文，逐封 y/n/a/q，确认后自动通过 SMTP 发送
- **申诉记录**：确认后生成 `_sent.md`，表格记录已申诉文件及发送状态
- **无邮箱兜底**：厂商只提供网页表单或无公开联系方式时，写入 `_no_email.md` / `_no_email.json`，**同时记录官网申报网址**，并按厂商去重汇总成可直接点击的申诉入口
- **厂商网站直提**：`--submit-vendors` 对无邮箱厂商自动打开提交页并预填文件 / SHA256 / 邮箱 / 说明；有验证码时窗口保留等人工点两下，自动失败的转「人工提交向导」逐项走查。支持 HTTP 直传 → 浏览器填表 → 人工向导三层降级，结果写入 `_vendor_submit.md` / `.json`

### 厂商申报能力现状

`vendor_registry.py` 登记了 141 家厂商的申报方式，按实际页面探测分类：

| 类型 | 数量 | 说明 |
|------|------|------|
| `email` | 116 | 有邮箱，走 `--gen-emails` 邮件链路 |
| `file_form` | 5 | APEX / SecureAge / AVG / Microsoft / Symantec，可自动上传样本 |
| `hash_form` | 3 | Fortinet / GreenSnow / CRDF，只需提交 SHA256 |
| `url_form` | 8 | 只受理 URL / 域名误报，与文件无关 |
| `forum` / `ticket` / `guide` / `blocked` | 9 | 论坛、登录工单、说明页、人机验证拦截，只能人工提交 |

绝大多数厂商无公开上传接口且带验证码，因此「自动」的边界是：**能自动的自动填好，不能自动的开好页面并逐个确认**。

## 环境要求

- Python 3.8+
- Windows / macOS / Linux

## 安装

```bash
git clone https://github.com/huangli007/virus_auto.git
cd virus_auto
pip install -r requirements.txt
```

## 获取 API Key

1. 注册 [VirusTotal](https://www.virustotal.com) 账号
2. 登录后进入 [API Key 页面](https://www.virustotal.com/gui/my-apikey)
3. 复制个人 API Key

## 使用

### 1. 扫描文件

```bash
# 扫描文件夹（scan 是 -f 的简写）
python virus_scanner.py scan "C:\Program Files\MyApp"

# 自定义项目名称
python virus_scanner.py scan "C:\Target" --project-name MyProject

# 强制重扫（忽略缓存）
python virus_scanner.py scan "C:\Target" --no-cache

# 全量扫描（忽略缓存 + 不按扩展名过滤，目录下全部非空文件重新检查/上传）
python virus_scanner.py scan "C:\Target" --full-scan

# 全量扫描并跳过配额超限时的二次确认（用于无人值守）
python virus_scanner.py scan "C:\Target" --full-scan -y

# 混合路径扫描
python virus_scanner.py -p "D:\file1.dll" "C:\Program Files\MyApp"

# 不带参数进入交互模式（GUI 选文件夹）
python virus_scanner.py
```

扫描产物目录结构：

```
projects/
└── Target/                      # 项目文件夹（同名扫描共享）
    ├── scan_data.json            # 扫描结果 JSON
    ├── report.html               # HTML 报告
    └── detections/               # 报毒文件详情
        ├── uninst.exe.json
        └── uninst.exe.md
```

### 2. 管理 API Key

```bash
python virus_scanner.py -k YOUR_API_KEY --save-key    # 添加并持久化
python virus_scanner.py --add-key                      # 交互添加
python virus_scanner.py --add-key YOUR_API_KEY         # 命令行添加
python virus_scanner.py --key-file keys.txt             # 从文件批量导入
python virus_scanner.py --list-keys                    # 查看 Key 池
```

### 3. 缓存管理

```bash
python virus_scanner.py --cache-stats    # 查看缓存统计
python virus_scanner.py --clear-cache    # 清空缓存
```

### 4. 误报申诉邮件

```bash
python virus_scanner.py email [扫描结果文件或目录]   # 省略则用最近的报毒项目
```

交互流程：展示邮件全文（文件路径、SHA256、引擎、报毒名、收件人、正文），每封可选 y确认 / n跳过 / a全部确认 / q退出。确认后通过 SMTP 自动发送，同时生成 `.txt` 备份到 `emails_<ts>/` 目录。

#### SMTP 配置

工具默认使用 QQ 邮箱 SMTP，需配置授权码才能发送：

1. 登录 QQ 邮箱 → 设置 → 账户 → POP3/SMTP 服务 → 生成授权码
2. 编辑 `smtp_config.json` 填入授权码：

```json
{
  "host": "smtp.qq.com",
  "port": 587,
  "auth_code": "你的QQ邮箱授权码"
}
```

### 5. 筛选报毒报告

```bash
python virus_scanner.py filter projects\Target
```

### 6. 导出报毒 Excel

```bash
python virus_scanner.py excel projects\Target
```

生成 `报毒清单_<json文件名>.xlsx`，包含五列：文件路径、报毒详情、VT链接、厂家联系方式、扫毒日期。恶意行为红色底色，可疑行为橙色底色。

### 7. 自动提交到厂商网站

给「没有邮箱、只能走网页表单」的厂商补一条直提通道：

```bash
# 自动 + 人工向导（推荐）
python virus_scanner.py submit projects\Target

# 只提交指定厂商
python virus_scanner.py submit projects\Target -e Fortinet,APEX

# 先试运行：只打开并预填页面做验证，不真正提交
python virus_scanner.py submit projects\Target --dry

# 无人值守（不弹浏览器、不询问，全部记入待人工清单）
python virus_scanner.py submit projects\Target --headless
```

GUI 里对应「邮件申诉」页的 **自动上传到厂商网站** 按钮，流程一致：

1. **自动项**（`file_form` / `hash_form`）—— 打开可见浏览器，自动选文件、填 SHA256 / 邮箱 / 说明；
2. 遇到验证码或自动失败 —— 该窗口保留，并转入 **人工提交向导**；
3. **人工向导** —— 逐项显示厂商、上传网址、文件名、路径、SHA256、报毒信息，点「打开上传页面」后手动提交，回来点「已上传」确认，再点「下一个」继续；
4. 结果写入 `vendor_submit_<时间>/_vendor_submit.md` 与 `.json`。

> 打包版（exe）不含 Playwright 浏览器，自动项会降级为人工向导，功能不受影响。

## 命令行参数

> 下表是完整参数。常用动作也支持简写（`scan` / `submit` / `email` / `err` / `excel` / `filter` / `keys` / `cache` / `cache-clear`），两种写法完全等价。
> `submit` / `email` / `err` / `excel` / `filter` 省略路径时自动使用最近的**有报毒记录**的项目。

| 参数 | 说明 |
|------|------|
| `-k`, `--key` | 临时使用指定的 API Key |
| `--save-key` | 配合 `-k` 将 Key 持久化到池 |
| `--add-key` | 添加 API Key 到池 |
| `--key-file` | 从文本文件加载 Key 池 |
| `--list-keys` | 查看 Key 池状态 |
| `-f`, `--folder` | 扫描文件夹路径 |
| `-p`, `--path` | 文件或文件夹路径（支持多个） |
| `--project-name` | 自定义项目名称 |
| `--no-cache` | 忽略本地缓存，强制上传 |
| `--full-scan` / `--full` | 全量扫描：忽略本地缓存 + 不按扩展名过滤，全部非空文件重新检查/上传 |
| `-y`, `--yes` | 跳过扫描前（配额超限时）的确认提示 |
| `--cache-stats` | 显示缓存统计 |
| `--clear-cache` | 清空本地扫描缓存 |
| `--report-filter` | 从 scan_data JSON 筛选报毒项生成 HTML 报告 |
| `--err` | 从 scan_data JSON 输出终端文本报毒测试报告 |
| `-E`, `--gen-emails` | 从 scan_data JSON 或 detections 目录生成并发送申诉邮件 |
| `-S`, `--submit-vendors` | 把报毒样本自动提交到厂商网页表单，不可自动的转人工向导 |
| `-e`, `--submit-engines` | 配合 `-S`，只提交指定厂商（逗号分隔） |
| `-n`, `--dry` | 配合 `-S`，只预填不提交，用于验证页面结构 |
| `--headless` | 配合 `-S`，无头浏览器运行（不弹窗、不询问） |
| `-x`, `--excel` | 从 scan_data JSON 导出报毒清单 Excel |

## 支持的扫描文件类型

可执行文件: exe, dll, sys, bat, cmd, ps1, vbs, vbe, js, jse, wsf, wsh, msi, scr, cpl, pif, com, drv, ocx, bin

包/安装: apk, ipa, app, deb, rpm, dmg, iso, img, vhd, vhdx

文档: pdf, doc, docx, docm, xls, xlsx, xlsm, ppt, pptx, pptm, rtf, mdb, accdb, htm, html

压缩: zip, rar, 7z, tar, gz, bz2, xz, cab, arj, lzh, ace, jar, war, ear

其他: swf, lnk, url, torrent, chm, eml, msg, hta
