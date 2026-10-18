# VirusTotal 批量扫描 & 误报申诉工具 v3.0

基于 VirusTotal API 的自动化安全扫描工具，支持批量文件扫描、报毒详情提取、逐封确认生成误报申诉邮件。

v3.0 新增：项目分类管理、SHA-256 本地缓存去重、跳过已扫描文件节省配额。

## 功能

| 命令 | 功能 |
|------|------|
| 扫描（默认） | 指定文件/文件夹 → SHA-256 缓存查重 → VT 扫描 → HTML + JSON 报告 |
| `--report-filter` | 从已有 scan_data JSON 筛选报毒文件，生成仅报毒 HTML 报告 |
| `--err` | 从 scan_data JSON 输出终端文本报毒测试报告 |
| `--gen-emails` | 从 scan_data JSON（或 detections 目录）自动筛选报毒项，逐封确认生成并发送申诉邮件 |
| `--excel` | 从 scan_data JSON 导出报毒清单 Excel（文件路径/报毒详情/VT链接/厂家联系方式/扫毒日期） |
| `--cache-stats` | 查看本地扫描缓存统计 |
| `--clear-cache` | 清空本地扫描缓存 |

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
# 扫描文件夹
python virus_scanner.py -f "C:\Program Files\MyApp"

# 自定义项目名称
python virus_scanner.py -f "C:\Target" --project-name MyProject

# 强制重扫（忽略缓存）
python virus_scanner.py -f "C:\Target" --no-cache

# 全量扫描（忽略缓存 + 不按扩展名过滤，目录下全部非空文件重新检查/上传）
python virus_scanner.py -f "C:\Target" --full-scan

# 全量扫描并跳过配额超限时的二次确认（用于无人值守）
python virus_scanner.py -f "C:\Target" --full-scan -y

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
python virus_scanner.py --gen-emails <扫描结果文件或目录>
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
python virus_scanner.py --report-filter projects\Target\scan_data.json
```

### 6. 导出报毒 Excel

```bash
python virus_scanner.py --excel projects\Target\scan_data.json
```

生成 `报毒清单_<json文件名>.xlsx`，包含五列：文件路径、报毒详情、VT链接、厂家联系方式、扫毒日期。恶意行为红色底色，可疑行为橙色底色。

## 命令行参数

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
| `--gen-emails` | 从 scan_data JSON 或 detections 目录生成并发送申诉邮件 |
| `--excel` | 从 scan_data JSON 导出报毒清单 Excel |

## 支持的扫描文件类型

可执行文件: exe, dll, sys, bat, cmd, ps1, vbs, vbe, js, jse, wsf, wsh, msi, scr, cpl, pif, com, drv, ocx, bin

包/安装: apk, ipa, app, deb, rpm, dmg, iso, img, vhd, vhdx

文档: pdf, doc, docx, docm, xls, xlsx, xlsm, ppt, pptx, pptm, rtf, mdb, accdb, htm, html

压缩: zip, rar, 7z, tar, gz, bz2, xz, cab, arj, lzh, ace, jar, war, ear

其他: swf, lnk, url, torrent, chm, eml, msg, hta
