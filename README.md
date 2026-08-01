# VirusTotal 批量扫描 & 误报申诉工具

基于 VirusTotal API 的自动化安全扫描工具，支持批量文件扫描、报毒详情提取、逐封确认生成误报申诉邮件。

## 功能

| 命令 | 功能 |
|------|------|
| 扫描（默认） | 指定文件/文件夹 → SHA-256 查重 → VT 扫描 → HTML + JSON 报告 |
| `--report-filter` | 从已有 scan_data JSON 筛选报毒文件，生成仅报毒 HTML 报告 |
| `--gen-emails` | 从 scan_data JSON（或 detections 目录）自动筛选报毒项，逐封确认生成申诉邮件 |

### 核心特性

- **多 Key 池**：配额耗尽自动切换，支持 key 文件批量导入
- **类型优先级**：exe/dll/sys 优先扫描
- **配额管控**：严格遵守 VT 公共 API 限制（4次/分钟，500次/天，155K次/月）
- **配额优化**：本地缓存查已有报告 + 免费操作不计配额 + 渐进式轮询 + 首请求免空等
- **增量扫描**：已有 VT 报告的文件跳过上传，直接复用结果
- **报毒详情**：为每个报毒文件生成独立 JSON + Markdown（含 `file_path` 绝对路径）
- **逐封确认**：生成申诉邮件前先展示邮件全文，逐封确认/跳过/全部确认/退出
- **申诉记录**：确认后生成 `_sent.md`，表格记录已申诉文件的绝对路径、SHA256、引擎、收件人

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
# 扫描单个文件
python virus_scanner.py -p "D:\Downloads\setup.exe"

# 扫描文件夹
python virus_scanner.py -p "C:\Program Files\MyApp"

# 混合路径扫描
python virus_scanner.py -p "D:\file1.dll" "C:\Program Files\MyApp"

# 指定文件夹（-f）
python virus_scanner.py -f "D:\Downloads"

# 不带参数进入交互模式（GUI 选文件夹）
python virus_scanner.py
```

### 2. 管理 API Key

```bash
# 添加 key（推荐 --save-key 持久化）
python virus_scanner.py -k YOUR_API_KEY --save-key

# 交互添加
python virus_scanner.py --add-key

# 命令行添加
python virus_scanner.py --add-key YOUR_API_KEY

# 批量导入 key 文件（每行一个，# 注释）
python virus_scanner.py --key-file keys.txt

# 查看 key 池状态
python virus_scanner.py --list-keys
```

### 3. 误报申诉邮件

扫描完成后，使用 `--gen-emails` 自动筛选报毒文件并逐封确认生成申诉邮件：

```bash
# 方式一：直接传入 scan_data JSON（推荐，自动筛选报毒文件）
python virus_scanner.py --gen-emails scan_reports\scan_data_20260731_133301.json

# 方式二：传入 detections 目录（兼容旧用法）
python virus_scanner.py --gen-emails scan_reports\detections_20260731_133301
```

交互流程：展示邮件全文（文件路径、SHA256、引擎、报毒名、收件人、正文），每封可选择：
- `y` 确认
- `n` 跳过
- `a` 全部确认
- `q` 退出

生成的文件结构：

```
scan_reports/
├── scan_data_20260731_133301.json          # 原始扫描数据
├── scan_report_20260731_133301.html         # HTML 报告
├── detections_20260731_133301/              # 报毒文件详情
│   ├── uninst.exe.json                      # JSON 详情（含 file_path）
│   └── uninst.exe.md                        # Markdown 详情
└── emails_20260731_133301/                  # 申诉邮件
    ├── uninst.exe__APEX.txt
    ├── _summary.txt                         # 纯文本汇总
    └── _sent.md                             # 申诉发送记录（表格）
```

### 4. 筛选报毒报告

从已有 scan_data JSON 快速生成仅含报毒项的 HTML 报告：

```bash
python virus_scanner.py --report-filter scan_reports\scan_data_20260731_133301.json
```

## 输出说明

### HTML 报告

包含每个文件的完整扫描结果：

- 文件路径、SHA-256、VT 链接
- 报毒详情（恶意/可疑引擎及威胁名称）
- 全部引擎检测统计
- 彩色标签区分恶意（红）/可疑（橙）/安全（绿）

### JSON 数据

```json
{
  "file_name": "setup.exe",
  "file_path": "D:\\Downloads\\setup.exe",
  "sha256": "abc123...",
  "virus_total_link": "https://www.virustotal.com/gui/file/abc123...",
  "malicious": 1,
  "suspicious": 0,
  "detections": [
    {
      "engine": "APEX",
      "name": "Malicious",
      "category": "malicious"
    }
  ]
}
```

### 邮件模板

仅对有邮箱的引擎生成邮件，纯网页表单提交的厂家自动跳过。邮件格式：

```
To: vt-pan-false-positive@paloaltonetworks.com
Subject: VirusTotal False Positive Report

I'm writing to report a false positive detection on my legitimate file.

1. File name: myapp.exe
2. SHA256: abc123...
3. VirusTotal link: https://www.virustotal.com/gui/file/abc123...
4. Detection engine: Palo Alto
5. Detection name: generic.ml

...
```

## 命令行参数

| 参数 | 说明 |
|------|------|
| `-p` / `--path` | 指定文件或文件夹路径（支持多个） |
| `-f` / `--folder` | 指定文件夹（单路径） |
| `-k` / `--key` | 临时 API Key |
| `--save-key` | 将 -k 传入的 Key 持久化保存 |
| `--add-key` | 交互/命令行添加 Key 到池 |
| `--key-file` | 从文本文件加载 Key 池 |
| `--list-keys` | 查看 Key 池状态与配额 |
| `--report-filter` | 从 scan_data JSON 筛选报毒项生成 HTML 报告 |
| `--gen-emails` | 从 scan_data JSON 或 detections 目录自动筛选报毒项生成申诉邮件 |

## 支持的扫描文件类型

60+ 种病毒载体扩展名：exe, dll, sys, bin, scr, com, bat, cmd, ps1, vbs, js, jar, msi, doc, docx, xls, xlsx, ppt, pptx, pdf, zip, rar, 7z, iso, img, elf, mach-o, apk, ipa, ...

文本类文件（txt, md, log, json, xml, csv 等）自动排除。

## License

MIT
