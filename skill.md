# Virus Auto Skill

VirusTotal 批量扫描与误报申诉自动化工具。

## 项目路径

`D:\ai_software\marvis\virus_auto`

## 核心脚本

| 脚本 | 用途 | 用法 |
|------|------|------|
| `virus_scanner.py` | 文件扫描 → HTML/JSON 报告 + 报毒详情 | `python virus_scanner.py -p <路径>` |
| `generate_fp_emails.py` | 报毒 JSON → 匹配厂家邮箱 → 申诉邮件 | `python generate_fp_emails.py <detections目录>` |

## 执行规范

### 扫描任务

1. 切换到项目目录：`cd D:\ai_software\marvis\virus_auto`
2. 用 `-p` 指定目标路径，多个路径空格分隔
3. 如 Key 池为空，提示用户提供 Key 并加上 `--save-key`
4. 扫描完成后告知用户报告路径

### 邮件生成

1. 扫描产出的 `detections_*` 目录即为输入
2. 运行 `python generate_fp_emails.py scan_reports\detections_时间戳`
3. 输出 `emails_*` 目录，内含按模板生成的 `.txt` 邮件
4. 无邮箱的厂家自动跳过

## 输出目录结构

```
scan_reports/
├── scan_data_YYYYMMDD_HHMMSS.json
├── scan_report_YYYYMMDD_HHMMSS.html
├── detections_YYYYMMDD_HHMMSS/
│   ├── <文件名>.json
│   └── <文件名>.md
└── emails_YYYYMMDD_HHMMSS/
    ├── <文件名>__<引擎名>.txt
    └── _summary.txt
```

## 注意事项

- VirusTotal 公共 API 限速：4次/分钟，500次/天，155K次/月
- 单个文件约需 6 次 API 调用，含 `check_existing_report` + `upload_file` + `get_analysis`
- 已有 VT 报告的文件（SHA-256 匹配）直接复用结果，不消耗上传配额
- 配置文件 `virus_scanner_config.json` 存储 Key 池，含敏感信息
