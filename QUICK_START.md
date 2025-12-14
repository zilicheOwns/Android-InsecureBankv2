# Quick Start Guide - Android Security Scanner

## 快速开始

### 方法 1: 使用生成器脚本（推荐）
```bash
python3 scanner_gen.py
```
这会自动生成 `security_scanner.py` 并执行扫描。

### 方法 2: 直接运行扫描器
```bash
python3 security_scanner.py
```

## 输出文件

扫描完成后会生成：

1. **JSON 报告** - `security_analysis_report_security_scanner.json`
   ```bash
   # 查看 JSON 报告摘要
   python3 -c "import json; data=json.load(open('security_analysis_report_security_scanner.json')); print(f'Total: {len(data[\"findings\"])} vulnerabilities')"
   ```

2. **HTML 报告** - `security_analysis_report_security_scanner.html`
   ```bash
   # 在浏览器中打开
   open security_analysis_report_security_scanner.html  # macOS
   xdg-open security_analysis_report_security_scanner.html  # Linux
   start security_analysis_report_security_scanner.html  # Windows
   ```

## 报告内容

每个漏洞包含：
- ✅ 精确行号
- ✅ 漏洞类型（中文）
- ✅ CWE 编号
- ✅ MASTG 参考
- ✅ 代码片段
- ✅ 严重性（HIGH/MEDIUM/LOW）
- ✅ 详细说明（中文）
- ✅ 修复建议（代码示例）

## 扫描结果概览

```
总计: 27 个安全漏洞
  🔴 高危: 19 个
  �� 中危: 7 个
  🟡 低危: 1 个
```

## 主要发现

### 平台安全 (7个)
- 导出的组件未保护
- 过度权限申请

### 网络安全 (6个)
- HTTP 明文传输
- 使用废弃 API

### 认证授权 (5个)
- 身份验证绕过
- 开发者后门

### 存储安全 (4个)
- 外部存储敏感数据
- 不安全日志

### 加密安全 (2个)
- 硬编码密钥
- 固定 IV

### 隐私合规 (2个)
- 短信发送密码
- 未授权收集信息

## 文档

- **README_SECURITY_SCANNER.md** - 详细使用说明
- **SCAN_RESULTS_SUMMARY.md** - 完整分析结果
- **本文件 (QUICK_START.md)** - 快速参考

## 要求

- Python 3.6+
- 标准库（无需额外依赖）

## 支持的平台

- ✅ Linux
- ✅ macOS
- ✅ Windows

## 注意事项

- 仅扫描 `InsecureBankv2/` 目录
- 扫描结果为静态分析，建议结合动态测试
- 本工具仅用于教育和安全研究目的

---
**版本**: 1.0  
**更新时间**: 2024-12-14
