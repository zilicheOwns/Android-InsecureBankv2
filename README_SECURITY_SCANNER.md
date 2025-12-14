# Android 安全分析引擎 (Android Security Analysis Engine)

这是一个针对 InsecureBankv2 Android 应用的安全漏洞扫描工具，基于 CWE/OWASP MASVS 标准进行静态代码分析。

## 功能特点

本扫描器覆盖 8 大安全域（Security Domains）：

### Domain 1: Storage (存储安全)
- CWE-316 - 敏感数据明文存储
- CWE-532 - 不安全日志
- CWE-922 - 不安全外置存储

### Domain 2: Network (网络安全)
- CWE-319 - HTTP 明文传输
- CWE-319 - 不安全的网络通信（废弃API）

### Domain 3: Platform (平台安全)
- CWE-926 - 有缺陷的广播接收器
- CWE-925 - 不安全的内容提供商
- CWE-926 - 易受攻击的 Activity 组件
- CWE-229 - AllowBackup 导致数据泄露
- CWE-925 - 过度敏感权限申请

### Domain 4: Code (代码安全)
- CWE-494 - 开发者后门
- CWE-89 - SQL 注入

### Domain 5: Crypto (加密安全)
- CWE-798 - 硬编码密钥/秘钥
- CWE-326 - IV/Salt 重复使用

### Domain 6: Resilience (弹性安全)
- CWE-749 - Root 检测绕过
- CWE-693 - 模拟器检测绕过

### Domain 7: Auth (认证授权)
- CWE-285 - 授权机制薄弱 (垂直/水平越权)
- CWE-640 - 弱密码修改机制

### Domain 8: Privacy (隐私合规)
- CWE-200 - 敏感数据泄露
- CWE-312 - 不安全的数据共享

## 使用方法

```bash
# 生成扫描器（scanner_gen.py已包含扫描器代码）
python3 scanner_gen.py

# 或直接运行已生成的扫描器
python3 security_scanner.py
```

## 输出报告

扫描完成后会生成两份报告：

1. **JSON 报告**: `security_analysis_report_security_scanner.json`
   - 结构化数据，便于进一步处理和集成
   - 包含所有漏洞的详细信息

2. **HTML 报告**: `security_analysis_report_security_scanner.html`
   - 美观的可视化报告
   - 支持颜色区分（高危=红色，中危=橙色，低危=黄色）
   - 交互式展开/收起漏洞详情
   - 包含代码片段和修复建议

## 扫描结果摘要

本次扫描发现 **27 个安全漏洞**：
- 🔴 高危（HIGH）: 19 个
- 🟠 中危（MEDIUM）: 7 个
- 🟡 低危（LOW）: 1 个

### 主要漏洞类型

1. **平台安全问题**
   - 多个 Activity 组件设置 exported=true 未做权限保护
   - BroadcastReceiver 可被外部应用调用
   - ContentProvider 数据可被任意应用访问

2. **网络安全问题**
   - 使用 HTTP 明文传输敏感数据
   - 使用已废弃的 DefaultHttpClient

3. **加密安全问题**
   - AES 密钥硬编码在源码中
   - 使用固定的全零初始化向量（IV）

4. **认证授权问题**
   - 通过 Intent 传递用户身份未验证
   - 修改密码无需验证旧密码

5. **存储安全问题**
   - 使用 MODE_WORLD_READABLE 存储敏感数据
   - 敏感文件存储在外部存储（SD卡）

6. **隐私合规问题**
   - 通过短信明文发送密码
   - 未经授权获取用户手机号

## 技术栈

- Python 3.x
- 正则表达式匹配
- JSON 数据处理
- HTML/CSS 报告生成

## 合规标准

- ✅ CWE (Common Weakness Enumeration)
- ✅ OWASP MASVS (Mobile Application Security Verification Standard)
- ✅ MASTG (Mobile Application Security Testing Guide)
- ✅ GDPR/CCPA 隐私法规

## 报告格式

每个漏洞包含以下信息：
- **行号**: 漏洞所在的准确行号
- **漏洞名称**: 清晰的中文漏洞描述
- **文件路径**: 受影响的源代码文件
- **MASTG 参考**: 对应的 MASTG 测试项编号
- **CWE ID**: 对应的 CWE 漏洞编号
- **代码片段**: 存在问题的源代码
- **问题类型**: 漏洞类别简述
- **严重性**: HIGH / MEDIUM / LOW
- **违规说明**: 详细的中文漏洞解释
- **修复建议**: 可直接使用的修复代码示例

## 注意事项

- 本工具仅扫描 `InsecureBankv2/` 目录，不扫描 `AndroLabServer/`、`wip-attackercode/`、`tools/` 等目录
- 扫描结果基于静态代码分析，可能存在误报或漏报
- 建议结合动态分析和人工审查进行全面的安全评估

## 许可证

本项目仅用于安全研究和教育目的。
