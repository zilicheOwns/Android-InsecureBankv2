# Android InsecureBankv2 安全扫描结果总结

## 扫描概述

本次安全扫描使用自动化工具对 InsecureBankv2 Android 应用进行静态代码分析，基于以下标准：
- **CWE** (Common Weakness Enumeration)
- **OWASP MASVS** (Mobile Application Security Verification Standard)
- **MASTG** (Mobile Application Security Testing Guide)
- **GDPR/CCPA** 隐私法规

## 扫描范围

仅扫描 `InsecureBankv2/` 目录：
- **Java 源代码文件**: 13 个
- **AndroidManifest.xml**: 1 个
- **总代码行数**: ~2,500 行

## 漏洞总结

### 严重性统计
```
🔴 高危 (HIGH):   19 个 (70%)
🟠 中危 (MEDIUM):  7 个 (26%)
🟡 低危 (LOW):     1 个 (4%)
━━━━━━━━━━━━━━━━━━━━━━━━━
   总计:         27 个
```

### 按安全域分类

#### 1. Platform (平台安全) - 7 个漏洞
- ❌ 广播接收器导出未保护 (HIGH)
- ❌ ContentProvider 导出未保护 (HIGH)  
- ❌ 多个 Activity 导出未授权 (HIGH)
- ⚠️  AllowBackup 启用 (MEDIUM)
- ⚠️  过度权限申请 (MEDIUM)

#### 2. Network (网络安全) - 6 个漏洞
- ❌ HTTP 明文传输敏感数据 (HIGH) × 3
- ⚠️  使用废弃 DefaultHttpClient (MEDIUM) × 3

#### 3. Auth (认证授权) - 5 个漏洞
- ❌ 通过 Intent 传递身份未验证 (HIGH) × 3
- ❌ 修改密码无需验证旧密码 (HIGH) × 1
- ❌ 开发者后门 (devadmin) (HIGH) × 1

#### 4. Storage (存储安全) - 4 个漏洞
- ❌ 外部存储保存敏感交易记录 (HIGH) × 2
- ❌ MODE_WORLD_READABLE (HIGH) × 1
- ❌ 日志泄露敏感信息 (HIGH) × 1

#### 5. Crypto (加密安全) - 2 个漏洞
- ❌ AES 密钥硬编码 (HIGH)
- ❌ 使用固定全零 IV (HIGH)

#### 6. Privacy (隐私合规) - 2 个漏洞
- ❌ 短信明文发送密码 (HIGH)
- ⚠️  未授权获取手机号 (MEDIUM)

#### 7. Code (代码安全) - 1 个漏洞
- ❌ SQL 注入风险 (HIGH)

#### 8. Resilience (弹性安全) - 2 个漏洞
- ⚠️  Root 检测简单易绕过 (MEDIUM)
- ⚡ 模拟器检测简单易绕过 (LOW)

## Top 10 高危漏洞

1. **有缺陷的广播接收器** (CWE-926)
   - 位置: AndroidManifest.xml:72
   - 影响: 任何应用可发送恶意广播触发密码短信发送

2. **不安全的内容提供商** (CWE-925)
   - 位置: AndroidManifest.xml:72
   - 影响: 任何应用可访问用户登录历史

3. **易受攻击的 Activity 组件** (CWE-926)
   - 位置: AndroidManifest.xml:51
   - 影响: 可绕过登录直接访问敏感功能

4. **HTTP 明文传输** (CWE-319)
   - 位置: 多个 Java 文件
   - 影响: 登录凭证、交易数据可被中间人截获

5. **授权机制薄弱** (CWE-285)
   - 位置: 多个 Activity
   - 影响: 通过伪造 Intent 实现水平越权

6. **弱密码修改机制** (CWE-640)
   - 位置: ChangePassword.java:138
   - 影响: 无需旧密码即可修改密码

7. **硬编码密钥** (CWE-798)
   - 位置: CryptoClass.java:25
   - 影响: AES 密钥可通过反编译获取

8. **固定 IV** (CWE-326)
   - 位置: CryptoClass.java:28
   - 影响: 相同明文产生相同密文，可模式分析

9. **开发者后门** (CWE-494)
   - 位置: DoLogin.java:130
   - 影响: devadmin 账号可绕过正常认证

10. **敏感数据泄露** (CWE-200)
    - 位置: MyBroadCastReceiver.java:40
    - 影响: 通过短信明文发送密码

## 合规性评估

### GDPR/CCPA 违规点
1. ❌ 未经授权收集手机号 (Article 6, 7)
2. ❌ 敏感数据未加密存储 (Article 32)
3. ❌ 过度权限申请违反最小化原则 (Article 5)
4. ❌ 通过不安全渠道传输个人数据 (Article 32)

### OWASP MASVS 符合度
- **存储 (MSTG-STORAGE)**: ❌ 不符合
- **加密 (MSTG-CRYPTO)**: ❌ 不符合
- **认证 (MSTG-AUTH)**: ❌ 不符合
- **网络 (MSTG-NETWORK)**: ❌ 不符合
- **平台 (MSTG-PLATFORM)**: ❌ 不符合
- **代码质量 (MSTG-CODE)**: ❌ 不符合
- **弹性 (MSTG-RESILIENCE)**: ⚠️  部分符合
- **隐私 (MSTG-PRIVACY)**: ❌ 不符合

**总体评级**: ❌ **不符合 OWASP MASVS 标准**

## 修复优先级

### P0 - 立即修复 (高危且易被利用)
1. 关闭所有导出的 Activity/Service/Receiver (设为 exported=false)
2. 使用 HTTPS 替代 HTTP
3. 修复 Intent 传递身份验证漏洞
4. 移除开发者后门 (devadmin)
5. 停止短信发送密码功能

### P1 - 短期修复 (高危但利用难度较高)
6. 使用 Android Keystore 存储密钥
7. 每次加密生成随机 IV
8. 敏感文件存储到内部存储并加密
9. 移除敏感信息日志输出
10. 修改密码时验证旧密码

### P2 - 中期修复 (中危)
11. 移除不必要的危险权限
12. 禁用 allowBackup 或配置排除规则
13. 使用 OkHttp 替代 DefaultHttpClient
14. 增强 Root 检测逻辑

### P3 - 长期改进 (低危或增强)
15. 改进模拟器检测
16. 实施代码混淆和完整性校验

## 报告文件

- **JSON 报告**: `security_analysis_report_security_scanner.json`
  - 结构化数据，包含所有漏洞详情
  - 适合自动化处理和CI/CD集成

- **HTML 报告**: `security_analysis_report_security_scanner.html`
  - 可视化报告，支持交互式查看
  - 颜色编码，代码片段高亮
  - 包含详细修复建议

## 工具信息

- **扫描工具**: Android Security Scanner v1.0
- **扫描时间**: 2024-12-14
- **扫描方式**: 静态代码分析 (SAST)
- **技术栈**: Python 3.x, 正则表达式, JSON, HTML/CSS

## 免责声明

本报告仅用于安全研究和教育目的。InsecureBankv2 是一个故意设计存在漏洞的应用，用于学习 Android 安全测试技术。在生产环境中部署类似应用会带来严重的安全风险。

---
**报告生成者**: Android Security Analysis Engine  
**标准依据**: CWE, OWASP MASVS, MASTG, GDPR/CCPA  
**联系方式**: 仅用于教育目的
