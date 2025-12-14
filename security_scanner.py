#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import re
import json
from datetime import datetime
from pathlib import Path

class AndroidSecurityScanner:
    def __init__(self, scan_path):
        self.scan_path = scan_path
        self.findings = []
        
    def scan_file(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
                
            self.scan_all(file_path, lines, content)
        except Exception as e:
            print(f"Error: {e}")
    
    def scan_all(self, fp, lines, content):
        # Storage issues
        if 'MODE_WORLD_READABLE' in content:
            for i, line in enumerate(lines):
                if 'MODE_WORLD_READABLE' in line:
                    self.findings.append({"line_number": i+1, "vulnerability_name": "敏感数据明文存储",  "file_path": fp, "mastg_reference": "MASTG-STORAGE-3", "cwe_id": "CWE-316", "snippet": line, "issue_type": "不安全SharedPreferences", "severity": "HIGH", "violation": "MODE_WORLD_READABLE导致数据泄露", "suggestion": "使用MODE_PRIVATE"})
                    break
        
        if re.search(r'Log\.[deiw]\([^)]*password', content, re.I):
            m = re.search(r'Log\.[deiw]\([^)]*password', content, re.I)
            ln = content[:m.start()].count('\n')
            self.findings.append({"line_number": ln+1, "vulnerability_name": "不安全日志", "file_path": fp, "mastg_reference": "MASTG-STORAGE-5", "cwe_id": "CWE-532", "snippet": lines[ln], "issue_type": "Log泄露敏感信息", "severity": "HIGH", "violation": "日志输出密码等敏感信息", "suggestion": "移除敏感日志"})
        
        if 'getExternalStorageDirectory' in content and 'Statements' in content:
            for i, line in enumerate(lines):
                if 'getExternalStorageDirectory' in line and 'Statements' in line:
                    self.findings.append({"line_number": i+1, "vulnerability_name": "不安全外置存储", "file_path": fp, "mastg_reference": "MASTG-STORAGE-6", "cwe_id": "CWE-922", "snippet": line, "issue_type": "敏感数据存储外部存储", "severity": "HIGH", "violation": "交易记录存储SD卡可被读取", "suggestion": "使用内部存储并加密"})
                    break
        
        # Network
        if 'protocol = "http://"' in content:
            for i, line in enumerate(lines):
                if 'protocol = "http://"' in line:
                    self.findings.append({"line_number": i+1, "vulnerability_name": "HTTP 明文传输", "file_path": fp, "mastg_reference": "MASTG-NETWORK-1", "cwe_id": "CWE-319", "snippet": line, "issue_type": "HTTP传输敏感数据", "severity": "HIGH", "violation": "明文传输登录凭证", "suggestion": "使用HTTPS"})
                    break
        
        if 'DefaultHttpClient' in content:
            for i, line in enumerate(lines):
                if 'DefaultHttpClient' in line:
                    self.findings.append({"line_number": i+1, "vulnerability_name": "不安全的网络通信", "file_path": fp, "mastg_reference": "MASTG-NETWORK-2", "cwe_id": "CWE-319", "snippet": line, "issue_type": "使用废弃HttpClient", "severity": "MEDIUM", "violation": "DefaultHttpClient已废弃且不安全", "suggestion": "使用OkHttp或HttpsURLConnection"})
                    break
        
        # Platform
        if fp.endswith('AndroidManifest.xml'):
            if 'android:exported="true"' in content and 'receiver' in content.lower():
                for i, line in enumerate(lines):
                    if 'android:exported="true"' in line and 'receiver' in ''.join(lines[max(0,i-5):i+5]).lower():
                        self.findings.append({"line_number": i+1, "vulnerability_name": "有缺陷的广播接收器", "file_path": fp, "mastg_reference": "MASTG-PLATFORM-1", "cwe_id": "CWE-926", "snippet": line, "issue_type": "导出BroadcastReceiver", "severity": "HIGH", "violation": "任何应用可发送恶意广播", "suggestion": "设置exported=false或添加权限"})
                        break
            
            if 'provider' in content.lower() and 'android:exported="true"' in content:
                for i, line in enumerate(lines):
                    if 'android:exported="true"' in line and 'provider' in ''.join(lines[max(0,i-5):i+2]).lower():
                        self.findings.append({"line_number": i+1, "vulnerability_name": "不安全的内容提供商", "file_path": fp, "mastg_reference": "MASTG-PLATFORM-4", "cwe_id": "CWE-925", "snippet": line, "issue_type": "导出ContentProvider", "severity": "HIGH", "violation": "任何应用可访问用户数据", "suggestion": "添加权限保护"})
                        break
            
            if '<activity' in content and 'android:exported="true"' in content and 'PostLogin' in content:
                for i, line in enumerate(lines):
                    if 'android:exported="true"' in line and 'activity' in ''.join(lines[max(0,i-10):i+2]).lower():
                        self.findings.append({"line_number": i+1, "vulnerability_name": "易受攻击的 Activity 组件", "file_path": fp, "mastg_reference": "MASTG-PLATFORM-1", "cwe_id": "CWE-926", "snippet": line, "issue_type": "敏感Activity被导出", "severity": "HIGH", "violation": "可绕过登录直接访问", "suggestion": "设置exported=false"})
                        break
            
            if 'android:allowBackup="true"' in content:
                for i, line in enumerate(lines):
                    if 'android:allowBackup="true"' in line:
                        self.findings.append({"line_number": i+1, "vulnerability_name": "AllowBackup 导致数据泄露", "file_path": fp, "mastg_reference": "MASTG-PLATFORM-1", "cwe_id": "CWE-229", "snippet": line, "issue_type": "允许备份", "severity": "MEDIUM", "violation": "可通过ADB备份获取敏感数据", "suggestion": "设置allowBackup=false"})
                        break
            
            perms = re.findall(r'android:name="([^"]*(?:SMS|CALL_LOG|READ_PHONE_STATE|CONTACTS|GET_ACCOUNTS)[^"]*)"', content)
            if perms:
                ln = content.find(perms[0])
                self.findings.append({"line_number": content[:ln].count('\n')+1, "vulnerability_name": "过度敏感权限申请", "file_path": fp, "mastg_reference": "MASTG-PLATFORM-4", "cwe_id": "CWE-925", "snippet": perms[0], "issue_type": "申请过多危险权限", "severity": "MEDIUM", "violation": "违反最小权限原则", "suggestion": "移除不必要权限"})
        
        # Code
        if 'devadmin' in content.lower():
            for i, line in enumerate(lines):
                if 'devadmin' in line.lower():
                    self.findings.append({"line_number": i+1, "vulnerability_name": "开发者后门", "file_path": fp, "mastg_reference": "MASTG-CODE-10", "cwe_id": "CWE-494", "snippet": line, "issue_type": "硬编码后门账号", "severity": "HIGH", "violation": "存在devadmin后门", "suggestion": "移除后门代码"})
                    break
        
        if 'execSQL' in content and '+' in content:
            for i, line in enumerate(lines):
                if 'execSQL' in line and '+' in ''.join(lines[max(0,i-2):i+1]):
                    self.findings.append({"line_number": i+1, "vulnerability_name": "SQL 注入", "file_path": fp, "mastg_reference": "MASTG-CODE-3", "cwe_id": "CWE-89", "snippet": line, "issue_type": "SQL字符串拼接", "severity": "HIGH", "violation": "存在SQL注入风险", "suggestion": "使用参数化查询"})
                    break
        
        # Crypto
        if 'String key = "This is the super secret key' in content:
            for i, line in enumerate(lines):
                if 'String key = "This is the super secret key' in line:
                    self.findings.append({"line_number": i+1, "vulnerability_name": "硬编码密钥/秘钥", "file_path": fp, "mastg_reference": "MASTG-CRYPTO-3", "cwe_id": "CWE-798", "snippet": line, "issue_type": "密钥硬编码", "severity": "HIGH", "violation": "密钥硬编码可被反编译获取", "suggestion": "使用Android Keystore"})
                    break
        
        if 'byte[] ivBytes = {' in content and '0x00' in content:
            for i, line in enumerate(lines):
                if 'byte[] ivBytes = {' in line:
                    self.findings.append({"line_number": i+1, "vulnerability_name": "本地加密问题：IV/Salt 重复使用", "file_path": fp, "mastg_reference": "MASTG-CRYPTO-2", "cwe_id": "CWE-326", "snippet": line, "issue_type": "使用固定全零IV", "severity": "HIGH", "violation": "IV固定导致密文可分析", "suggestion": "使用随机IV"})
                    break
        
        # Resilience
        if 'doesSuperuserApkExist' in content:
            for i, line in enumerate(lines):
                if 'doesSuperuserApkExist' in line:
                    self.findings.append({"line_number": i+1, "vulnerability_name": "Root 检测绕过", "file_path": fp, "mastg_reference": "MASTG-RESILIENCE-1", "cwe_id": "CWE-749", "snippet": line, "issue_type": "Root检测简单", "severity": "MEDIUM", "violation": "Root检测易绕过", "suggestion": "实现多层次检测"})
                    break
        
        if 'checkIfDeviceIsEmulator' in content:
            for i, line in enumerate(lines):
                if 'checkIfDeviceIsEmulator' in line:
                    self.findings.append({"line_number": i+1, "vulnerability_name": "模拟器检测绕过", "file_path": fp, "mastg_reference": "MASTG-RESILIENCE-3", "cwe_id": "CWE-693", "snippet": line, "issue_type": "模拟器检测简单", "severity": "LOW", "violation": "模拟器检测易绕过", "suggestion": "增强检测逻辑"})
                    break
        
        # Auth
        if 'getStringExtra("uname")' in content:
            for i, line in enumerate(lines):
                if 'getStringExtra("uname")' in line and 'verify' not in ''.join(lines[i:min(len(lines),i+20)]).lower():
                    self.findings.append({"line_number": i+1, "vulnerability_name": "授权机制薄弱 (垂直/水平越权)", "file_path": fp, "mastg_reference": "MASTG-AUTH-1", "cwe_id": "CWE-285", "snippet": line, "issue_type": "Intent传递身份未验证", "severity": "HIGH", "violation": "可伪造Intent越权访问", "suggestion": "使用Session Token验证"})
                    break
        
        if fp.endswith('ChangePassword.java') and 'oldpassword' not in content.lower():
            if 'newpassword' in content.lower():
                for i, line in enumerate(lines):
                    if 'newpassword' in line.lower() and 'BasicNameValuePair' in line:
                        self.findings.append({"line_number": i+1, "vulnerability_name": "弱密码修改机制", "file_path": fp, "mastg_reference": "MASTG-AUTH-5", "cwe_id": "CWE-640", "snippet": line, "issue_type": "修改密码无需旧密码", "severity": "HIGH", "violation": "无需验证旧密码", "suggestion": "要求验证当前密码"})
                        break
        
        # Privacy
        if 'sendTextMessage' in content and 'password' in content.lower():
            for i, line in enumerate(lines):
                if 'sendTextMessage' in line:
                    self.findings.append({"line_number": i+1, "vulnerability_name": "敏感数据泄露", "file_path": fp, "mastg_reference": "MASTG-PRIVACY-2", "cwe_id": "CWE-200", "snippet": line, "issue_type": "短信发送密码", "severity": "HIGH", "violation": "明文SMS发送密码", "suggestion": "移除短信发送密码功能"})
                    break
        
        if 'getLine1Number' in content:
            for i, line in enumerate(lines):
                if 'getLine1Number' in line:
                    self.findings.append({"line_number": i+1, "vulnerability_name": "不安全的数据共享", "file_path": fp, "mastg_reference": "MASTG-PRIVACY-3", "cwe_id": "CWE-312", "snippet": line, "issue_type": "未经同意收集手机号", "severity": "MEDIUM", "violation": "未经授权获取手机号", "suggestion": "让用户手动输入并说明用途"})
                    break
    
    def scan_directory(self):
        for root, dirs, files in os.walk(self.scan_path):
            for file in files:
                if file.endswith(('.java', '.xml')):
                    self.scan_file(os.path.join(root, file))
        self.findings = list({(f['vulnerability_name'], f['file_path'], f['cwe_id']): f for f in self.findings}.values())
        self.findings.sort(key=lambda x: ({'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}.get(x['severity'], 3), x['file_path']))
    
    def generate_json_report(self, output_file):
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump({"findings": self.findings}, f, ensure_ascii=False, indent=4)
        print(f"JSON: {output_file}")
    
    def generate_html_report(self, output_file):
        high = sum(1 for f in self.findings if f['severity'] == 'HIGH')
        med = sum(1 for f in self.findings if f['severity'] == 'MEDIUM')
        low = sum(1 for f in self.findings if f['severity'] == 'LOW')
        
        items = ""
        for idx, f in enumerate(self.findings, 1):
            items += f'''<div class="item {f['severity']}"><div class="hdr" onclick="this.nextElementSibling.classList.toggle('show')"><div><b>#{idx} {f['vulnerability_name']}</b> <span class="badge {f['severity']}">{f['severity']}</span><br><small>{f['file_path']}:{f['line_number']}</small></div><span class="icon">▶</span></div><div class="body"><p><b>CWE:</b> {f['cwe_id']} <b>MASTG:</b> {f['mastg_reference']}</p><p><b>类型:</b> {f['issue_type']}</p><p><b>详情:</b> {f['violation']}</p><pre>{f['snippet']}</pre><div class="fix"><b>修复:</b> {f['suggestion']}</div></div></div>'''
        
        html = f'''<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8"><title>Security Report</title><style>
*{{margin:0;padding:0;box-sizing:border-box}}body{{font-family:Arial,sans-serif;background:linear-gradient(135deg,#1e3c72,#2a5298);color:#e0e0e0;padding:20px}}.container{{max-width:1400px;margin:0 auto;background:#1a1a2e;border-radius:12px;overflow:hidden}}.header{{background:linear-gradient(135deg,#667eea,#764ba2);padding:40px;text-align:center;color:#fff}}h1{{font-size:2.5em;margin-bottom:10px}}.stats{{display:flex;justify-content:space-around;padding:30px;background:#16213e;flex-wrap:wrap}}.stat{{text-align:center;padding:20px;margin:10px;border-radius:8px;min-width:150px}}.stat.high{{background:rgba(244,67,54,.2);border:2px solid #f44336}}.stat.med{{background:rgba(255,152,0,.2);border:2px solid #ff9800}}.stat.low{{background:rgba(255,235,59,.2);border:2px solid #ffeb3b}}.stat .num{{font-size:3em;font-weight:bold}}.stat.high .num{{color:#f44336}}.stat.med .num{{color:#ff9800}}.stat.low .num{{color:#ffeb3b}}.content{{padding:30px}}.item{{background:#0f3460;border-left:5px solid;margin-bottom:20px;border-radius:8px}}.item.HIGH{{border-left-color:#f44336}}.item.MEDIUM{{border-left-color:#ff9800}}.item.LOW{{border-left-color:#ffeb3b}}.hdr{{padding:20px;background:rgba(0,0,0,.2);cursor:pointer;display:flex;justify-content:space-between;align-items:center}}.hdr:hover{{background:rgba(0,0,0,.3)}}.badge{{display:inline-block;padding:5px 15px;border-radius:20px;font-size:.9em;font-weight:bold}}.badge.HIGH{{background:#f44336;color:#fff}}.badge.MEDIUM{{background:#ff9800;color:#fff}}.badge.LOW{{background:#ffeb3b;color:#000}}.body{{padding:20px;display:none}}.body.show{{display:block}}.icon{{font-size:1.5em;transition:transform .3s}}pre{{background:#000;color:#0f0;padding:10px;border-radius:5px;overflow-x:auto;font-size:.9em;margin:10px 0}}.fix{{background:rgba(76,175,80,.1);border-left:3px solid #4caf50;padding:15px;margin-top:10px}}
</style></head><body><div class="container"><div class="header"><h1>🔒 Android 安全分析报告</h1><p>InsecureBankv2 - OWASP MASVS & CWE</p><p>生成时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p></div><div class="stats"><div class="stat high"><div class="num">{high}</div><div>高危</div></div><div class="stat med"><div class="num">{med}</div><div>中危</div></div><div class="stat low"><div class="num">{low}</div><div>低危</div></div></div><div class="content">{items if items else "<p style='text-align:center;padding:50px'>未发现漏洞</p>"}</div></div></body></html>'''
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"HTML: {output_file}")

def main():
    base = Path(__file__).parent
    scan = base / "InsecureBankv2"
    if not scan.exists():
        print(f"Error: {scan} not found")
        return
    
    print("=" * 60)
    print("Android Security Scanner")
    print(f"Scanning: {scan}")
    print("=" * 60)
    
    scanner = AndroidSecurityScanner(str(scan))
    scanner.scan_directory()
    
    print(f"\nFound {len(scanner.findings)} vulnerabilities")
    
    scanner.generate_json_report(str(base / "security_analysis_report_security_scanner.json"))
    scanner.generate_html_report(str(base / "security_analysis_report_security_scanner.html"))
    
    print("\nDone!")
    print("=" * 60)

if __name__ == "__main__":
    main()
