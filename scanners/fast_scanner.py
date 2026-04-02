import requests
import socket
import ssl
import json
from urllib.parse import urlparse
from typing import List, Dict, Any, Optional

class FastScanner:
    def __init__(self, target: str):
        self.target = target
        self.findings = []
        self.parsed_url = None
        
        try:
            self.parsed_url = urlparse(target if '://' in target else f'http://{target}')
        except:
            self.parsed_url = urlparse(f'http://{target}')
    
    def run_sync(self) -> List[Dict[str, Any]]:
        """Run synchronous scan and return findings"""
        self.findings = []
        
        self._check_http_headers()
        self._check_ssl_tls()
        self._check_common_vulnerabilities()
        self._check_information_disclosure()
        self._check_security_headers()
        
        return self.findings
    
    def _check_http_headers(self):
        """Check HTTP headers for security issues"""
        url = self.parsed_url.geturl()
        
        try:
            response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
            headers = response.headers
            
            missing_headers = []
            security_headers = {
                'strict-transport-security': 'HSTS',
                'content-security-policy': 'CSP',
                'x-frame-options': 'X-Frame-Options',
                'x-content-type-options': 'X-Content-Type-Options',
                'x-xss-protection': 'X-XSS-Protection',
                'referrer-policy': 'Referrer-Policy'
            }
            
            for header, name in security_headers.items():
                if header.lower() not in {k.lower() for k in headers.keys()}:
                    missing_headers.append(name)
            
            if missing_headers:
                self.findings.append({
                    'type': 'missing_security_headers',
                    'name': 'Security Headers Missing',
                    'severity': 'medium',
                    'description': f'Missing security headers: {", ".join(missing_headers)}',
                    'recommendation': 'Implement security headers to enhance protection'
                })
            
            if 'Server' in headers:
                self.findings.append({
                    'type': 'information_disclosure',
                    'name': 'Server Header Exposed',
                    'severity': 'low',
                    'description': f'Server header reveals: {headers["Server"]}',
                    'recommendation': 'Consider hiding server version information'
                })
            
            if 'X-Powered-By' in headers:
                self.findings.append({
                    'type': 'information_disclosure',
                    'name': 'X-Powered-By Header Exposed',
                    'severity': 'low',
                    'description': f'X-Powered-By reveals: {headers["X-Powered-By"]}',
                    'recommendation': 'Remove or hide X-Powered-By header'
                })
                
        except requests.RequestException as e:
            print(f"HTTP headers check failed: {e}")
    
    def _check_ssl_tls(self):
        """Check SSL/TLS configuration"""
        hostname = self.parsed_url.hostname
        port = self.parsed_url.port or 443
        
        if self.parsed_url.scheme != 'https':
            return
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    cert = ssock.getpeercert()
                    
                    if cipher:
                        cipher_name = cipher[0]
                        if any(w in cipher_name for w in ['RC4', 'DES', '3DES', 'MD5', 'SHA1']):
                            self.findings.append({
                                'type': 'weak_cipher',
                                'name': 'Weak TLS Cipher',
                                'severity': 'medium',
                                'description': f'Weak cipher in use: {cipher_name}',
                                'recommendation': 'Disable weak ciphers and use TLS 1.2 or higher'
                            })
                    
                    if cert:
                        import datetime
                        try:
                            not_after = cert.get('notAfter')
                            if not_after:
                                expiry = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                                days_remaining = (expiry - datetime.datetime.now()).days
                                
                                if days_remaining < 0:
                                    self.findings.append({
                                        'type': 'expired_certificate',
                                        'name': 'SSL Certificate Expired',
                                        'severity': 'critical',
                                        'description': 'SSL certificate has expired',
                                        'recommendation': 'Renew SSL certificate immediately'
                                    })
                                elif days_remaining < 30:
                                    self.findings.append({
                                        'type': 'expiring_certificate',
                                        'name': 'SSL Certificate Expiring Soon',
                                        'severity': 'high',
                                        'description': f'SSL certificate expires in {days_remaining} days',
                                        'recommendation': 'Plan certificate renewal'
                                    })
                        except:
                            pass
                            
        except ssl.SSLError as e:
            self.findings.append({
                'type': 'ssl_error',
                'name': 'SSL/TLS Error',
                'severity': 'high',
                'description': f'SSL error: {str(e)}',
                'recommendation': 'Fix SSL/TLS configuration'
            })
        except Exception as e:
            print(f"SSL/TLS check failed: {e}")
    
    def _check_common_vulnerabilities(self):
        """Check for common web vulnerabilities"""
        hostname = self.parsed_url.hostname
        port = self.parsed_url.port or (443 if self.parsed_url.scheme == 'https' else 80)
        base_url = f"{self.parsed_url.scheme}://{hostname}:{port}" if port not in [80, 443] else self.parsed_url.geturl()
        
        common_paths = [
            '/admin/', '/login/', '/wp-admin/', '/administrator/',
            '/phpmyadmin/', '/.git/', '/.env', '/config.php',
            '/backup/', '/api/', '/debug/', '/console/'
        ]
        
        for path in common_paths:
            try:
                url = base_url.rstrip('/') + path
                response = requests.get(url, timeout=5, verify=False, allow_redirects=False)
                
                if response.status_code == 200:
                    risk = 'high' if any(x in path.lower() for x in ['admin', 'config', 'env', 'git', 'backup']) else 'medium'
                    self.findings.append({
                        'type': 'exposed_path',
                        'name': 'Exposed Administrative Path',
                        'severity': risk,
                        'description': f'Path {path} is accessible (Status: {response.status_code})',
                        'url': url,
                        'recommendation': 'Restrict access to administrative paths'
                    })
            except:
                continue
    
    def _check_information_disclosure(self):
        """Check for information disclosure issues"""
        url = self.parsed_url.geturl()
        
        try:
            response = requests.get(url, timeout=10, verify=False)
            content = response.text.lower()
            
            disclosure_patterns = [
                (r'error.*mysql', 'MySQL Error', 'high'),
                (r'syntax.*error', 'Syntax Error', 'medium'),
                (r'warning.*php', 'PHP Warning', 'medium'),
                (r'stack.*trace', 'Stack Trace', 'high'),
                (r'exception', 'Exception', 'medium'),
                (r'debug.*mode', 'Debug Mode', 'high'),
                (r'copyright.*202[0-9]', 'Year Disclosure', 'low')
            ]
            
            import re
            for pattern, name, severity in disclosure_patterns:
                if re.search(pattern, content):
                    self.findings.append({
                        'type': 'information_disclosure',
                        'name': name,
                        'severity': severity,
                        'description': f'Potential {name} detected in response',
                        'recommendation': 'Disable detailed error messages in production'
                    })
                    break
                    
        except:
            pass
    
    def _check_security_headers(self):
        """Detailed security headers check"""
        url = self.parsed_url.geturl()
        
        try:
            response = requests.get(url, timeout=10, verify=False)
            headers = response.headers
            
            if 'X-Frame-Options' not in headers:
                self.findings.append({
                    'type': 'clickjacking_protection',
                    'name': 'Clickjacking Protection Missing',
                    'severity': 'medium',
                    'description': 'X-Frame-Options header not set',
                    'recommendation': 'Add X-Frame-Options: DENY or SAMEORIGIN'
                })
            
            if 'Content-Security-Policy' not in headers:
                self.findings.append({
                    'type': 'csp_missing',
                    'name': 'Content Security Policy Missing',
                    'severity': 'medium',
                    'description': 'CSP header not set',
                    'recommendation': 'Implement Content-Security-Policy header'
                })
            
            if 'Strict-Transport-Security' not in headers:
                self.findings.append({
                    'type': 'hsts_missing',
                    'name': 'HSTS Not Enabled',
                    'severity': 'low',
                    'description': 'HTTP Strict Transport Security not configured',
                    'recommendation': 'Enable HSTS with appropriate max-age'
                })
                
        except:
            pass
    
    def scan_sqli(self, param_url: str) -> List[Dict]:
        """Check for SQL injection vulnerabilities"""
        findings = []
        sqli_payloads = ["'", "' OR '1'='1", '" OR "1"="1"', "1' ORDER BY 1--"]
        
        try:
            for payload in sqli_payloads:
                test_url = f"{param_url}{payload}"
                response = requests.get(test_url, timeout=5, verify=False)
                
                error_patterns = ['sql syntax', 'mysql', 'sqlite', 'postgresql', 'ora-', 'microsoft sql']
                content_lower = response.text.lower()
                
                for pattern in error_patterns:
                    if pattern in content_lower:
                        findings.append({
                            'type': 'sqli',
                            'name': 'Potential SQL Injection',
                            'severity': 'critical',
                            'description': f'SQL error detected with payload: {payload}',
                            'payload': payload,
                            'recommendation': 'Use parameterized queries'
                        })
                        break
        except:
            pass
        
        return findings
    
    def scan_xss(self, param_url: str) -> List[Dict]:
        """Check for XSS vulnerabilities"""
        findings = []
        xss_payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
        
        try:
            for payload in xss_payloads:
                test_url = f"{param_url}{payload}"
                response = requests.get(test_url, timeout=5, verify=False)
                
                if payload in response.text:
                    findings.append({
                        'type': 'xss',
                        'name': 'Potential XSS Vulnerability',
                        'severity': 'high',
                        'description': f'XSS payload reflected in response',
                        'payload': payload,
                        'recommendation': 'Implement input sanitization and output encoding'
                    })
                    break
        except:
            pass
        
        return findings
