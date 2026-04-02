import nmap
import socket
import requests
import re
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

try:
    from utils.cve_lookup import CVELookup
    CVE_LOOKUP_AVAILABLE = True
except ImportError:
    CVE_LOOKUP_AVAILABLE = False
    CVELookup = None

class PortScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.cve_lookup = CVELookup() if CVE_LOOKUP_AVAILABLE else None
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
            993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 27017, 6379,
            25, 53, 81, 300, 443, 500, 502, 503, 587, 993, 995, 1025,
            1026, 1027, 1028, 1029, 1110, 1234, 1311, 1337, 1433, 1434,
            1500, 1521, 1604, 1701, 1720, 1723, 1725, 1883, 1900, 1911,
            2000, 2001, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 2111,
            2121, 2375, 2376, 2379, 2525, 3000, 3128, 3268, 3300, 3306,
            3389, 3478, 3541, 3542, 3632, 4000, 4064, 4200, 4242, 4369,
            4443, 4444, 4445, 4500, 4567, 4711, 4712, 4786, 4840, 4843,
            4848, 5000, 5009, 5050, 5060, 5061, 5080, 5190, 5222, 5223,
            5357, 5432, 5433, 5500, 5556, 5672, 5683, 5900, 5901, 6000,
            6001, 6379, 6443, 6660, 6661, 6662, 6663, 6664, 6665, 6666,
            6667, 6668, 6669, 7000, 7001, 7002, 7003, 7004, 7005, 7006,
            7007, 7008, 7009, 7010, 7080, 7200, 7272, 7379, 7474, 7548,
            7676, 7777, 7778, 7779, 8000, 8001, 8008, 8009, 8010, 8020,
            8021, 8022, 8030, 8031, 8042, 8060, 8069, 8080, 8081, 8082,
            8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8091, 8092,
            8093, 8094, 8095, 8096, 8097, 8098, 8099, 8100, 8118, 8123,
            8139, 8140, 8180, 8181, 8200, 8222, 8243, 8280, 8281, 8333,
            8334, 8400, 8443, 8444, 8445, 8500, 8530, 8531, 8600, 8686,
            8761, 8765, 8800, 8834, 8880, 8888, 8889, 8983, 9000, 9001,
            9002, 9003, 9009, 9010, 9042, 9043, 9050, 9051, 9080, 9081,
            9090, 9091, 9092, 9093, 9094, 9095, 9096, 9097, 9098, 9099,
            9100, 9101, 9102, 9103, 9110, 9111, 9121, 9200, 9300, 9306,
            9418, 9443, 9500, 9530, 9595, 9600, 9876, 9877, 9878, 9898,
            9943, 9944, 9998, 9999, 10000, 10001, 10010, 10080, 10243, 10443,
            11211, 11311, 12000, 12345, 12443, 13000, 13443, 14000, 15000,
            16000, 16080, 17000, 18000, 18080, 18081, 18091, 18092, 19000,
            20000, 20880, 21000, 22000, 22222, 23023, 24000, 25000, 25565,
            26000, 27017, 27018, 27019, 28017, 30000, 31000, 32000, 33000,
            34000, 35000, 36000, 37000, 38000, 39000, 40000, 41000, 42000,
            43000, 44000, 45000, 46000, 47000, 48000, 49000, 49152, 50000,
            50030, 50060, 50070, 50090, 54321, 55553, 60000, 61613, 61616
        ]
        
        self.port_service_map = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
            53: 'dns', 80: 'http', 110: 'pop3', 111: 'rpcbind',
            135: 'msrpc', 139: 'netbios-ssn', 143: 'imap',
            443: 'https', 445: 'microsoft-ds', 993: 'imaps',
            995: 'pop3s', 1433: 'mssql', 1434: 'mssql-m',
            1521: 'oracle', 1723: 'pptp', 3306: 'mysql',
            3389: 'rdp', 5432: 'postgresql', 5900: 'vnc',
            5901: 'vnc', 6379: 'redis', 8080: 'http-proxy',
            8443: 'https-alt', 9200: 'elasticsearch',
            27017: 'mongodb'
        }
    
    def resolve_target(self, target):
        """Resolve hostname/domain to IP if needed"""
        try:
            parsed = urlparse(target if '://' in target else f'http://{target}')
            hostname = parsed.hostname or target
            if parsed.port:
                return hostname, parsed.port
            return hostname, None
        except:
            return target, None
    
    def scan_ports(self, target, ports=None, use_nmap_vuln_scripts=False):
        """Scan for open ports - optimized for speed"""
        if ports is None:
            ports = self.common_ports
        
        open_ports = []
        hostname, default_port = self.resolve_target(target)
        
        try:
            arguments = '-T5 -F --min-rate 1000'
            if use_nmap_vuln_scripts:
                arguments += ' -sV --script vuln'
            
            self.nm.scan(hostname, arguments=arguments, timeout=60)
            
            if hostname in self.nm.all_hosts():
                for proto in self.nm[hostname].all_protocols():
                    ports_found = self.nm[hostname][proto].keys()
                    for port in ports_found:
                        state = self.nm[hostname][proto][port]['state']
                        if state == 'open':
                            open_ports.append(port)
            
            if not open_ports:
                open_ports = self.manual_port_check(hostname, ports)
                
        except Exception as e:
            print(f"Nmap scan failed: {e}")
            open_ports = self.manual_port_check(hostname, ports)
        
        return sorted(open_ports)
    
    def manual_port_check(self, target, ports):
        """Manual TCP port checking - optimized"""
        open_ports = []
        
        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((target, port))
                sock.close()
                return port if result == 0 else None
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=200) as executor:
            futures = {executor.submit(check_port, port): port for port in ports}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
        
        return sorted(open_ports)
    
    def detect_services(self, target, open_ports, use_vuln_scripts=False):
        """Detect services running on open ports"""
        services = []
        hostname, _ = self.resolve_target(target)
        
        try:
            arguments = '-sV --version-intensity 5'
            if use_vuln_scripts:
                arguments += ' --script vuln'
            
            self.nm.scan(hostname, arguments=arguments)
            
            if hostname in self.nm.all_hosts():
                for proto in self.nm[hostname].all_protocols():
                    for port in open_ports:
                        if port in self.nm[hostname][proto]:
                            service_info = self.nm[hostname][proto][port]
                            service_data = {
                                'port': port,
                                'name': service_info.get('name', 'unknown'),
                                'version': service_info.get('version', ''),
                                'product': service_info.get('product', ''),
                                'extrainfo': service_info.get('extrainfo', ''),
                                'cpe': service_info.get('cpe', ''),
                                'protocol': proto
                            }
                            
                            if use_vuln_scripts:
                                scripts = service_info.get('script', {})
                                if scripts:
                                    service_data['vuln_scripts'] = scripts
                                    service_data['vulnerabilities'] = self._parse_vuln_scripts(scripts, port)
                            
                            services.append(service_data)
        except Exception as e:
            print(f"Service detection failed: {e}")
        
        if not services:
            for port in open_ports:
                service_name = self.port_service_map.get(port, 'unknown')
                services.append({
                    'port': port,
                    'name': service_name,
                    'version': 'unknown',
                    'product': '',
                    'extrainfo': '',
                    'cpe': '',
                    'protocol': 'tcp'
                })
        
        return services
    
    def _parse_vuln_scripts(self, scripts, port, service_name=''):
        """Parse nmap vulnerability scripts output - simplified"""
        vulnerabilities = []
        
        for script_name, output in scripts.items():
            output_lower = output.lower()
            
            if any(x in output_lower for x in ['vulnerability', 'vulnerable', 'cve-', 'expoit']):
                vuln = {
                    'script': script_name,
                    'port': port,
                    'service': service_name,
                    'output': output.strip(),
                    'severity': self._assess_severity(output),
                    'cves': self._extract_cves(output),
                    'summary': self._summarize_vuln(script_name, output)
                }
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _assess_severity(self, output):
        """Assess severity from script output"""
        output_lower = output.lower()
        if any(x in output_lower for x in ['critical', 'cvss:10', 'cvss:9']):
            return 'critical'
        elif any(x in output_lower for x in ['high', 'cvss:8', 'cvss:7']):
            return 'high'
        elif any(x in output_lower for x in ['medium', 'cvss:6', 'cvss:5']):
            return 'medium'
        elif any(x in output_lower for x in ['low', 'cvss:4', 'cvss:3']):
            return 'low'
        return 'info'
    
    def _extract_cves(self, output):
        """Extract CVE IDs from output"""
        cve_pattern = r'CVE-\d{4}-\d{4,}'
        return re.findall(cve_pattern, output)
    
    def scan_with_vuln_scripts(self, target, ports=None):
        """Full scan with vulnerability scripts"""
        open_ports = self.scan_ports(target, ports, use_nmap_vuln_scripts=True)
        services = self.detect_services(target, open_ports, use_vuln_scripts=True)
        
        return {
            'open_ports': open_ports,
            'services': services,
            'scan_type': 'vulnerability_scan'
        }
    
    def quick_scan(self, target):
        """Quick scan with common ports only"""
        quick_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 
                      993, 995, 3306, 3389, 5900, 8080, 8443]
        return self.scan_ports(target, quick_ports)
    
    def full_scan(self, target, use_vuln_scripts=False):
        """Full scan with all ports"""
        return self.scan_ports(target, use_nmap_vuln_scripts=use_vuln_scripts)
    
    def fast_vuln_scan(self, target):
        """Fast nmap scan with vulnerability scripts - optimized for quick results"""
        hostname, _ = self.resolve_target(target)
        results = {
            'open_ports': [],
            'services': [],
            'vulnerabilities': [],
            'cves': [],
            'scan_type': 'fast_vuln'
        }
        
        try:
            self.nm.scan(
                hostname,
                arguments='-sV --script vuln -T4 -F --max-retries 2 --host-timeout 30s',
                timeout=60
            )
            
            services_list = []
            
            if hostname in self.nm.all_hosts():
                for proto in self.nm[hostname].all_protocols():
                    for port in self.nm[hostname][proto].keys():
                        port_info = self.nm[hostname][proto][port]
                        if port_info['state'] == 'open':
                            results['open_ports'].append(port)
                            
                            service_data = {
                                'port': port,
                                'name': port_info.get('name', 'unknown'),
                                'version': port_info.get('version', ''),
                                'product': port_info.get('product', ''),
                                'protocol': proto
                            }
                            
                            scripts = port_info.get('script', {})
                            if scripts:
                                parsed_vulns = self._parse_vuln_scripts(scripts, port, service_data['name'])
                                if parsed_vulns:
                                    results['vulnerabilities'].extend(parsed_vulns)
                                    service_data['has_vulns'] = True
                                    
                                    for vuln in parsed_vulns:
                                        cve_ids = vuln.get('cves', [])
                                        for cve_id in cve_ids:
                                            results['cves'].append({
                                                'id': cve_id,
                                                'service': service_data['name'],
                                                'port': port,
                                                'severity': vuln.get('severity', 'UNKNOWN'),
                                                'description': vuln.get('summary', '')
                                            })
                                service_data['scripts'] = scripts
                            
                            port_cves = self.get_known_cves_for_port(port, service_data['name'])
                            for cve in port_cves:
                                if not any(c['id'] == cve['id'] for c in results['cves']):
                                    results['cves'].append(cve)
                            
                            services_list.append(service_data)
                            results['services'].append(service_data)
            
            nvd_cves = self.lookup_service_cves(services_list)
            for cve in nvd_cves:
                if not any(c['id'] == cve['id'] for c in results['cves']):
                    results['cves'].append(cve)
                            
        except Exception as e:
            print(f"Nmap fast vuln scan failed: {e}")
        
        return results
    
    def _summarize_vuln(self, script_name, output):
        """Create a short summary of the vulnerability"""
        first_line = output.split('\n')[0] if '\n' in output else output
        if len(first_line) > 150:
            first_line = first_line[:150] + '...'
        return first_line
    
    def lookup_service_cves(self, services):
        """Look up CVEs for detected services using NVD API"""
        if not self.cve_lookup:
            return []
        
        nvd_api_key = os.getenv('NVD_API_KEY', '')
        if nvd_api_key:
            self.cve_lookup.api_key = nvd_api_key
            self.cve_lookup.headers['apiKey'] = nvd_api_key
        
        all_cves = []
        seen_cves = set()
        
        for service in services:
            service_name = service.get('name', '').lower()
            version = service.get('version', '')
            product = service.get('product', '')
            
            if product:
                search_term = f"{product} {version}".strip()
            else:
                search_term = service_name
            
            if search_term and search_term != 'unknown':
                try:
                    cves = self.cve_lookup.search_cves(search_term, version)
                    
                    for cve in cves:
                        if cve['id'] not in seen_cves:
                            seen_cves.add(cve['id'])
                            cve['service'] = service_name
                            cve['port'] = service.get('port', 0)
                            all_cves.append(cve)
                except Exception as e:
                    print(f"CVE lookup failed for {search_term}: {e}")
        
        all_cves.sort(key=lambda x: x.get('cvss_score') or 0, reverse=True)
        return all_cves[:20]
    
    def get_known_cves_for_port(self, port, service_name=''):
        """Get known CVEs for common services based on port numbers"""
        known_cves_map = {
            21: {'service': 'ftp', 'cves': [
                {'id': 'CVE-2015-3306', 'desc': 'ProFTPD mod_copy remote code execution', 'severity': 'CRITICAL', 'cvss': 10.0},
                {'id': 'CVE-2011-3863', 'desc': 'ProFTPD heap overflow vulnerability', 'severity': 'HIGH', 'cvss': 7.5},
            ]},
            22: {'service': 'ssh', 'cves': [
                {'id': 'CVE-2024-6387', 'desc': 'OpenSSH regreSSHion RCE (Linux)', 'severity': 'CRITICAL', 'cvss': 9.8},
                {'id': 'CVE-2023-48795', 'desc': 'OpenSSH busylog potential RCE', 'severity': 'HIGH', 'cvss': 8.1},
                {'id': 'CVE-2020-15778', 'desc': 'scp allow command injection', 'severity': 'HIGH', 'cvss': 7.8},
            ]},
            23: {'service': 'telnet', 'cves': [
                {'id': 'CVE-2020-10188', 'desc': 'Telnetd arbitrary code execution', 'severity': 'CRITICAL', 'cvss': 9.8},
                {'id': 'CVE-2017-1778', 'desc': 'Telnet encryption not enforced', 'severity': 'HIGH', 'cvss': 7.5},
            ]},
            80: {'service': 'http', 'cves': [
                {'id': 'CVE-2024-21762', 'desc': 'FortiOS SSL VPN RCE', 'severity': 'CRITICAL', 'cvss': 9.8},
                {'id': 'CVE-2023-44487', 'desc': 'HTTP/2 Rapid Reset DoS', 'severity': 'HIGH', 'cvss': 7.5},
            ]},
            443: {'service': 'https', 'cves': [
                {'id': 'CVE-2024-21762', 'desc': 'FortiOS SSL VPN RCE', 'severity': 'CRITICAL', 'cvss': 9.8},
                {'id': 'CVE-2022-0778', 'desc': 'OpenSSL infinite loop in BN_mod_sqrt', 'severity': 'HIGH', 'cvss': 7.5},
            ]},
            445: {'service': 'smb', 'cves': [
                {'id': 'CVE-2017-0144', 'desc': 'EternalBlue SMB RCE (WannaCry)', 'severity': 'CRITICAL', 'cvss': 9.8},
                {'id': 'CVE-2022-38023', 'desc': 'SMB RCE vulnerability', 'severity': 'HIGH', 'cvss': 7.5},
            ]},
            3306: {'service': 'mysql', 'cves': [
                {'id': 'CVE-2024-20963', 'desc': 'MySQL Server RCE vulnerability', 'severity': 'CRITICAL', 'cvss': 9.8},
                {'id': 'CVE-2021-25215', 'desc': 'MySQL authentication bypass', 'severity': 'HIGH', 'cvss': 8.8},
            ]},
            3389: {'service': 'rdp', 'cves': [
                {'id': 'CVE-2019-0708', 'desc': 'BlueKeep RDP RCE vulnerability', 'severity': 'CRITICAL', 'cvss': 9.8},
                {'id': 'CVE-2022-21999', 'desc': 'Windows RDP RCE vulnerability', 'severity': 'CRITICAL', 'cvss': 9.0},
            ]},
            5432: {'service': 'postgresql', 'cves': [
                {'id': 'CVE-2024-1597', 'desc': 'PostgreSQL SQL injection vulnerability', 'severity': 'CRITICAL', 'cvss': 9.1},
                {'id': 'CVE-2023-2454', 'desc': 'PostgreSQL privilege escalation', 'severity': 'HIGH', 'cvss': 8.8},
            ]},
            5900: {'service': 'vnc', 'cves': [
                {'id': 'CVE-2023-27350', 'desc': 'Splashtop RCE vulnerability', 'severity': 'CRITICAL', 'cvss': 9.8},
                {'id': 'CVE-2022-27518', 'desc': 'RealVNC authentication bypass', 'severity': 'HIGH', 'cvss': 8.1},
            ]},
            6379: {'service': 'redis', 'cves': [
                {'id': 'CVE-2023-41053', 'desc': 'Redis arbitrary module execution', 'severity': 'CRITICAL', 'cvss': 9.1},
                {'id': 'CVE-2023-22458', 'desc': 'Redis heap overflow', 'severity': 'HIGH', 'cvss': 7.5},
            ]},
            8080: {'service': 'http-proxy', 'cves': [
                {'id': 'CVE-2024-21762', 'desc': 'FortiOS SSL VPN RCE', 'severity': 'CRITICAL', 'cvss': 9.8},
                {'id': 'CVE-2023-44487', 'desc': 'HTTP/2 Rapid Reset DoS', 'severity': 'HIGH', 'cvss': 7.5},
            ]},
            9200: {'service': 'elasticsearch', 'cves': [
                {'id': 'CVE-2024-3727', 'desc': 'Elasticsearch arbitrary code execution', 'severity': 'CRITICAL', 'cvss': 9.8},
                {'id': 'CVE-2023-31419', 'desc': 'Elasticsearch SSRF vulnerability', 'severity': 'HIGH', 'cvss': 8.6},
            ]},
            11211: {'service': 'memcached', 'cves': [
                {'id': 'CVE-2023-38545', 'desc': 'SOCKS5 heap overflow in curl', 'severity': 'CRITICAL', 'cvss': 9.8},
                {'id': 'CVE-2021-32717', 'desc': 'Memcached integer overflow', 'severity': 'HIGH', 'cvss': 7.5},
            ]},
            1433: {'service': 'mssql', 'cves': [
                {'id': 'CVE-2023-29360', 'desc': 'Microsoft SQL Server RCE', 'severity': 'CRITICAL', 'cvss': 9.0},
                {'id': 'CVE-2022-29145', 'desc': 'SQL Server RCE vulnerability', 'severity': 'HIGH', 'cvss': 8.8},
            ]},
            27017: {'service': 'mongodb', 'cves': [
                {'id': 'CVE-2023-0138', 'desc': 'MongoDB Server bypass authentication', 'severity': 'CRITICAL', 'cvss': 9.8},
                {'id': 'CVE-2022-26196', 'desc': 'MongoDB Server-Side JavaScript injection', 'severity': 'HIGH', 'cvss': 8.1},
            ]},
            8443: {'service': 'https-alt', 'cves': [
                {'id': 'CVE-2024-21762', 'desc': 'FortiOS SSL VPN RCE', 'severity': 'CRITICAL', 'cvss': 9.8},
            ]},
        }
        
        if port in known_cves_map:
            cves = known_cves_map[port]['cves']
            for cve in cves:
                cve['port'] = port
                cve['service'] = known_cves_map[port]['service']
            return cves
        return []
    
    def scan_with_cve_check(self, target, ports=None):
        """Full scan with CVE detection for detected services"""
        open_ports = self.scan_ports(target, ports, use_nmap_vuln_scripts=True)
        services = self.detect_services(target, open_ports, use_vuln_scripts=True)
        
        all_cves = []
        
        for service in services:
            nmap_cves = service.get('vulnerabilities', [])
            for vuln in nmap_cves:
                cve_ids = vuln.get('cves', [])
                for cve_id in cve_ids:
                    all_cves.append({
                        'id': cve_id,
                        'service': service.get('name', ''),
                        'port': service.get('port', 0),
                        'severity': vuln.get('severity', 'UNKNOWN'),
                        'script': vuln.get('script', ''),
                        'description': vuln.get('summary', '')
                    })
            
            port_cves = self.get_known_cves_for_port(service.get('port', 0), service.get('name', ''))
            for cve in port_cves:
                if not any(c['id'] == cve['id'] for c in all_cves):
                    all_cves.append(cve)
        
        nvd_cves = self.lookup_service_cves(services)
        for cve in nvd_cves:
            if not any(c['id'] == cve['id'] for c in all_cves):
                all_cves.append(cve)
        
        return {
            'open_ports': open_ports,
            'services': services,
            'cves': all_cves,
            'scan_type': 'cve_scan'
        }
