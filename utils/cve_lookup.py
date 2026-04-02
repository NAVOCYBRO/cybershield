import requests
import json
import os
from datetime import datetime, timedelta

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

class CVELookup:
    def __init__(self):
        self.nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cache = {}
        self.api_key = os.getenv('NVD_API_KEY', '')
        self.headers = {}
        if self.api_key:
            self.headers['apiKey'] = self.api_key
            print(f"NVD API key loaded: {self.api_key[:8]}...")
    
    def search_cves(self, product, version=None):
        """Search for CVEs related to a product and version - optimized"""
        if not product or product == 'unknown':
            return []
        
        cache_key = f"{product}_{version}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        cves = []
        
        try:
            keywords = self._extract_keywords(product)
            
            for keyword in keywords[:2]:
                params = {
                    'keywordSearch': keyword,
                    'resultsPerPage': 20
                }
                
                response = requests.get(self.nvd_api_url, params=params, headers=self.headers, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    for item in data.get('vulnerabilities', []):
                        cve_data = item.get('cve', {})
                        
                        cve_id = cve_data.get('id', '')
                        description = self._get_description(cve_data)
                        cvss_score = self._get_cvss_score(cve_data)
                        published = cve_data.get('published', '')
                        
                        cves.append({
                            'id': cve_id,
                            'description': description[:150] + '...' if len(description) > 150 else description,
                            'cvss_score': cvss_score,
                            'published': published,
                            'severity': self._get_severity(cvss_score)
                        })
            
            def sort_key(x):
                score = x['cvss_score'] or 0
                pub = x['published'][:4] if x['published'] else '1900'
                recency = int(pub) if pub.isdigit() else 1900
                return (score, recency)
            
            cves.sort(key=sort_key, reverse=True)
            self.cache[cache_key] = cves[:5]
            
        except Exception as e:
            print(f"CVE lookup failed for {product}: {e}")
        
        return self.cache.get(cache_key, [])
    
    def _extract_keywords(self, product):
        """Extract search keywords from product name"""
        keywords = []
        product_lower = product.lower()
        
        if 'apache' in product_lower:
            if 'http' in product_lower:
                keywords.append('apache http server')
            elif 'tomcat' in product_lower:
                keywords.append('apache tomcat')
        elif 'nginx' in product_lower:
            keywords.append('nginx')
        elif 'iis' in product_lower:
            keywords.append('internet information services')
        elif 'openssh' in product_lower or 'ssh' in product_lower:
            keywords.append('openssh')
        elif 'mysql' in product_lower:
            keywords.append('mysql')
        elif 'postgres' in product_lower:
            keywords.append('postgresql')
        elif 'redis' in product_lower:
            keywords.append('redis')
        elif 'mongodb' in product_lower:
            keywords.append('mongodb')
        elif 'elasticsearch' in product_lower:
            keywords.append('elasticsearch')
        elif 'wordpress' in product_lower:
            keywords.append('wordpress')
        elif 'joomla' in product_lower:
            keywords.append('joomla')
        elif 'drupal' in product_lower:
            keywords.append('drupal')
        elif 'apache struts' in product_lower:
            keywords.append('apache struts')
        elif 'openssl' in product_lower:
            keywords.append('openssl')
        elif 'jquery' in product_lower:
            keywords.append('jquery')
        elif 'react' in product_lower:
            keywords.append('react javascript library')
        elif 'angular' in product_lower:
            keywords.append('angular')
        elif 'vue' in product_lower:
            keywords.append('vue.js')
        elif 'node.js' in product_lower or 'nodejs' in product_lower:
            keywords.append('node.js')
        elif 'python' in product_lower:
            keywords.append('python')
        elif 'php' in product_lower:
            keywords.append('php')
        elif 'java' in product_lower:
            keywords.append('java')
        elif 'tomcat' in product_lower:
            keywords.append('apache tomcat')
        elif 'jboss' in product_lower:
            keywords.append('jboss')
        elif 'weblogic' in product_lower:
            keywords.append('weblogic')
        elif 'oracle' in product_lower:
            keywords.append('oracle database')
        elif 'mssql' in product_lower or 'sql server' in product_lower:
            keywords.append('microsoft sql server')
        else:
            keywords.append(product)
        
        return keywords
    
    def _get_description(self, cve_data):
        """Extract description from CVE data"""
        descriptions = cve_data.get('descriptions', [])
        for desc in descriptions:
            if desc.get('lang') == 'en':
                return desc.get('value', 'No description')
        return 'No description available'
    
    def _get_cvss_score(self, cve_data):
        """Extract CVSS score from CVE data"""
        try:
            metrics = cve_data.get('metrics', {})
            
            if 'cvssMetricV31' in metrics:
                for metric in metrics['cvssMetricV31']:
                    return metric.get('cvssData', {}).get('baseScore')
            
            if 'cvssMetricV30' in metrics:
                for metric in metrics['cvssMetricV30']:
                    return metric.get('cvssData', {}).get('baseScore')
            
            if 'cvssMetricV2' in metrics:
                for metric in metrics['cvssMetricV2']:
                    return metric.get('cvssData', {}).get('baseScore')
                    
        except:
            pass
        
        return None
    
    def _get_severity(self, cvss_score):
        """Determine severity based on CVSS score"""
        if cvss_score is None:
            return 'UNKNOWN'
        elif cvss_score >= 9.0:
            return 'CRITICAL'
        elif cvss_score >= 7.0:
            return 'HIGH'
        elif cvss_score >= 4.0:
            return 'MEDIUM'
        elif cvss_score > 0:
            return 'LOW'
        else:
            return 'NONE'
    
    def _is_relevant(self, cve_data, product, version):
        """Check if CVE is relevant to the product and version"""
        description = self._get_description(cve_data).lower()
        product_lower = product.lower()
        
        if product_lower in description:
            return True
        
        configurations = cve_data.get('configurations', [])
        for config in configurations:
            nodes = config.get('nodes', [])
            for node in nodes:
                cpe_matches = node.get('cpeMatch', [])
                for cpe in cpe_matches:
                    cpe_string = cpe.get('criteria', '').lower()
                    if product_lower in cpe_string:
                        if version:
                            if version in cpe_string:
                                return True
                        else:
                            return True
        
        return False
    
    def get_cve_details(self, cve_id):
        """Get detailed information about a specific CVE"""
        try:
            params = {'cveId': cve_id}
            response = requests.get(self.nvd_api_url, params=params, headers=self.headers, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                if vulnerabilities:
                    return vulnerabilities[0].get('cve', {})
        except Exception as e:
            print(f"Failed to get CVE details for {cve_id}: {e}")
        
        return None
    
    def search_recent_cves(self, product, days=30):
        """Search for recent CVEs affecting a product"""
        try:
            keywords = self._extract_keywords(product)
            
            recent_date = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%dT%H:%M:%S.000')
            
            all_cves = []
            for keyword in keywords:
                params = {
                    'keywordSearch': keyword,
                    'resultsPerPage': 50,
                    'pubStartDate': recent_date
                }
                
                response = requests.get(self.nvd_api_url, params=params, headers=self.headers, timeout=15)
                
                if response.status_code == 200:
                    data = response.json()
                    for item in data.get('vulnerabilities', []):
                        cve_data = item.get('cve', {})
                        cve_id = cve_data.get('id', '')
                        description = self._get_description(cve_data)
                        cvss_score = self._get_cvss_score(cve_data)
                        
                        all_cves.append({
                            'id': cve_id,
                            'description': description,
                            'cvss_score': cvss_score,
                            'severity': self._get_severity(cvss_score),
                            'published': cve_data.get('published', '')
                        })
            
            all_cves.sort(key=lambda x: x['cvss_score'] or 0, reverse=True)
            return all_cves[:10]
            
        except Exception as e:
            print(f"Failed to search recent CVEs: {e}")
            return []
    
    def search_cves_by_cpe(self, product, version=''):
        """Search CVEs using CPE matching for more accurate results"""
        if not product or product == 'unknown':
            return []
        
        cache_key = f"cpe_{product}_{version}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        cves = []
        
        try:
            cpe_product = self._product_to_cpe(product)
            if not cpe_product:
                return []
            
            params = {
                'cpeName': cpe_product,
                'resultsPerPage': 20
            }
            
            response = requests.get(self.nvd_api_url, params=params, headers=self.headers, timeout=15)
            
            if response.status_code == 403:
                print("NVD API rate limit reached. Waiting...")
                return []
            
            if response.status_code == 200:
                data = response.json()
                
                for item in data.get('vulnerabilities', [])[:10]:
                    cve_data = item.get('cve', {})
                    
                    cve_id = cve_data.get('id', '')
                    description = self._get_description(cve_data)
                    cvss_score = self._get_cvss_score(cve_data)
                    
                    cves.append({
                        'id': cve_id,
                        'description': description[:150] + '...' if len(description) > 150 else description,
                        'cvss_score': cvss_score,
                        'published': cve_data.get('published', ''),
                        'severity': self._get_severity(cvss_score)
                    })
            
            cves.sort(key=lambda x: x['cvss_score'] or 0, reverse=True)
            self.cache[cache_key] = cves[:5]
            
        except Exception as e:
            print(f"CPE CVE lookup failed for {product}: {e}")
        
        return self.cache.get(cache_key, [])
    
    def _product_to_cpe(self, product):
        """Convert product name to CPE format"""
        product_lower = product.lower()
        
        cpe_map = {
            'openssh': 'cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*',
            'ssh': 'cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*',
            'apache': 'cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*',
            'nginx': 'cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*',
            'mysql': 'cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*',
            'postgresql': 'cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*',
            'redis': 'cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*',
            'mongodb': 'cpe:2.3:a:mongodb:mongodb:*:*:*:*:*:*:*:*',
            'elasticsearch': 'cpe:2.3:a:elasticsearch:elasticsearch:*:*:*:*:*:*:*:*',
            'ssh': 'cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*',
            'vsftpd': 'cpe:2.3:a:vsftpd:vsftpd:*:*:*:*:*:*:*:*',
            'proftpd': 'cpe:2.3:a:proftpd:proftpd:*:*:*:*:*:*:*:*',
            'wordpress': 'cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*',
            'joomla': 'cpe:2.3:a:joomla:joomla:*:*:*:*:*:*:*:*',
            'drupal': 'cpe:2.3:a:drupal:drupal:*:*:*:*:*:*:*:*',
        }
        
        for key, cpe in cpe_map.items():
            if key in product_lower:
                return cpe
        
        return None
