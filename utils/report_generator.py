import json
from datetime import datetime
from typing import Dict, Any

class ReportGenerator:
    def __init__(self):
        self.report_templates = {
            'executive': self._executive_template,
            'technical': self._technical_template,
            'detailed': self._detailed_template
        }
    
    def generate(self, scan_data: Dict, format: str = 'json') -> Any:
        """Generate report in specified format"""
        if format == 'json':
            return self._generate_json_report(scan_data)
        elif format == 'html':
            return self._generate_html_report(scan_data)
        elif format == 'text':
            return self._generate_text_report(scan_data)
        else:
            return self._generate_json_report(scan_data)
    
    def _generate_json_report(self, scan_data: Dict) -> Dict:
        """Generate JSON format report"""
        summary = scan_data.get('summary', {})
        
        report = {
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'report_type': 'security_scan',
                'target': scan_data.get('target', 'Unknown'),
                'scan_duration': scan_data.get('scan_duration', 0)
            },
            'executive_summary': {
                'risk_level': summary.get('risk_level', 'UNKNOWN'),
                'risk_score': summary.get('risk_score', 0),
                'total_findings': summary.get('total_findings', 0),
                'critical': summary.get('critical', 0),
                'high': summary.get('high', 0),
                'medium': summary.get('medium', 0),
                'low': summary.get('low', 0),
                'open_ports': summary.get('ports_open', 0),
                'services_detected': summary.get('services_found', 0),
                'cves_found': summary.get('cves_found', 0)
            },
            'network_findings': {
                'open_ports': scan_data.get('open_ports', []),
                'services': scan_data.get('services', [])
            },
            'vulnerabilities': scan_data.get('vulnerabilities', {}),
            'cve_details': scan_data.get('cves', {}),
            'recommendations': scan_data.get('recommendations', []),
            'ai_analysis': scan_data.get('ai_analysis', ''),
            'risk_assessment': scan_data.get('risk_assessment', {})
        }
        
        return report
    
    def _generate_html_report(self, scan_data: Dict) -> str:
        """Generate HTML format report"""
        summary = scan_data.get('summary', {})
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Scan Report - {scan_data.get('target', 'Unknown')}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; background: #1a1a2e; color: #fff; }}
                .header {{ text-align: center; margin-bottom: 40px; }}
                .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 30px; }}
                .stat-card {{ background: #16213e; padding: 20px; border-radius: 10px; text-align: center; }}
                .critical {{ border-left: 4px solid #ff4757; }}
                .high {{ border-left: 4px solid #ffa502; }}
                .medium {{ border-left: 4px solid #ffdd59; }}
                .low {{ border-left: 4px solid #2ed573; }}
                .section {{ background: #16213e; padding: 20px; margin-bottom: 20px; border-radius: 10px; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #333; }}
                th {{ background: #0f3460; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Security Scan Report</h1>
                <p>Target: {scan_data.get('target', 'Unknown')}</p>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="summary">
                <div class="stat-card critical">
                    <h3>Critical</h3>
                    <p style="font-size: 32px;">{summary.get('critical', 0)}</p>
                </div>
                <div class="stat-card high">
                    <h3>High</h3>
                    <p style="font-size: 32px;">{summary.get('high', 0)}</p>
                </div>
                <div class="stat-card medium">
                    <h3>Medium</h3>
                    <p style="font-size: 32px;">{summary.get('medium', 0)}</p>
                </div>
                <div class="stat-card low">
                    <h3>Low</h3>
                    <p style="font-size: 32px;">{summary.get('low', 0)}</p>
                </div>
            </div>
            
            <div class="section">
                <h2>Risk Assessment</h2>
                <p>Risk Level: <strong>{summary.get('risk_level', 'UNKNOWN')}</strong></p>
                <p>Risk Score: <strong>{summary.get('risk_score', 0)}/100</strong></p>
            </div>
            
            <div class="section">
                <h2>Open Ports ({len(scan_data.get('open_ports', []))})</h2>
                <p>{', '.join(map(str, scan_data.get('open_ports', [])))}</p>
            </div>
            
            <div class="section">
                <h2>Services Detected</h2>
                <table>
                    <tr><th>Port</th><th>Service</th><th>Version</th></tr>
        """
        
        for service in scan_data.get('services', []):
            html += f"<tr><td>{service.get('port')}</td><td>{service.get('name')}</td><td>{service.get('version', 'Unknown')}</td></tr>"
        
        html += """
                </table>
            </div>
            
            <div class="section">
                <h2>Recommendations</h2>
        """
        
        for rec in scan_data.get('recommendations', [])[:5]:
            html += f"""
                <div class="section {rec.get('severity', 'low')}">
                    <h3>{rec.get('title', 'Recommendation')}</h3>
                    <p>{rec.get('description', '')}</p>
                </div>
            """
        
        html += """
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _generate_text_report(self, scan_data: Dict) -> str:
        """Generate plain text report"""
        summary = scan_data.get('summary', {})
        
        report = f"""
================================================================================
                    CYBERSHIELD SECURITY SCAN REPORT
================================================================================

Target: {scan_data.get('target', 'Unknown')}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Scan Duration: {scan_data.get('scan_duration', 0):.2f} seconds

--------------------------------------------------------------------------------
                              EXECUTIVE SUMMARY
--------------------------------------------------------------------------------

Risk Level: {summary.get('risk_level', 'UNKNOWN')}
Risk Score: {summary.get('risk_score', 0)}/100

Total Findings: {summary.get('total_findings', 0)}
  - Critical: {summary.get('critical', 0)}
  - High: {summary.get('high', 0)}
  - Medium: {summary.get('medium', 0)}
  - Low: {summary.get('low', 0)}

Open Ports: {summary.get('ports_open', 0)}
Services Detected: {summary.get('services_found', 0)}
CVEs Found: {summary.get('cves_found', 0)}

--------------------------------------------------------------------------------
                              NETWORK FINDINGS
--------------------------------------------------------------------------------

Open Ports ({len(scan_data.get('open_ports', []))}):
"""
        
        for port in scan_data.get('open_ports', []):
            report += f"  - Port {port}\n"
        
        report += "\nServices Detected:\n"
        for service in scan_data.get('services', []):
            report += f"  - {service.get('port')}/tcp: {service.get('name')} {service.get('version', '')}\n"
        
        report += """
--------------------------------------------------------------------------------
                            VULNERABILITIES
--------------------------------------------------------------------------------
"""
        
        vulns = scan_data.get('vulnerabilities', {})
        for vuln_type, vuln_list in vulns.items():
            if vuln_list:
                report += f"\n{vuln_type.upper().replace('_', ' ')}:\n"
                for vuln in vuln_list[:5]:
                    report += f"  - [{vuln.get('risk', 'unknown').upper()}] {vuln.get('issue', 'Issue')}\n"
        
        report += """
--------------------------------------------------------------------------------
                              RECOMMENDATIONS
--------------------------------------------------------------------------------
"""
        
        for i, rec in enumerate(scan_data.get('recommendations', [])[:5], 1):
            report += f"""
{i}. [{rec.get('severity', 'unknown').upper()}] {rec.get('title', 'Recommendation')}
   {rec.get('description', '')}
   Priority: {rec.get('priority', 'N/A')}
   Estimated Time: {rec.get('estimated_time', 'N/A')}
"""
        
        report += """
================================================================================
                         END OF SECURITY SCAN REPORT
================================================================================
"""
        
        return report
    
    def _executive_template(self, scan_data: Dict) -> Dict:
        """Executive summary template"""
        summary = scan_data.get('summary', {})
        return {
            'report_type': 'executive',
            'title': 'Executive Security Summary',
            'target': scan_data.get('target'),
            'risk_level': summary.get('risk_level'),
            'risk_score': summary.get('risk_score'),
            'critical_findings': summary.get('critical', 0),
            'key_recommendations': [
                rec.get('title') for rec in scan_data.get('recommendations', [])[:3]
            ]
        }
    
    def _technical_template(self, scan_data: Dict) -> Dict:
        """Technical report template"""
        return {
            'report_type': 'technical',
            'target': scan_data.get('target'),
            'open_ports': scan_data.get('open_ports'),
            'services': scan_data.get('services'),
            'vulnerabilities': scan_data.get('vulnerabilities'),
            'cves': scan_data.get('cves')
        }
    
    def _detailed_template(self, scan_data: Dict) -> Dict:
        """Detailed report template"""
        return {
            'report_type': 'detailed',
            'full_data': scan_data,
            'ai_analysis': scan_data.get('ai_analysis'),
            'risk_assessment': scan_data.get('risk_assessment')
        }
