import os
import json
from typing import Dict, List, Optional, Any
from datetime import datetime


class AIAssistant:
    def __init__(self, ai_client):
        """Initialize AI Assistant with multi-provider support"""
        self.ai_client = ai_client
    
    def analyze_scan_results(self, scan_data: Dict) -> str:
        """Analyze scan results and provide expert analysis"""
        if not self.ai_client.get_status().get('available'):
            return self._fallback_analysis(scan_data)
        
        prompt = self._create_analysis_prompt(scan_data)
        
        messages = [
            {
                "role": "system",
                "content": """You are a friendly security expert explaining scan results in simple words.
                
STRICT RULES (MUST FOLLOW):
- NO PARAGRAPHS - ONLY bullet points
- NO long sentences - max 10 words each
- NO prose/description blocks
- Every item MUST be a bullet point starting with "-" or number
- Avoid technical jargon - use simple words
- Keep it under 200 words total

OUTPUT FORMAT (exactly like this):
### TOP THREATS
- Bullet point
- Another bullet

### HOW TO FIX
1. First fix
2. Second fix

### QUICK WINS
- Quick action
- Another action

### THREAT LEVEL
- One line only

BAD (paragraphs): "The vulnerability assessment indicates a critical SQL injection vulnerability in the login endpoint."
GOOD (bullets): "CRITICAL: Login page may let hackers steal data. Fix: Use secure code."
"""
            },
            {
                "role": "user",
                "content": prompt
            }
        ]
        
        response = self.ai_client.chat(messages, temperature=0.7, max_tokens=3000)
        
        if response:
            return response
        return self._fallback_analysis(scan_data)
    
    def answer_security_question(self, question: str, context: Optional[Dict] = None) -> str:
        """Answer user's security-related questions"""
        if not self.ai_client.get_status().get('available'):
            return self._fallback_response(question)
        
        messages = [
            {
                "role": "system",
                "content": """You are a cybersecurity expert assistant specializing in:
                - Network security
                - Vulnerability management
                - Incident response
                - Security best practices
                - Compliance (NIST, ISO27001, PCI-DSS)
                
                Provide accurate, practical advice. If unsure, say so and suggest resources."""
            }
        ]
        
        if context:
            context_str = json.dumps({
                'target': context.get('target'),
                'critical_findings': context.get('summary', {}).get('critical', 0),
                'high_findings': context.get('summary', {}).get('high', 0),
                'open_ports': len(context.get('open_ports', [])),
                'services': [s['name'] for s in context.get('services', [])][:5]
            }, indent=2)
            messages.append({
                "role": "system",
                "content": f"Current scan context:\n{context_str}"
            })
        
        messages.append({
            "role": "user",
            "content": question
        })
        
        response = self.ai_client.chat(messages, temperature=0.7, max_tokens=1500)
        
        if response:
            return response
        return self._fallback_response(question)
    
    def generate_remediation_plan(self, scan_data: Dict, specific_issue: str = None) -> str:
        """Generate detailed remediation plan"""
        if not self.ai_client.get_status().get('available'):
            return self._fallback_remediation_plan(scan_data)
        
        summary = scan_data.get('summary', {})
        
        prompt = f"""Generate a comprehensive remediation plan based on these security findings:
        
        TARGET: {scan_data.get('target', 'Unknown')}
        RISK LEVEL: {summary.get('risk_level', 'UNKNOWN')} ({summary.get('risk_score', 0)}/100)
        CRITICAL FINDINGS: {summary.get('critical', 0)}
        HIGH FINDINGS: {summary.get('high', 0)}
        OPEN PORTS: {len(scan_data.get('open_ports', []))}
        
        """
        
        if specific_issue:
            prompt += f"\nFOCUS AREA: {specific_issue}\n"
        
        prompt += """
        Provide a detailed plan with:
        
        PHASE 1: IMMEDIATE ACTIONS (First 24 hours)
        - Emergency patches
        - Access restrictions
        - Monitoring setup
        
        PHASE 2: SHORT-TERM REMEDIATION (1 week)
        - Patch management
        - Configuration hardening
        - Basic security controls
        
        PHASE 3: LONG-TERM IMPROVEMENTS (1 month)
        - Security architecture review
        - Process improvements
        - Training and awareness
        
        PHASE 4: VERIFICATION & VALIDATION
        - Rescan procedures
        - Success criteria
        - Compliance checks
        
        Include specific commands, configuration examples, and tool recommendations.
        """
        
        messages = [
            {
                "role": "system",
                "content": "You are a cybersecurity incident response and remediation specialist."
            },
            {
                "role": "user",
                "content": prompt
            }
        ]
        
        response = self.ai_client.chat(messages, temperature=0.7, max_tokens=4000)
        
        if response:
            return response
        return self._fallback_remediation_plan(scan_data)
    
    def generate_recommendations(self, scan_data: Dict) -> List[Dict]:
        """Generate recommendations based on scan results"""
        recommendations = []
        summary = self.generate_summary(scan_data)
        vulns = scan_data.get('vulnerabilities', {})
        cves = scan_data.get('cves', {})
        
        if summary.get('critical', 0) > 0:
            recommendations.append({
                'id': 'rec_001',
                'title': 'Patch Critical Vulnerabilities Immediately',
                'description': f"{summary.get('critical')} critical vulnerabilities require emergency patching",
                'severity': 'critical',
                'category': 'patch',
                'steps': [
                    'Identify affected systems and services',
                    'Apply emergency security patches',
                    'Restart services if required',
                    'Verify patch installation',
                    'Monitor for stability issues'
                ],
                'priority': 1,
                'estimated_time': '2-4 hours',
                'tools_needed': ['Patch Management', 'System Monitoring'],
                'business_impact': 'High'
            })
        
        open_ports = scan_data.get('open_ports', [])
        if len(open_ports) > 15:
            recommendations.append({
                'id': 'rec_002',
                'title': 'Reduce Network Attack Surface',
                'description': f"Too many open ports ({len(open_ports)}) increase attack surface",
                'severity': 'high',
                'category': 'network',
                'steps': [
                    'Review necessity of each open port',
                    'Close unnecessary ports',
                    'Implement firewall rules',
                    'Document allowed ports',
                    'Regular port scanning'
                ],
                'priority': 2,
                'estimated_time': '4-8 hours',
                'tools_needed': ['Firewall', 'Port Scanner'],
                'business_impact': 'Medium'
            })
        
        services = scan_data.get('services', [])
        for service in services[:3]:
            service_name = service.get('name', '').lower()
            
            if 'ssh' in service_name:
                recommendations.append({
                    'id': f'rec_{len(recommendations) + 1:03d}',
                    'title': 'Harden SSH Configuration',
                    'description': 'SSH service detected - implement security hardening',
                    'severity': 'high',
                    'category': 'configuration',
                    'steps': [
                        'Disable root login',
                        'Use key-based authentication',
                        'Implement fail2ban',
                        'Restrict allowed users',
                        'Change default port'
                    ],
                    'priority': 3,
                    'estimated_time': '1-2 hours',
                    'tools_needed': ['SSH Client', 'Text Editor'],
                    'business_impact': 'High'
                })
            
            if 'http' in service_name or 'apache' in service_name or 'nginx' in service_name:
                recommendations.append({
                    'id': f'rec_{len(recommendations) + 1:03d}',
                    'title': 'Secure Web Server Configuration',
                    'description': 'Web server requires security hardening',
                    'severity': 'medium',
                    'category': 'web',
                    'steps': [
                        'Implement security headers',
                        'Disable directory listing',
                        'Remove version information',
                        'Configure proper permissions',
                        'Enable HTTPS only'
                    ],
                    'priority': 4,
                    'estimated_time': '2-3 hours',
                    'tools_needed': ['Web Server Config', 'SSL Tools'],
                    'business_impact': 'Medium'
                })
        
        for service_name, cve_list in cves.items():
            if cve_list:
                critical_cves = [cve for cve in cve_list if cve.get('severity') in ['CRITICAL', 'HIGH']]
                if critical_cves:
                    cve_ids = [cve.get('id', 'CVE') for cve in critical_cves[:3]]
                    recommendations.append({
                        'id': f'rec_{len(recommendations) + 1:03d}',
                        'title': f'Patch {service_name} CVEs',
                        'description': f"Critical CVEs affecting {service_name}: {', '.join(cve_ids)}",
                        'severity': 'critical' if 'CRITICAL' in [c.get('severity') for c in critical_cves] else 'high',
                        'category': 'patch',
                        'steps': [
                            f"Check {service_name} vendor advisory",
                            'Apply security updates',
                            'Test functionality after patching',
                            'Monitor for issues',
                            'Document changes'
                        ],
                        'priority': 2,
                        'estimated_time': '3-6 hours',
                        'tools_needed': ['Patch Manager', 'Testing Tools'],
                        'cve_references': cve_ids,
                        'business_impact': 'High'
                    })
        
        return recommendations
    
    def generate_summary(self, scan_data: Dict) -> Dict:
        """Generate summary of findings"""
        total_critical = 0
        total_high = 0
        total_medium = 0
        total_low = 0
        
        vulns = scan_data.get('vulnerabilities', {})
        
        total_critical += len(vulns.get('critical_findings', []))
        total_high += len(vulns.get('high_findings', []))
        
        cves = scan_data.get('cves', {})
        for service_cves in cves.values():
            for cve in service_cves:
                severity = cve.get('severity', '').upper()
                if 'CRITICAL' in severity:
                    total_critical += 1
                elif 'HIGH' in severity:
                    total_high += 1
                elif 'MEDIUM' in severity:
                    total_medium += 1
                else:
                    total_low += 1
        
        web_vulns = vulns.get('web_vulns', {})
        if isinstance(web_vulns, dict):
            for vuln_type, vuln_list in web_vulns.items():
                if isinstance(vuln_list, list):
                    for web_vuln in vuln_list:
                        risk = web_vuln.get('risk', 'medium').lower()
                        if risk == 'critical':
                            total_critical += 1
                        elif risk == 'high':
                            total_high += 1
                        elif risk == 'medium':
                            total_medium += 1
                        else:
                            total_low += 1
        
        risk_score = min(100, (
            total_critical * 10 +
            total_high * 5 +
            total_medium * 2 +
            total_low * 1
        ))
        
        if risk_score >= 80:
            risk_level = 'CRITICAL'
        elif risk_score >= 60:
            risk_level = 'HIGH'
        elif risk_score >= 40:
            risk_level = 'MEDIUM'
        elif risk_score >= 20:
            risk_level = 'LOW'
        else:
            risk_level = 'INFO'
        
        xss_count = len(web_vulns.get('xss', [])) if isinstance(web_vulns, dict) else 0
        sqli_count = len(web_vulns.get('sqli', [])) if isinstance(web_vulns, dict) else 0
        
        return {
            'total_findings': total_critical + total_high + total_medium + total_low,
            'critical': total_critical,
            'high': total_high,
            'medium': total_medium,
            'low': total_low,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'ports_open': len(scan_data.get('open_ports', [])),
            'services_found': len(scan_data.get('services', [])),
            'cves_found': sum(len(c) for c in cves.values()),
            'xss_found': xss_count,
            'sqli_found': sqli_count
        }
    
    def assess_risk(self, scan_data: Dict) -> Dict:
        """Assess overall risk based on scan data"""
        summary = self.generate_summary(scan_data)
        
        risk_factors = []
        
        if summary.get('critical', 0) > 0:
            risk_factors.append({
                'factor': 'Critical Vulnerabilities',
                'impact': 'Critical',
                'description': f'{summary["critical"]} critical issues found'
            })
        
        open_ports = scan_data.get('open_ports', [])
        if len(open_ports) > 20:
            risk_factors.append({
                'factor': 'Large Attack Surface',
                'impact': 'High',
                'description': f'{len(open_ports)} open ports detected'
            })
        
        services = scan_data.get('services', [])
        risky_services = [s for s in services if any(x in s.get('name', '').lower() 
                      for x in ['telnet', 'ftp', 'rsh', 'finger'])]
        if risky_services:
            risk_factors.append({
                'factor': 'Insecure Services',
                'impact': 'High',
                'description': f'{len(risky_services)} insecure services running'
            })
        
        return {
            'risk_score': summary.get('risk_score', 0),
            'risk_level': summary.get('risk_level', 'UNKNOWN'),
            'risk_factors': risk_factors,
            'recommendations': [
                'Address critical vulnerabilities immediately',
                'Implement network segmentation',
                'Deploy intrusion detection systems'
            ]
        }
    
    def chat(self, message: str, history: List = None, context: Dict = None) -> str:
        """Interactive chat with context"""
        if not self.ai_client.get_status().get('available'):
            return "AI assistant is currently unavailable. Please check your API key configuration."
        
        messages = []
        
        messages.append({
            "role": "system",
            "content": """You are a helpful cybersecurity AI assistant. You help with:
            - Explaining security findings
            - Providing remediation guidance
            - Answering security questions
            - Suggesting best practices
            - Interpreting scan results
            
            Be conversational but professional. Use markdown for formatting when helpful."""
        })
        
        if context:
            services = context.get('services', [])
            if services and isinstance(services[0], dict):
                services_str = ', '.join([s.get('name', str(s)) for s in services[:3]])
            else:
                services_str = ', '.join([str(s) for s in services[:3]])
            
            context_summary = f"""
            Current Scan Context:
            - Target: {context.get('target', 'Unknown')}
            - Risk Score: {context.get('summary', {}).get('risk_score', 0)}/100
            - Critical Issues: {context.get('summary', {}).get('critical', 0)}
            - Open Ports: {len(context.get('ports', []))}
            - Top Services: {services_str}
            """
            messages.append({
                "role": "system",
                "content": context_summary
            })
        
        if history:
            for msg in history[-6:]:
                messages.append({
                    "role": msg.get("role", "user"),
                    "content": msg.get("content", "")
                })
        
        messages.append({
            "role": "user",
            "content": message
        })
        
        response = self.ai_client.chat(messages, temperature=0.8, max_tokens=2000)
        
        if response:
            return response
        return "I apologize, but I'm having trouble responding right now. Please try again."
    
    def _create_analysis_prompt(self, scan_data: Dict) -> str:
        """Create simple analysis prompt from scan data - output as bullet points"""
        summary = scan_data.get('summary', {})
        
        critical = summary.get('critical', 0)
        high = summary.get('high', 0)
        medium = summary.get('medium', 0)
        low = summary.get('low', 0)
        total = critical + high + medium + low
        
        vulns = scan_data.get('vulnerabilities', {})
        vuln_list = []
        for vuln_type, items in vulns.items():
            if items and isinstance(items, list):
                for item in items[:10]:
                    if isinstance(item, dict):
                        vuln_list.append({
                            'type': item.get('name', vuln_type),
                            'severity': item.get('severity', 'medium'),
                            'desc': item.get('description', item.get('summary', ''))[:100],
                            'remediation': item.get('remediation', [])[:2] if item.get('remediation') else []
                        })
        
        ports = scan_data.get('ports', [])[:15]
        services = scan_data.get('services', [])[:10]
        
        leaks = scan_data.get('leaks', {})
        leak_count = sum(len(v) for v in leaks.values()) if isinstance(leaks, dict) else 0
        
        cves = scan_data.get('cves', [])
        
        prompt = f"""SECURITY SCAN REPORT: {scan_data.get('target', 'Unknown')}

## QUICK STATS
- Risk Score: {summary.get('risk_score', 0)}/100 ({summary.get('risk_level', 'UNKNOWN')})
- Total Issues: {total}
- Critical: {critical} | High: {high} | Medium: {medium} | Low: {low}
- Open Ports: {len(scan_data.get('ports', []))}
- CVEs Found: {len(cves)}
- Data Leaks Found: {leak_count}

## OPEN PORTS
{chr(10).join(f'- Port {p}' for p in ports) if ports else '- No open ports detected'}

## SERVICES DETECTED
{chr(10).join(f'- {s}' for s in services) if services else '- No services identified'}

## VULNERABILITIES FOUND
"""
        for v in vuln_list[:15]:
            fix_tips = ''
            if v.get('remediation'):
                fix_tips = ' | Fix: ' + '; '.join(v['remediation'][:2])
            prompt += f"- [{v['severity'].upper()}] {v['type']}: {v['desc']}{fix_tips}\n"
        
        if cves:
            prompt += "\n## KNOWN CVEs (from NVD database)\n"
            for cve in cves[:10]:
                cve_id = cve.get('id', 'Unknown')
                cve_sev = cve.get('severity', cve.get('cvss_severity', 'UNKNOWN'))
                cve_desc = cve.get('description', cve.get('desc', ''))[:80]
                cve_port = cve.get('port', 'N/A')
                cve_service = cve.get('service', 'unknown')
                prompt += f"- [{cve_sev}] {cve_id} ({cve_service}): {cve_desc}\n"
        
        if leak_count > 0:
            prompt += "\n## DATA LEAKS\n"
            for leak_type, items in leaks.items() if isinstance(leaks, dict) else {}:
                if items:
                    prompt += f"- {leak_type.replace('_', ' ').title()}: {len(items)} found\n"
        
        prompt += """
## OUTPUT FORMAT (IMPORTANT - Use this exact format)
You MUST output in bullet points only. NO paragraphs, NO long sentences.

Format:
### TOP THREATS
- Bullet point (max 15 words)

### HOW TO FIX (numbered)
1. Fix step
2. Fix step

### QUICK WINS
- Actionable bullet
- Another action

### THREAT LEVEL
- One line assessment

Keep it SHORT. Max 200 words total. Use emojis sparingly."""
        
        return prompt
    
    def _fallback_analysis(self, scan_data: Dict) -> str:
        """Fallback analysis when AI is unavailable - in bullet points"""
        summary = scan_data.get('summary', {})
        ports = scan_data.get('ports', [])
        services = scan_data.get('services', [])
        vulns = scan_data.get('vulnerabilities', {})
        
        critical = summary.get('critical', 0)
        high = summary.get('high', 0)
        medium = summary.get('medium', 0)
        low = summary.get('low', 0)
        
        all_vulns = []
        for vuln_list in vulns.values():
            if isinstance(vuln_list, list):
                all_vulns.extend(vuln_list[:3])
        
        output = f"""
### QUICK STATS
- **Risk Score:** {summary.get('risk_score', 0)}/100 ({summary.get('risk_level', 'UNKNOWN')})
- **Critical:** {critical} | **High:** {high} | **Medium:** {medium} | **Low:** {low}
- **Open Ports:** {len(ports)} | **Services:** {len(services)}

### BIGGEST THREATS
"""
        
        if critical > 0:
            output += f"- **{critical} CRITICAL** vulnerabilities need immediate fix!\n"
        if high > 0:
            output += f"- **{high} HIGH** issues - fix within 48 hours\n"
        
        if all_vulns:
            for v in all_vulns[:5]:
                name = v.get('name', v.get('type', 'Unknown'))
                sev = v.get('severity', 'medium')
                output += f"- [{sev.upper()}] {name}\n"
        else:
            output += "- No major vulnerabilities detected\n"
        
        output += f"""
### HOW TO FIX (Priority Order)
1. Patch CRITICAL/HIGH vulnerabilities first
2. Close unnecessary open ports (found {len(ports)})
3. Restrict database access (MySQL, PostgreSQL, Redis, MongoDB)
4. Remove debug/error info from production
5. Enable firewall and access controls

### OPEN PORTS
- {', '.join(str(p) for p in ports[:10]) if ports else 'None detected'}
{f'- +{len(ports)-10} more ports' if len(ports) > 10 else ''}

### SERVICES FOUND
- {', '.join(services[:8]) if services else 'None identified'}

---
*Enable AI (GROQ_API_KEY or OPENROUTER_API_KEY) for detailed analysis*
"""
        return output
    
    def _fallback_response(self, question: str) -> str:
        """Fallback response for questions"""
        return f"""
        ## 🤖 AI Assistant Status: Offline
        
        **Your Question:** {question}
        
        ### To enable AI Assistant:
        1. Get a free API key from [Groq Cloud](https://console.groq.com) or [OpenRouter](https://openrouter.ai)
        2. Add `GROQ_API_KEY=your-key-here` or `OPENROUTER_API_KEY=your-key-here` to `.env` file
        3. Restart the application
        
        ### Basic Security Guidance:
        - **Patch Management:** Regularly update all software
        - **Access Control:** Implement least privilege principle
        - **Network Security:** Use firewalls and segmentation
        - **Monitoring:** Enable logging and alerting
        - **Backups:** Maintain regular, tested backups
        
        ### For immediate help:
        - [OWASP Top 10](https://owasp.org/www-project-top-ten/)
        - [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
        - [CVE Database](https://cve.mitre.org)
        
        *AI features require an internet connection and API key*
        """
    
    def _fallback_remediation_plan(self, scan_data: Dict) -> str:
        """Fallback remediation plan"""
        summary = scan_data.get('summary', {})
        
        return f"""
        ## 🛠️ BASIC REMEDIATION PLAN
        
        ### Target: {scan_data.get('target', 'Unknown')}
        ### Risk Score: {summary.get('risk_score', 0)}/100 ({summary.get('risk_level', 'UNKNOWN')})
        
        ### 🚨 IMMEDIATE ACTIONS (First 24 Hours)
        
        1. **Emergency Response**
           - Isolate system if critical vulnerabilities exist
           - Apply emergency patches
           - Change all default and weak passwords
        
        2. **Access Control**
           - Restrict network access to vulnerable ports
           - Implement IP whitelisting where possible
           - Disable unnecessary services
        
        3. **Monitoring Setup**
           - Enable firewall logging
           - Set up basic intrusion detection
           - Monitor for suspicious activity
        
        ### 📋 SHORT-TERM REMEDIATION (1 Week)
        
        1. **Patch Management**
           - Apply all available security updates
           - Update {len(scan_data.get('services', []))} detected services
           - Verify patch installation
        
        2. **Configuration Hardening**
           - Harden {len(scan_data.get('open_ports', []))} open ports
           - Remove unnecessary user accounts
           - Disable unused features
        
        3. **Basic Controls**
           - Implement basic firewall rules
           - Enable antivirus/malware protection
           - Configure basic logging
        
        ### 🏗️ LONG-TERM IMPROVEMENTS (1 Month)
        
        1. **Security Architecture**
           - Review network segmentation
           - Implement defense in depth
           - Regular vulnerability scanning
        
        2. **Process Improvement**
           - Establish patch management process
           - Create incident response plan
           - Conduct security awareness training
        
        3. **Compliance & Validation**
           - Regular security assessments
           - Penetration testing
           - Compliance verification
        
        ### ✅ VERIFICATION STEPS
        
        1. **Rescan target after remediation**
        2. **Verify risk score improvement**
        3. **Document all changes made**
        4. **Update security policies**
        
        ---
        *Enable AI Assistant for customized, detailed remediation plans with specific commands and configurations.*
        """
