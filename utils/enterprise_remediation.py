"""
Remediation System - Professional Security Recommendations
"""

class Remediation:
    def __init__(self):
        self.remediation_db = {
            'xss': {
                'name': 'Cross-Site Scripting (XSS)',
                'severity': 'HIGH',
                'cwe': 'CWE-79',
                'owasp': 'A7:2017 - Cross-Site Scripting (XSS)',
                'quick_fix': '''
// Quick Fix - Add to your HTML templates:
<script src="https://cdnjs.cloudflare.com/ajax/libs/dompurify/3.0.0/purify.min.js"></script>

// Sanitize user input:
const clean = DOMPurify.sanitize(userInput);
''',
                'full_remediation': {
                    'php': '''
// PHP - Use htmlspecialchars for output encoding
<?php echo htmlspecialchars($userInput, ENT_QUOTES, 'UTF-8'); ?>

// Or use a library like HTML Purifier
require_once 'HTMLPurifier.auto.php';
$config = HTMLPurifier_Config::createDefault();
$purifier = new HTMLPurifier($config);
$clean = $purifier->purify($dirty);
''',
                    'python': '''
// Python - Use Bleach library
import bleach
clean = bleach.clean(user_input, tags=['p', 'b', 'i'], attributes={'a': ['href']})

// Or use Jinja2 auto-escaping (default)
from jinja2 import Template
template = Template('Hello {{ name }}!')
template.render(name=user_input)
''',
                    'javascript': '''
// JavaScript - Use DOMPurify
import DOMPurify from 'dompurify';

const clean = DOMPurify.sanitize(dirty);
// Or escape HTML
function escapeHtml(text) {
    const map = {
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'': '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}
''',
                    'java': '''
// Java - Use OWASP Java Encoder
import org.owasp.encoder.Encode;
String safe = Encode.forHtml(userInput);
// Or use Jsoup
import org.jsoup.Jsoup;
String clean = Jsoup.clean(userInput, Whitelist.basic());
'''
                },
                'prevention': [
                    'Implement Content Security Policy (CSP) headers',
                    'Use template engines with auto-escaping (Jinja2, ERB, Thymeleaf)',
                    'Validate and sanitize all user inputs',
                    'Use HTTPOnly and Secure flags for cookies',
                    'Enable X-XSS-Protection header',
                    'Regular security testing and code review'
                ],
                'compliance': ['OWASP Top 10', 'PCI-DSS 6.5.7', 'HIPAA Security Rule']
            },
            'sqli': {
                'name': 'SQL Injection',
                'severity': 'CRITICAL',
                'cwe': 'CWE-89',
                'owasp': 'A1:2017 - Injection',
                'quick_fix': '''
// Quick Fix - NEVER do this:
const query = "SELECT * FROM users WHERE id = " + userId; // DANGEROUS!

// ALWAYS use parameterized queries:
const query = "SELECT * FROM users WHERE id = ?";
db.query(query, [userId]);
''',
                'full_remediation': {
                    'php': '''
// PHP - Use PDO with prepared statements
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->execute(['id' => $userId]);
$user = $stmt->fetch();

// Or use an ORM like Doctrine or Eloquent
''',
                    'python': '''
// Python - Use parameterized queries
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

// Or use SQLAlchemy ORM
from sqlalchemy import text
result = db.session.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})
''',
                    'javascript': '''
// JavaScript - Use parameterized queries
const query = 'SELECT * FROM users WHERE id = $1';
const result = await db.query(query, [userId]);

// Or use an ORM like Sequelize or Prisma
''',
                    'java': '''
// Java - Use PreparedStatement
String sql = "SELECT * FROM users WHERE id = ?";
PreparedStatement pstmt = connection.prepareStatement(sql);
pstmt.setInt(1, userId);
ResultSet rs = pstmt.executeQuery();

// Or use JPA/Hibernate
'''
                },
                'prevention': [
                    'Use parameterized queries (prepared statements) for all DB queries',
                    'Use ORM frameworks with proper escaping',
                    'Implement input validation and whitelist filtering',
                    'Use least privilege database accounts',
                    'Enable database error logging without exposing to users',
                    'Regular dependency and vulnerability scanning'
                ],
                'compliance': ['OWASP Top 10', 'PCI-DSS 6.5.1', 'HIPAA Security Rule', 'NIST SP 800-53']
            },
            'lfi': {
                'name': 'Local File Inclusion',
                'severity': 'HIGH',
                'cwe': 'CWE-22',
                'owasp': 'A5:2017 - Broken Access Control',
                'quick_fix': '''
// Quick Fix - Never include files based on user input directly
// DANGEROUS:
include($_GET['page'] . '.php');

// SAFE - Use a whitelist:
$allowed_pages = ['home', 'about', 'contact'];
$page = in_array($_GET['page'], $allowed_pages) ? $_GET['page'] : 'home';
include($page . '.php');
''',
                'full_remediation': {
                    'php': '''
// PHP - Use whitelist approach
$allowed_pages = [
    'home' => 'pages/home.php',
    'about' => 'pages/about.php',
    'contact' => 'pages/contact.php'
];

$page = $_GET['page'] ?? 'home';
if (isset($allowed_pages[$page])) {
    include $allowed_pages[$page];
} else {
    include 'pages/404.php';
}

// Never use user input directly in file operations
''',
                    'python': '''
// Python - Use whitelist approach
from pathlib import Path

ALLOWED_PAGES = {
    'home': 'pages/home.html',
    'about': 'pages/about.html',
    'contact': 'pages/contact.html'
}

page = request.args.get('page', 'home')
if page in ALLOWED_PAGES:
    return send_file(ALLOWED_PAGES[page])
else:
    abort(404)
'''
                },
                'prevention': [
                    'Never use user input directly in file operations',
                    'Implement whitelist-based page routing',
                    'Use base directory checking: realpath() in PHP, Path.resolve() in Python',
                    'Disable allow_url_fopen and allow_url_include',
                    'Implement proper access control checks',
                    'Use chroot jails or containerization'
                ],
                'compliance': ['OWASP Top 10', 'NIST SP 800-53 AC-3']
            },
            'leak_credentials': {
                'name': 'Exposed Credentials',
                'severity': 'CRITICAL',
                'cwe': 'CWE-312',
                'owasp': 'A3:2017 - Sensitive Data Exposure',
                'quick_fix': '''
// IMMEDIATE ACTIONS:
// 1. Rotate all exposed credentials NOW
// 2. Check if credentials were used
// 3. Enable MFA for all accounts
// 4. Review access logs

# Rotate AWS keys:
aws iam create-access-key --user-name username
aws iam update-access-key --access-key-id AKIA... --status Inactive

# Change database passwords:
ALTER USER 'app'@'%' IDENTIFIED BY 'new_strong_password';
FLUSH PRIVILEGES;
''',
                'full_remediation': {
                    'general': '''
// Password Management Best Practices:
1. Use password managers (Bitwarden, 1Password)
2. Use strong unique passwords (16+ chars, random)
3. Enable MFA everywhere possible
4. Never commit secrets to git
5. Use secret management services (AWS Secrets, HashiCorp Vault)

// For API keys:
// NEVER store in code or version control
// Use environment variables:
// export API_KEY="your-key-here"
// In code: process.env.API_KEY

// Use secret scanning tools:
// - GitGuardian
// - TruffleHog
// - SecretScanner
''',
                    'aws': '''
# AWS Secrets Manager
aws secretsmanager create-secret --name db-password --secret-string 'password'

# In application:
import boto3
client = boto3.client('secretsmanager')
secret = client.get_secret_value(SecretId='db-password')

# IAM policies - least privilege
{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": ["secretsmanager:GetSecretValue"],
        "Resource": "arn:aws:secretsmanager:region:account:secret:db-password"
    }]
}
'''
                },
                'prevention': [
                    'Use secret management services (AWS Secrets Manager, HashiCorp Vault)',
                    'Implement pre-commit hooks for secret scanning',
                    'Use .gitignore to exclude sensitive files',
                    'Enable secret scanning in your VCS',
                    'Regular security audits of exposed files',
                    'Implement proper access controls'
                ],
                'compliance': ['GDPR Art. 32', 'PCI-DSS 3.7', 'HIPAA Security Rule']
            },
            'debug_enabled': {
                'name': 'Debug Mode Enabled',
                'severity': 'HIGH',
                'cwe': 'CWE-489',
                'owasp': 'A6:2017 - Security Misconfiguration',
                'quick_fix': '''
// PRODUCTION - Disable all debug modes:

// Node.js
process.env.NODE_ENV = 'production';

// PHP
ini_set('display_errors', 0);
error_reporting(0);

// Python
import os
os.environ['DEBUG'] = 'False'

// Java
System.setProperty("debug.enabled", "false");
''',
                'full_remediation': {
                    'php': '''
// production.php or bootstrap
error_reporting(0);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', '/var/log/app/errors.log');

// Or in php.ini for production:
display_errors = Off
log_errors = On
error_log = /var/log/php_errors.log
''',
                    'nodejs': '''
// config/production.js
module.exports = {
    env: 'production',
    debug: false,
    logging: {
        level: 'error'
    }
};

// Use helmet.js for security headers
const helmet = require('helmet');
app.use(helmet());
'''
                },
                'prevention': [
                    'Use environment-based configuration',
                    'Separate development and production environments',
                    'Implement proper logging without exposing sensitive data',
                    'Use configuration management tools',
                    'Regular security configuration audits',
                    'Implement health checks that hide debug info'
                ],
                'compliance': ['OWASP Top 10', 'PCI-DSS 6.5.10']
            }
        }
    
    def get_remediation(self, vuln_type):
        """Get full remediation for a vulnerability type"""
        vuln_type = vuln_type.lower().replace(' ', '_')
        
        for key in self.remediation_db:
            if key in vuln_type:
                return self.remediation_db[key]
        
        return {
            'name': 'Unknown Vulnerability',
            'severity': 'MEDIUM',
            'cwe': 'Unknown',
            'quick_fix': 'Consult security documentation and best practices.',
            'prevention': [
                'Keep software updated',
                'Follow secure coding practices',
                'Regular security testing',
                'Security awareness training'
            ],
            'compliance': ['OWASP Guidelines']
        }
    
    def generate_report(self, findings):
        """Generate comprehensive remediation report"""
        report = {
            'executive_summary': self._generate_executive_summary(findings),
            'vulnerabilities': [],
            'remediation_roadmap': self._generate_roadmap(findings),
            'compliance_gaps': self._check_compliance(findings)
        }
        
        for vuln in findings:
            remediation = self.get_remediation(vuln.get('type', ''))
            report['vulnerabilities'].append({
                'vulnerability': vuln,
                'remediation': remediation
            })
        
        return report
    
    def _generate_executive_summary(self, findings):
        """Generate executive summary"""
        critical = sum(1 for f in findings if f.get('severity') == 'critical')
        high = sum(1 for f in findings if f.get('severity') == 'high')
        
        return {
            'total_findings': len(findings),
            'critical_count': critical,
            'high_count': high,
            'priority': 'CRITICAL' if critical > 0 else 'HIGH' if high > 0 else 'MEDIUM',
            'estimated_fix_time': f'{critical * 2 + high * 1} hours'
        }
    
    def _generate_roadmap(self, findings):
        """Generate remediation roadmap"""
        roadmap = {
            'immediate': [],
            'short_term': [],
            'long_term': []
        }
        
        for vuln in findings:
            severity = vuln.get('severity', 'medium')
            if severity == 'critical':
                roadmap['immediate'].append(vuln)
            elif severity == 'high':
                roadmap['short_term'].append(vuln)
            else:
                roadmap['long_term'].append(vuln)
        
        return roadmap
    
    def _check_compliance(self, findings):
        """Check compliance gaps"""
        required = ['OWASP Top 10', 'PCI-DSS']
        return {std: True for std in required}
