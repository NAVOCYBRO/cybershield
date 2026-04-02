let currentScanId = null;
let chatHistory = [];
let aiAvailable = false;
let scanResults = null;

document.addEventListener('DOMContentLoaded', () => {
    checkAIStatus();
    initTabs();
    initModeCards();
});

function showToast(type, message) {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <div class="toast-header">
            <span class="toast-title">${type.charAt(0).toUpperCase() + type.slice(1)}</span>
            <button class="toast-close" onclick="this.parentElement.parentElement.remove()">×</button>
        </div>
        <div class="toast-message">${message}</div>
    `;
    container.appendChild(toast);
    setTimeout(() => toast.remove(), 5000);
}

async function checkAIStatus() {
    try {
        const res = await fetch('/ai/status');
        const data = await res.json();
        aiAvailable = data.available;
        
        const dot = document.getElementById('aiStatusDot');
        if (dot) dot.classList.toggle('online', aiAvailable);
        
        if (aiAvailable) {
            showToast('success', `AI Connected via ${data.provider}`);
        }
    } catch (e) {
        console.error('AI status check failed:', e);
    }
}

function initTabs() {
    document.querySelectorAll('.tab-nav').forEach(tab => {
        tab.addEventListener('click', () => {
            const tabId = tab.dataset.tab;
            
            document.querySelectorAll('.tab-nav').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
            
            tab.classList.add('active');
            document.getElementById(`${tabId}Tab`).classList.add('active');
        });
    });
}

function initModeCards() {
    document.querySelectorAll('.mode-card').forEach(card => {
        card.addEventListener('click', () => {
            document.querySelectorAll('.mode-card').forEach(c => c.classList.remove('active'));
            card.classList.add('active');
        });
    });
}

// Scan Handler
document.getElementById('scanForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const target = document.getElementById('target').value;
    if (!target) {
        showToast('error', 'Please enter a target');
        return;
    }
    
    const formData = new FormData(e.target);
    const options = {
        port_scan: formData.get('port_scan') === 'on',
        leak_scan: formData.get('leak_scan') === 'on',
        web_scan: formData.get('web_scan') === 'on',
        xss_scan: formData.get('xss_scan') === 'on',
        sqli_scan: formData.get('sqli_scan') === 'on',
        nmap_vuln_scan: formData.get('nmap_vuln_scan') === 'on',
        ai_analysis: formData.get('ai_analysis') === 'on'
    };
    
    const btn = document.getElementById('scanButton');
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';
    
    const progressSection = document.getElementById('progressSection');
    progressSection.style.display = 'block';
    
    try {
        const res = await fetch('/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({ target, ...Object.fromEntries(Object.entries(options).map(([k,v]) => [k, v ? 'on' : 'off'])) })
        });
        
        const data = await res.json();
        
        if (data.status === 'scan_started') {
            currentScanId = data.scan_id;
            pollStatus(data.scan_id);
        }
    } catch (err) {
        showToast('error', 'Scan failed: ' + err.message);
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-rocket"></i> Start Security Scan';
    }
});

async function pollStatus(scanId) {
    const startTime = Date.now();
    const timeDisplay = document.getElementById('scanTime');
    
    const interval = setInterval(() => {
        timeDisplay.textContent = `${Math.floor((Date.now() - startTime) / 1000)}s`;
    }, 1000);
    
    async function poll() {
        try {
            const res = await fetch(`/scan/status/${scanId}`);
            const data = await res.json();
            
            document.getElementById('progressPercent').textContent = `${data.progress}%`;
            document.getElementById('progressFill').style.width = `${data.progress}%`;
            
            addProgressStep(data.current_step, data.status === 'running' ? 'active' : 'completed');
            
            if (data.status === 'completed') {
                clearInterval(interval);
                showToast('success', 'Scan completed!');
                loadResults(scanId);
                
                const btn = document.getElementById('scanButton');
                btn.disabled = false;
                btn.innerHTML = '<i class="fas fa-rocket"></i> Start Security Scan';
                
            } else if (data.status === 'error') {
                clearInterval(interval);
                showToast('error', data.error);
                
                const btn = document.getElementById('scanButton');
                btn.disabled = false;
                btn.innerHTML = '<i class="fas fa-rocket"></i> Start Security Scan';
            } else {
                setTimeout(poll, 1000);
            }
        } catch (e) {
            console.error('Poll error:', e);
            setTimeout(poll, 2000);
        }
    }
    
    poll();
}

function addProgressStep(text, status) {
    const steps = document.getElementById('progressSteps');
    const step = document.createElement('div');
    step.className = `progress-step ${status}`;
    step.innerHTML = `
        <div class="step-icon"><i class="fas fa-${status === 'completed' ? 'check' : 'sync-alt'} ${status === 'active' ? 'fa-spin' : ''}"></i></div>
        <div class="step-text">${text}</div>
        <div class="step-time">${new Date().toLocaleTimeString()}</div>
    `;
    steps.appendChild(step);
    steps.scrollTop = steps.scrollHeight;
}

async function loadResults(scanId) {
    try {
        const res = await fetch(`/scan/results/${scanId}`);
        scanResults = await res.json();
        
        document.getElementById('resultsContainer').style.display = 'block';
        document.getElementById('resultsTarget').textContent = scanResults.target;
        
        updateRiskMeter(scanResults.summary);
        updateOverview(scanResults);
        updateServices(scanResults);
        updateVulnerabilities(scanResults);
        updateLeaks(scanResults);
        updateAI(scanResults);
        
        document.getElementById('resultsContainer').scrollIntoView({ behavior: 'smooth' });
        
    } catch (e) {
        showToast('error', 'Failed to load results');
    }
}

function updateRiskMeter(summary) {
    const score = summary.risk_score || 0;
    const label = summary.risk_level || 'INFO';
    
    document.getElementById('riskScore').textContent = score;
    document.getElementById('riskLabel').textContent = label;
    
    const circle = document.getElementById('riskCircle');
    const offset = 283 - (283 * score / 100);
    circle.style.strokeDashoffset = offset;
    
    let color = '#22c55e';
    if (score >= 80) color = '#ef4444';
    else if (score >= 60) color = '#f97316';
    else if (score >= 40) color = '#eab308';
    
    circle.style.stroke = color;
    document.getElementById('riskScore').style.color = color;
    document.getElementById('riskLabel').style.color = color;
    
    const counts = summary.severity_counts || { critical: 0, high: 0, medium: 0, low: 0 };
    document.getElementById('criticalCount').textContent = counts.critical;
    document.getElementById('highCount').textContent = counts.high;
    document.getElementById('mediumCount').textContent = counts.medium;
    document.getElementById('lowCount').textContent = counts.low;
}

function updateServices(data) {
    const tab = document.getElementById('servicesTab');
    const ports = data.ports || [];
    const services = data.services || [];
    const vulns = data.vulnerabilities || {};
    const serviceVulns = vulns.service_vulns || [];
    
    const dangerPorts = [21, 23, 3306, 5432, 6379, 27017, 9200, 11211, 1433, 1521];
    
    let html = '<div class="services-container">';
    
    // Services list
    html += '<div class="services-section">';
    html += '<h4><i class="fas fa-server"></i> Detected Services</h4>';
    
    if (services.length > 0) {
        html += '<div class="services-grid">';
        services.forEach(s => {
            const portNum = typeof s === 'number' ? s : s.port || s;
            const serviceName = typeof s === 'string' ? s : s.name || 'unknown';
            const isDanger = dangerPorts.includes(portNum);
            
            html += `
                <div class="service-item ${isDanger ? 'danger' : ''}">
                    <div class="service-port">${portNum}</div>
                    <div class="service-name">${serviceName.toUpperCase()}</div>
                    ${isDanger ? '<i class="fas fa-exclamation-triangle"></i>' : '<i class="fas fa-check-circle"></i>'}
                </div>
            `;
        });
        html += '</div>';
    } else {
        html += '<p class="no-data">No services detected</p>';
    }
    html += '</div>';
    
    // Service vulnerabilities
    html += '<div class="services-section">';
    html += '<h4><i class="fas fa-shield-alt"></i> Service Security Issues</h4>';
    
    if (serviceVulns.length > 0) {
        html += '<div class="vuln-list">';
        serviceVulns.forEach(v => {
            const sevClass = v.severity?.toLowerCase() || 'medium';
            html += `
                <div class="service-vuln-card ${sevClass}">
                    <div class="vuln-badge ${sevClass}">${v.severity}</div>
                    <div class="vuln-info">
                        <h5>${v.name}</h5>
                        <p>Port ${v.port} - ${v.service}</p>
                        <p class="vuln-desc">${v.description}</p>
                    </div>
                    <div class="vuln-fixes">
                        <h6><i class="fas fa-tools"></i> How to Fix:</h6>
                        <ul>
                            ${(v.remediation || []).map(r => `<li>${r}</li>`).join('')}
                        </ul>
                    </div>
                </div>
            `;
        });
        html += '</div>';
    } else {
        html += '<p class="no-data success"><i class="fas fa-check-circle"></i> No dangerous services detected</p>';
    }
    html += '</div>';
    
    html += '</div>';
    
    html += `
        <style>
            .services-container { display: flex; flex-direction: column; gap: 20px; }
            .services-section { background: var(--bg-secondary); border-radius: 12px; padding: 20px; }
            .services-section h4 { margin-bottom: 15px; display: flex; align-items: center; gap: 10px; font-size: 16px; }
            .services-section h4 i { color: var(--accent); }
            .services-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(120px, 1fr)); gap: 10px; }
            .service-item { 
                display: flex; align-items: center; gap: 10px;
                padding: 12px 15px; background: var(--bg-card); 
                border-radius: 8px; border-left: 3px solid var(--low);
            }
            .service-item.danger { border-color: var(--high); }
            .service-item .service-port { font-family: monospace; font-size: 14px; color: var(--text-muted); }
            .service-item .service-name { flex: 1; font-size: 12px; font-weight: 600; }
            .service-item.danger i { color: var(--high); }
            .service-item:not(.danger) i { color: var(--low); }
            .vuln-list { display: flex; flex-direction: column; gap: 15px; }
            .service-vuln-card { background: var(--bg-card); border-radius: 10px; padding: 15px; border-left: 4px solid var(--medium); }
            .service-vuln-card.critical { border-color: var(--critical); }
            .service-vuln-card.high { border-color: var(--high); }
            .service-vuln-card.medium { border-color: var(--medium); }
            .service-vuln-card.low { border-color: var(--low); }
            .vuln-badge { display: inline-block; padding: 3px 10px; border-radius: 10px; font-size: 10px; font-weight: 600; text-transform: uppercase; margin-bottom: 10px; }
            .vuln-badge.critical { background: var(--critical); }
            .vuln-badge.high { background: var(--high); }
            .vuln-badge.medium { background: var(--medium); color: #000; }
            .vuln-badge.low { background: var(--low); }
            .service-vuln-card h5 { font-size: 14px; margin-bottom: 5px; }
            .service-vuln-card p { font-size: 12px; color: var(--text-muted); margin-bottom: 5px; }
            .vuln-desc { color: var(--text-secondary) !important; }
            .vuln-fixes { margin-top: 10px; padding-top: 10px; border-top: 1px solid rgba(255,255,255,0.1); }
            .vuln-fixes h6 { font-size: 11px; color: var(--accent); margin-bottom: 8px; display: flex; align-items: center; gap: 5px; }
            .vuln-fixes ul { margin: 0; padding-left: 20px; }
            .vuln-fixes li { font-size: 12px; color: var(--text-secondary); margin-bottom: 4px; }
            .no-data { text-align: center; padding: 20px; color: var(--text-muted); }
            .no-data.success { color: var(--low); }
            .no-data i { display: block; font-size: 24px; margin-bottom: 10px; }
        </style>
    `;
    
    tab.innerHTML = html;
}

function updateOverview(data) {
    const tab = document.getElementById('overviewTab');
    const ports = data.ports || [];
    const services = data.services || [];
    const vulns = data.vulnerabilities || {};
    const leaks = data.leaks || {};
    
    const totalVulns = Object.values(vulns).flat().length;
    const totalLeaks = Object.values(leaks).flat().length;
    const serviceVulns = (vulns.service_vulns || []).length;
    
    const riskColors = {
        critical: 'var(--critical)',
        high: 'var(--high)',
        medium: 'var(--medium)',
        low: 'var(--low)',
        info: 'var(--info)'
    };
    
    tab.innerHTML = `
        <div class="overview-grid">
            <div class="overview-card">
                <h4><i class="fas fa-shield-halved"></i> Risk Score</h4>
                <div class="overview-big-stat" style="color: ${riskColors[data.summary?.risk_level?.toLowerCase()] || 'var(--accent)'}">
                    ${data.summary?.risk_score || 0}
                </div>
                <small>${data.summary?.risk_level || 'UNKNOWN'}</small>
            </div>
            <div class="overview-card">
                <h4><i class="fas fa-bug"></i> Vulnerabilities</h4>
                <div class="overview-big-stat">${totalVulns}</div>
                <small>${serviceVulns > 0 ? `${serviceVulns} service issues` : 'Issues found'}</small>
            </div>
            <div class="overview-card">
                <h4><i class="fas fa-door-open"></i> Open Ports</h4>
                <div class="overview-big-stat">${ports.length}</div>
                <small>${ports.length > 15 ? 'Large attack surface!' : 'Ports detected'}</small>
            </div>
            <div class="overview-card ${totalLeaks > 0 ? 'danger' : ''}">
                <h4><i class="fas fa-key"></i> Data Leaks</h4>
                <div class="overview-big-stat">${totalLeaks}</div>
                <small>${totalLeaks > 0 ? 'Immediate action needed!' : 'No leaks detected'}</small>
            </div>
        </div>
        
        <div class="overview-ports">
            <h4><i class="fas fa-server"></i> Open Ports & Services</h4>
            <div class="port-service-list">
                ${ports.length > 0 ? ports.slice(0, 25).map((p, i) => {
                    const svc = services[i] || '';
                    const dangerPorts = [21, 23, 3306, 5432, 6379, 27017, 9200, 11211];
                    const isDanger = dangerPorts.includes(p);
                    return `<span class="port-svc-item ${isDanger ? 'danger' : ''}">
                        <span class="port-num">${p}</span>
                        <span class="svc-name">${svc}</span>
                        ${isDanger ? '<i class="fas fa-exclamation-triangle"></i>' : ''}
                    </span>`;
                }).join('') : '<span class="no-data">No open ports detected</span>'}
                ${ports.length > 25 ? `<span class="more-badge">+${ports.length - 25} more</span>` : ''}
            </div>
        </div>
        
        <style>
            .overview-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 20px; }
            .overview-card { background: var(--bg-secondary); padding: 20px; border-radius: 12px; text-align: center; }
            .overview-card.danger { border: 1px solid var(--critical); }
            .overview-card h4 { font-size: 12px; color: var(--text-muted); margin-bottom: 10px; display: flex; align-items: center; justify-content: center; gap: 8px; }
            .overview-card h4 i { color: var(--accent); }
            .overview-big-stat { font-size: 32px; font-weight: 700; margin-bottom: 5px; }
            .overview-card small { font-size: 11px; color: var(--text-muted); }
            .overview-ports { background: var(--bg-secondary); padding: 20px; border-radius: 12px; }
            .overview-ports h4 { font-size: 14px; color: var(--text-secondary); margin-bottom: 15px; display: flex; align-items: center; gap: 8px; }
            .overview-ports h4 i { color: var(--accent); }
            .port-service-list { display: flex; flex-wrap: wrap; gap: 8px; }
            .port-svc-item { display: flex; align-items: center; gap: 8px; padding: 8px 12px; background: var(--bg-card); border-radius: 8px; border-left: 3px solid var(--low); }
            .port-svc-item.danger { border-color: var(--high); background: rgba(249, 115, 22, 0.1); }
            .port-num { font-family: monospace; font-size: 13px; font-weight: 600; }
            .svc-name { font-size: 11px; color: var(--text-muted); text-transform: uppercase; }
            .port-svc-item.danger .svc-name { color: var(--high); }
            .port-svc-item.danger i { color: var(--high); font-size: 10px; }
            .more-badge { padding: 8px 12px; background: var(--bg-hover); border-radius: 8px; font-size: 11px; color: var(--text-muted); }
            .no-data { color: var(--text-muted); font-size: 13px; }
            @media (max-width: 768px) {
                .overview-grid { grid-template-columns: repeat(2, 1fr); }
            }
        </style>
    `;
}

function updateVulnerabilities(data) {
    const tab = document.getElementById('vulnerabilitiesTab');
    const vulns = data.vulnerabilities || {};
    
    let html = '<div class="vuln-grid">';
    
    // Service vulnerabilities (NEW - show first)
    (vulns.service_vulns || []).forEach(v => {
        html += createVulnCard('service', v.name || 'Service Issue', v.severity || 'medium',
            `${v.description || 'Service vulnerability detected'}`, v);
    });
    
    // XSS
    (vulns.xss || []).forEach(v => {
        html += createVulnCard('xss', 'XSS Vulnerability', v.severity || 'high', 
            `${v.description || 'Cross-Site Scripting detected'}`, v);
    });
    
    // SQLi
    (vulns.sqli || []).forEach(v => {
        html += createVulnCard('sqli', 'SQL Injection', 'critical',
            `${v.description || 'SQL Injection detected'}`, v);
    });
    
    // Nmap vulnerabilities
    (vulns.nmap_vuln || []).forEach(v => {
        html += createVulnCard('nmap', v.script || 'Nmap Finding', v.severity || 'medium',
            `${v.summary || v.output || 'Nmap vulnerability detected'}`, v);
    });
    
    // Web vulns
    (vulns.web || []).forEach(v => {
        html += createVulnCard(v.type || 'web', v.name || 'Web Issue', v.severity || 'medium',
            `${v.description || v.name || 'Web vulnerability found'}`, v);
    });
    
    html += '</div>';
    
    if (html === '<div class="vuln-grid"></div>') {
        html = '<p style="text-align:center; padding:40px; color:var(--text-muted);"><i class="fas fa-check-circle" style="font-size:48px; display:block; margin-bottom:15px;"></i>No vulnerabilities detected!</p>';
    }
    
    tab.innerHTML = html;
}

function createVulnCard(type, title, severity, desc, data) {
    const sevClass = severity?.toLowerCase() || 'medium';
    return `
        <div class="vuln-card ${sevClass}">
            <div class="vuln-header">
                <span class="vuln-title">${title}</span>
                <span class="vuln-severity ${sevClass}">${severity}</span>
            </div>
            <p class="vuln-desc">${desc}</p>
            <div class="vuln-meta">
                ${data.parameter ? `<span><i class="fas fa-key"></i> Param: ${data.parameter}</span>` : ''}
                ${data.path ? `<span><i class="fas fa-folder"></i> ${data.path}</span>` : ''}
                ${data.port ? `<span><i class="fas fa-plug"></i> Port: ${data.port}</span>` : ''}
                ${data.service ? `<span><i class="fas fa-server"></i> ${data.service}</span>` : ''}
            </div>
            ${data.remediation && data.remediation.length > 0 ? `
                <div class="vuln-remediation">
                    <h5><i class="fas fa-tools"></i> How to Fix:</h5>
                    <ul class="fix-list">
                        ${data.remediation.slice(0, 3).map((r, i) => `<li><span class="fix-num">${i + 1}.</span> ${r}</li>`).join('')}
                    </ul>
                </div>
            ` : ''}
        </div>
    `;
}

function updateLeaks(data) {
    const tab = document.getElementById('leaksTab');
    const leaks = data.leaks || {};
    
    const leakTypes = {
        credentials: { icon: 'key', title: 'Exposed Credentials', color: 'critical' },
        api_keys: { icon: 'lock', title: 'API Endpoints', color: 'high' },
        emails: { icon: 'envelope', title: 'Exposed Emails', color: 'medium' },
        config_exposure: { icon: 'folder-open', title: 'Sensitive Files', color: 'high' },
        sensitive_files: { icon: 'file-alt', title: 'Sensitive Data', color: 'high' },
        debug_info: { icon: 'bug', title: 'Debug Info', color: 'medium' }
    };
    
    const fixTips = {
        credentials: ['Rotate exposed credentials immediately', 'Enable MFA on all accounts', 'Check logs for unauthorized access'],
        api_keys: ['Revoke exposed API keys', 'Use environment variables for secrets', 'Enable API key rotation'],
        emails: ['Remove emails from public files', 'Use contact forms instead', 'Monitor for phishing attempts'],
        config_exposure: ['Restrict file access immediately', 'Remove sensitive files from web root', 'Check for git history exposure'],
        sensitive_files: ['Delete or move files out of web root', 'Update .gitignore', 'Review file permissions']
    };
    
    let html = '<div class="leaks-container">';
    
    let hasLeaks = false;
    for (const [type, info] of Object.entries(leakTypes)) {
        const items = leaks[type] || [];
        if (items.length > 0) {
            hasLeaks = true;
            html += `
                <div class="leak-card">
                    <div class="leak-header">
                        <span class="leak-type"><i class="fas fa-${info.icon}"></i> ${info.title}</span>
                        <span class="leak-count ${info.color}">${items.length}</span>
                    </div>
                    <div class="leak-items">
                        ${items.slice(0, 5).map(item => {
                            let content = '';
                            if (type === 'credentials') content = `${item.file}: ${item.match}`;
                            else if (type === 'api_keys') content = `${item.endpoint} (${item.status})`;
                            else if (type === 'emails') content = item.email;
                            else if (item.file || item.type) content = item.file || item.type;
                            else content = JSON.stringify(item).substring(0, 50);
                            return `<div class="leak-item"><code>${content}</code></div>`;
                        }).join('')}
                    </div>
                    ${fixTips[type] ? `
                        <div class="leak-fix">
                            <h6><i class="fas fa-tools"></i> Fix Steps:</h6>
                            <ul>
                                ${fixTips[type].map((tip, i) => `<li><span class="fix-num">${i+1}.</span> ${tip}</li>`).join('')}
                            </ul>
                        </div>
                    ` : ''}
                </div>
            `;
        }
    }
    
    if (!hasLeaks) {
        html += `
            <div class="no-leaks">
                <i class="fas fa-shield-check"></i>
                <h3>No Data Leaks Detected</h3>
                <p>Your target appears to be handling data securely</p>
            </div>
        `;
    }
    
    html += '</div>';
    
    html += `
        <style>
            .leaks-container { display: flex; flex-direction: column; gap: 15px; }
            .leak-card { background: var(--bg-secondary); border-radius: 12px; padding: 20px; border-left: 4px solid var(--high); }
            .leak-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
            .leak-type { font-weight: 600; display: flex; align-items: center; gap: 10px; }
            .leak-type i { color: var(--accent); }
            .leak-count { padding: 3px 10px; border-radius: 10px; font-size: 12px; font-weight: 600; }
            .leak-count.critical { background: var(--critical); }
            .leak-count.high { background: var(--high); }
            .leak-count.medium { background: var(--medium); color: #000; }
            .leak-items { margin-bottom: 15px; }
            .leak-item { padding: 10px 12px; background: var(--bg-card); border-radius: 8px; margin-bottom: 8px; }
            .leak-item code { display: block; word-break: break-all; color: var(--text-primary); font-size: 12px; }
            .leak-fix { padding-top: 15px; border-top: 1px solid rgba(255,255,255,0.1); }
            .leak-fix h6 { font-size: 11px; color: var(--accent); margin-bottom: 10px; display: flex; align-items: center; gap: 5px; }
            .leak-fix ul { list-style: none; padding: 0; margin: 0; }
            .leak-fix li { font-size: 12px; color: var(--text-secondary); margin-bottom: 8px; display: flex; gap: 8px; }
            .fix-num { color: var(--accent); font-weight: 600; }
            .no-leaks { text-align: center; padding: 40px; background: var(--bg-secondary); border-radius: 12px; }
            .no-leaks i { font-size: 48px; color: var(--low); margin-bottom: 15px; }
            .no-leaks h3 { margin-bottom: 10px; }
            .no-leaks p { color: var(--text-muted); }
        </style>
    `;
    
    tab.innerHTML = html;
}

function updateRemediation(data) {
    const tab = document.getElementById('remediationTab');
    const rem = data.remediation || {};
    
    const roadmap = rem.remediation_roadmap || {};
    
    tab.innerHTML = `
        <div class="roadmap">
            <h4><i class="fas fa-exclamation-circle"></i> Immediate Actions (Critical)</h4>
            ${(roadmap.immediate || []).map(v => `<div class="roadmap-item critical">${v.name || v.type}</div>`).join('') || '<p>No critical issues</p>'}
            
            <h4 style="margin-top:20px;"><i class="fas fa-clock"></i> Short Term (High Priority)</h4>
            ${(roadmap.short_term || []).map(v => `<div class="roadmap-item high">${v.name || v.type}</div>`).join('') || '<p>No high priority issues</p>'}
            
            <h4 style="margin-top:20px;"><i class="fas fa-calendar"></i> Long Term</h4>
            ${(roadmap.long_term || []).map(v => `<div class="roadmap-item">${v.name || v.type}</div>`).join('') || '<p>No medium/low priority issues</p>'}
        </div>
        <style>
            .roadmap-item { padding: 12px 15px; background: var(--bg-secondary); border-radius: 8px; margin-bottom: 8px; border-left: 3px solid var(--low); }
            .roadmap-item.critical { border-color: var(--critical); }
            .roadmap-item.high { border-color: var(--high); }
            .roadmap h4 { margin-bottom: 10px; display: flex; align-items: center; gap: 8px; }
        </style>
    `;
}

function updateAI(data) {
    const tab = document.getElementById('aiTab');
    
    if (data.ai_analysis) {
        // Parse markdown and wrap in styled container
        const parsed = marked.parse(data.ai_analysis);
        tab.innerHTML = `
            <div class="ai-analysis-container">
                <div class="ai-header">
                    <i class="fas fa-robot"></i>
                    <span>AI Security Analysis</span>
                </div>
                <div class="ai-content">
                    ${parsed}
                </div>
            </div>
            <style>
                .ai-analysis-container {
                    background: var(--bg-secondary);
                    border-radius: 12px;
                    overflow: hidden;
                }
                .ai-header {
                    display: flex;
                    align-items: center;
                    gap: 10px;
                    padding: 15px 20px;
                    background: var(--gradient);
                    font-weight: 600;
                    font-size: 14px;
                }
                .ai-content { 
                    padding: 20px; 
                }
                .ai-content h1, .ai-content h2, .ai-content h3 {
                    color: var(--accent);
                    margin: 15px 0 10px 0;
                    font-size: 16px;
                    display: flex;
                    align-items: center;
                    gap: 8px;
                }
                .ai-content h1:first-child, .ai-content h2:first-child, .ai-content h3:first-child {
                    margin-top: 0;
                }
                .ai-content h1 { font-size: 18px; }
                .ai-content h2 { font-size: 16px; }
                .ai-content h3 { font-size: 14px; }
                .ai-content ul, .ai-content ol { 
                    margin: 10px 0 15px 25px; 
                }
                .ai-content li { 
                    margin-bottom: 8px;
                    line-height: 1.5;
                }
                .ai-content p { 
                    margin-bottom: 10px;
                    color: var(--text-secondary);
                }
                .ai-content strong { 
                    color: var(--critical); 
                    font-weight: 600;
                }
                .ai-content code { 
                    background: var(--bg-card); 
                    padding: 2px 6px; 
                    border-radius: 4px;
                    font-size: 12px;
                }
                .ai-content pre { 
                    background: var(--bg-card); 
                    padding: 12px; 
                    border-radius: 8px; 
                    overflow-x: auto;
                    margin: 10px 0;
                }
                .ai-content blockquote {
                    border-left: 3px solid var(--accent);
                    padding-left: 15px;
                    margin: 10px 0;
                    color: var(--text-muted);
                    font-style: italic;
                }
                .ai-content hr {
                    border: none;
                    border-top: 1px solid rgba(255,255,255,0.1);
                    margin: 15px 0;
                }
                .ai-content .warning { color: var(--high); }
                .ai-content .success { color: var(--low); }
                .ai-content .info { color: var(--info); }
            </style>
        `;
    } else {
        tab.innerHTML = `
            <div class="no-ai">
                <i class="fas fa-robot"></i>
                <h3>AI Analysis Not Available</h3>
                <p>Enable AI Analysis option to get detailed insights</p>
                <p class="hint">Set GROQ_API_KEY or OPENROUTER_API_KEY in .env file</p>
            </div>
            <style>
                .no-ai {
                    text-align: center;
                    padding: 40px;
                }
                .no-ai i {
                    font-size: 48px;
                    color: var(--text-muted);
                    margin-bottom: 15px;
                }
                .no-ai h3 { margin-bottom: 10px; }
                .no-ai p { color: var(--text-muted); }
                .no-ai .hint { font-size: 12px; margin-top: 10px; }
            </style>
        `;
    }
}

// Chat
async function sendMessage() {
    const input = document.getElementById('chatInput');
    const msg = input.value.trim();
    if (!msg) return;
    
    addChatMessage('user', msg);
    input.value = '';
    
    const chatMessages = document.getElementById('chatMessages');
    const typing = document.createElement('div');
    typing.className = 'message ai';
    typing.innerHTML = '<div class="message-content"><i class="fas fa-spinner fa-spin"></i> Analyzing...</div>';
    chatMessages.appendChild(typing);
    chatMessages.scrollTop = chatMessages.scrollHeight;
    
    try {
        const res = await fetch('/ai/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message: msg, scan_id: currentScanId, history: chatHistory })
        });
        
        const data = await res.json();
        chatMessages.removeChild(typing);
        
        if (data.status === 'success') {
            addChatMessage('ai', data.response);
            chatHistory.push({ role: 'user', content: msg });
            chatHistory.push({ role: 'assistant', content: data.response });
        } else {
            addChatMessage('ai', 'Error: ' + (data.error || 'Unknown error'));
        }
    } catch (e) {
        chatMessages.removeChild(typing);
        addChatMessage('ai', 'Connection error: ' + e.message);
    }
}

function addChatMessage(role, content) {
    const chatMessages = document.getElementById('chatMessages');
    const div = document.createElement('div');
    div.className = `message ${role}`;
    div.innerHTML = `<div class="message-content">${role === 'ai' ? marked.parse(content) : content}</div>`;
    chatMessages.appendChild(div);
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

// Placeholder for removed remediation function
function updateRemediation(data) {
    // Remediation is now shown in each vulnerability card
    const tab = document.getElementById('remediationTab');
    if (tab) {
        tab.innerHTML = `
            <div class="remediation-info">
                <i class="fas fa-tools"></i>
                <h3>Fix Steps Included in Vulnerability Cards</h3>
                <p>Each vulnerability now shows how to fix it. Check the Vulnerabilities tab for details.</p>
            </div>
            <style>
                .remediation-info { text-align: center; padding: 40px; background: var(--bg-secondary); border-radius: 12px; }
                .remediation-info i { font-size: 48px; color: var(--accent); margin-bottom: 15px; }
                .remediation-info h3 { margin-bottom: 10px; }
                .remediation-info p { color: var(--text-muted); }
            </style>
        `;
    }
}

// Export
function exportJSON() {
    if (!scanResults) return;
    const blob = new Blob([JSON.stringify(scanResults, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `scan-${currentScanId}.json`; a.click();
    showToast('success', 'JSON report downloaded');
}

function exportHTML() {
    if (!scanResults) return;
    const html = `<!DOCTYPE html><html><head><title>Scan Report</title></head><body><pre>${JSON.stringify(scanResults, null, 2)}</pre></body></html>`;
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `scan-${currentScanId}.html`; a.click();
    showToast('success', 'HTML report downloaded');
}

async function changeModel() {
    const model = document.getElementById('modelSelect').value;
    try {
        await fetch('/api/model/set', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ model })
        });
        showToast('success', `Model changed to ${model}`);
    } catch (e) {
        showToast('error', 'Failed to change model');
    }
}
