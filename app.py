"""
CyberShield - Main Application
AI-Powered Security Scanner
"""

from flask import Flask, render_template, request, jsonify, session
import threading
import queue
import json
import uuid
import time
import os
from datetime import datetime

from utils.enterprise_scanner import AdvancedScanner
from utils.ai_client import AIMultiClient
from utils.ai_assistant import AIAssistant
from utils.enterprise_remediation import Remediation
from utils.report_generator import ReportGenerator
from utils.history_analytics import (
    save_scan, get_scan_history, get_scan_by_id, delete_scan,
    get_analytics, get_statistics, get_recent_activity, init_db
)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'cybershield-key')
app.config['PERMANENT_SESSION_LIFETIME'] = 3600

results_queue = queue.Queue()
scan_data_store = {}
scan_status_store = {}

ai_client = AIMultiClient()
ai_assistant = AIAssistant(ai_client)
remediation_system = Remediation()
report_generator = ReportGenerator()

def run_scan(target, scan_id, options):
    """Run security scan"""
    try:
        scan_status_store[scan_id] = {
            'status': 'running',
            'progress': 0,
            'current_step': 'Initializing Scanner',
            'start_time': time.time()
        }
        
        scanner = AdvancedScanner()
        
        # Build scan options
        scan_options = {
            'port_scan': options.get('port_scan', True),
            'leak_scan': options.get('leak_scan', True),
            'web_scan': options.get('web_scan', True),
            'xss_scan': options.get('xss_scan', True),
            'sqli_scan': options.get('sqli_scan', True),
        }
        
        scan_status_store[scan_id]['current_step'] = 'Port Scanning'
        scan_status_store[scan_id]['progress'] = 10
        
        scan_status_store[scan_id]['current_step'] = 'Leak Detection'
        scan_status_store[scan_id]['progress'] = 30
        
        scan_status_store[scan_id]['current_step'] = 'Web Vulnerability Scan'
        scan_status_store[scan_id]['progress'] = 50
        
        scan_status_store[scan_id]['current_step'] = 'XSS Testing'
        scan_status_store[scan_id]['progress'] = 60
        
        scan_status_store[scan_id]['current_step'] = 'SQL Injection Testing'
        scan_status_store[scan_id]['progress'] = 70
        
        # Run comprehensive scan
        results = scanner.scan(target, scan_options)
        
        scan_status_store[scan_id]['progress'] = 80
        scan_status_store[scan_id]['current_step'] = 'Generating AI Analysis'
        
        # Generate AI analysis
        ai_analysis = ""
        if options.get('ai_analysis', True) and ai_client.get_status().get('available'):
            ai_analysis = ai_assistant.analyze_scan_results(results)
        
        scan_status_store[scan_id]['progress'] = 90
        scan_status_store[scan_id]['current_step'] = 'Generating Remediation'
        
        # Generate remediation
        all_vulns = []
        for vulns in results['vulnerabilities'].values():
            all_vulns.extend(vulns)
        
        remediation_report = remediation_system.generate_report(all_vulns)
        
        # Final results
        final_results = {
            'status': 'completed',
            'scan_id': scan_id,
            'target': target,
            'summary': results['summary'],
            'ports': results.get('ports', []),
            'services': results.get('services', []),
            'vulnerabilities': results['vulnerabilities'],
            'leaks': results['leaks'],
            'ai_analysis': ai_analysis,
            'remediation': remediation_report,
            'timestamp': datetime.now().isoformat(),
            'scan_duration': time.time() - scan_status_store[scan_id]['start_time']
        }
        
        scan_data_store[scan_id] = final_results
        
        try:
            save_scan(final_results)
        except Exception as e:
            print(f"Failed to save scan to history: {e}")
        
        scan_status_store[scan_id] = {
            'status': 'completed',
            'progress': 100,
            'current_step': 'Completed',
            'results': final_results
        }
        
        results_queue.put(final_results)
        
    except Exception as e:
        print(f"Scan error: {e}")
        import traceback
        traceback.print_exc()
        scan_status_store[scan_id] = {
            'status': 'error',
            'progress': 0,
            'current_step': 'Error',
            'error': str(e)
        }

@app.route('/')
def index():
    """Main page"""
    ai_status = ai_client.get_status()
    return render_template('index.html',
                         ai_provider=ai_status.get('provider', 'None'),
                         ai_available=ai_status.get('available', False),
                         ai_model=ai_status.get('model', 'N/A'))

@app.route('/scan', methods=['POST'])
def start_scan():
    """Start security scan"""
    target = request.form.get('target')
    
    if not target:
        return jsonify({'error': 'No target specified'}), 400
    
    options = {
        'port_scan': request.form.get('port_scan') == 'on',
        'leak_scan': request.form.get('leak_scan') == 'on',
        'web_scan': request.form.get('web_scan') == 'on',
        'xss_scan': request.form.get('xss_scan') == 'on',
        'sqli_scan': request.form.get('sqli_scan') == 'on',
        'nmap_vuln_scan': request.form.get('nmap_vuln_scan') == 'on',
        'ai_analysis': request.form.get('ai_analysis') == 'on',
        'lfi_scan': request.form.get('lfi_scan') == 'on',
        'ssrf_scan': request.form.get('ssrf_scan') == 'on',
    }
    
    scan_id = f"scan_{uuid.uuid4().hex[:8]}"
    
    scan_status_store[scan_id] = {
        'status': 'queued',
        'progress': 0,
        'current_step': 'Queued',
        'start_time': time.time()
    }
    
    thread = threading.Thread(
        target=run_scan,
        args=(target, scan_id, options),
        daemon=True
    )
    thread.start()
    
    return jsonify({
        'status': 'scan_started',
        'target': target,
        'scan_id': scan_id
    })

@app.route('/scan/status/<scan_id>')
def scan_status(scan_id):
    """Get scan status"""
    status = scan_status_store.get(scan_id, {'status': 'not_found'})
    return jsonify(status)

@app.route('/scan/results/<scan_id>')
def scan_results(scan_id):
    """Get scan results"""
    try:
        while not results_queue.empty():
            item = results_queue.get_nowait()
            if item.get('scan_id') == scan_id:
                return jsonify(item)
    except queue.Empty:
        pass
    
    status = scan_status_store.get(scan_id)
    if status and status.get('status') == 'completed':
        return jsonify(status.get('results', {}))
    
    return jsonify({'status': 'scanning'})

@app.route('/ai/status')
def ai_status():
    """Check AI status"""
    status = ai_client.get_status()
    return jsonify(status)

@app.route('/ai/chat', methods=['POST'])
def ai_chat():
    """Interactive AI chat"""
    data = request.json
    message = data.get('message')
    scan_id = data.get('scan_id')
    history = data.get('history', [])
    
    if not message:
        return jsonify({'error': 'Message required'}), 400
    
    context = scan_data_store.get(scan_id) if scan_id else None
    response = ai_assistant.chat(message, history, context)
    
    return jsonify({
        'status': 'success',
        'response': response,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/ai/analyze', methods=['POST'])
def ai_analyze():
    """AI analysis endpoint"""
    data = request.json
    scan_id = data.get('scan_id')
    
    if not scan_id:
        return jsonify({'error': 'Scan ID required'}), 400
    
    scan_data = scan_data_store.get(scan_id)
    if not scan_data:
        return jsonify({'error': 'Scan data not found'}), 404
    
    analysis = ai_assistant.analyze_scan_results(scan_data)
    
    return jsonify({
        'status': 'success',
        'analysis': analysis,
        'scan_id': scan_id
    })

@app.route('/remediation/<scan_id>')
def get_remediation(scan_id):
    """Get detailed remediation"""
    scan_data = scan_data_store.get(scan_id)
    if not scan_data:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify(scan_data.get('remediation', {}))

@app.route('/report/generate', methods=['POST'])
def generate_report():
    """Generate report"""
    data = request.json
    scan_id = data.get('scan_id')
    format_type = data.get('format', 'json')
    
    if not scan_id:
        return jsonify({'error': 'Scan ID required'}), 400
    
    scan_data = scan_data_store.get(scan_id)
    if not scan_data:
        return jsonify({'error': 'Scan not found'}), 404
    
    report = report_generator.generate(scan_data, format_type)
    
    return jsonify({
        'status': 'success',
        'report': report,
        'format': format_type
    })

@app.route('/api/providers')
def list_providers():
    """List AI providers"""
    return jsonify({
        'providers': ai_client.list_providers(),
        'current': ai_client.get_status().get('provider')
    })

@app.route('/api/model/set', methods=['POST'])
def set_model():
    """Set AI model"""
    data = request.json
    model = data.get('model')
    
    if model:
        success = ai_client.set_openrouter_model(model)
        if success:
            return jsonify({'status': 'success', 'model': model})
    
    return jsonify({'error': 'Failed to set model'}), 400

@app.route('/api/models')
def list_models():
    """List available models"""
    models = ai_client.get_available_models()
    return jsonify(models)

@app.route('/history')
def history_page():
    """History page"""
    return render_template('history.html')

@app.route('/analytics')
def analytics_page():
    """Analytics page"""
    return render_template('analytics.html')

@app.route('/api/history', methods=['GET'])
def api_history():
    """Get scan history"""
    limit = request.args.get('limit', 50, type=int)
    offset = request.args.get('offset', 0, type=int)
    scans = get_scan_history(limit=limit, offset=offset)
    return jsonify({'status': 'success', 'scans': scans})

@app.route('/api/history/<scan_id>', methods=['GET'])
def api_history_detail(scan_id):
    """Get scan details from history"""
    scan = get_scan_by_id(scan_id)
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    return jsonify({'status': 'success', 'scan': scan})

@app.route('/api/history/<scan_id>', methods=['DELETE'])
def api_history_delete(scan_id):
    """Delete scan from history"""
    delete_scan(scan_id)
    return jsonify({'status': 'success', 'message': 'Scan deleted'})

@app.route('/api/analytics', methods=['GET'])
def api_analytics():
    """Get analytics data"""
    time_range = request.args.get('range', '7d')
    data = get_analytics(time_range=time_range)
    return jsonify({'status': 'success', 'analytics': data})

@app.route('/api/statistics', methods=['GET'])
def api_statistics():
    """Get overall statistics"""
    stats = get_statistics()
    recent = get_recent_activity(limit=10)
    return jsonify({
        'status': 'success',
        'statistics': stats,
        'recent_activity': recent
    })

if __name__ == '__main__':
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    
    init_db()
    print("=" * 60)
    print("   CyberShield Security Scanner v2.0")
    print("=" * 60)
    
    status = ai_client.get_status()
    if status.get('available'):
        print(f"AI Provider: {status.get('provider')}")
        print(f"AI Model: {status.get('model')}")
        print("AI Status: Available")
    else:
        print("AI Status: Offline (Set GROQ_API_KEY or OPENROUTER_API_KEY)")
    
    print("=" * 60)
    print("Server: http://localhost:5000")
    print("=" * 60)
    
    app.run(debug=True, host='0.0.0.0', port=5000)
