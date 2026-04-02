"""
CyberShield - History & Analytics Module
Stores scan history and provides analytics
"""

import sqlite3
import json
import os
from datetime import datetime, timedelta
from contextlib import contextmanager

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'cybershield.db')

def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@contextmanager
def get_db_cursor():
    """Context manager for database operations"""
    conn = get_db()
    try:
        cursor = conn.cursor()
        yield cursor
        conn.commit()
    finally:
        conn.close()

def init_db():
    """Initialize database tables"""
    with get_db_cursor() as cursor:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT UNIQUE NOT NULL,
                target TEXT NOT NULL,
                scan_options TEXT,
                summary TEXT,
                total_vulns INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                risk_score INTEGER DEFAULT 0,
                risk_level TEXT DEFAULT 'INFO',
                scan_duration REAL DEFAULT 0,
                ai_analysis TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                vuln_type TEXT NOT NULL,
                name TEXT,
                severity TEXT,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS leaks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                leak_type TEXT NOT NULL,
                name TEXT,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                port_number INTEGER NOT NULL,
                service TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            )
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_vulns_scan_id ON vulnerabilities(scan_id)
        ''')

def save_scan(scan_data):
    """Save scan results to database"""
    init_db()
    
    summary = scan_data.get('summary', {})
    severity = summary.get('severity_counts', {})
    
    with get_db_cursor() as cursor:
        cursor.execute('''
            INSERT OR REPLACE INTO scans (
                scan_id, target, scan_options, summary,
                total_vulns, critical_count, high_count, medium_count, low_count,
                risk_score, risk_level, scan_duration, ai_analysis, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            scan_data.get('scan_id'),
            scan_data.get('target'),
            json.dumps(scan_data.get('options', {})),
            json.dumps(summary),
            summary.get('total_vulnerabilities', 0),
            severity.get('critical', 0),
            severity.get('high', 0),
            severity.get('medium', 0),
            severity.get('low', 0),
            summary.get('risk_score', 0),
            summary.get('risk_level', 'INFO'),
            scan_data.get('scan_duration', 0),
            scan_data.get('ai_analysis', ''),
            scan_data.get('timestamp', datetime.now().isoformat())
        ))
        
        scan_id = scan_data.get('scan_id')
        
        for vuln_type, vulns in scan_data.get('vulnerabilities', {}).items():
            if isinstance(vulns, list):
                for vuln in vulns:
                    cursor.execute('''
                        INSERT INTO vulnerabilities (scan_id, vuln_type, name, severity, details)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (
                        scan_id,
                        vuln_type,
                        vuln.get('name', ''),
                        vuln.get('severity', 'medium'),
                        json.dumps(vuln)
                    ))
        
        for leak_type, leaks in scan_data.get('leaks', {}).items():
            if isinstance(leaks, list):
                for leak in leaks:
                    cursor.execute('''
                        INSERT INTO leaks (scan_id, leak_type, name, details)
                        VALUES (?, ?, ?, ?)
                    ''', (
                        scan_id,
                        leak_type,
                        leak.get('file', leak.get('endpoint', '')),
                        json.dumps(leak)
                    ))
        
        for port in scan_data.get('ports', []):
            cursor.execute('''
                INSERT INTO ports (scan_id, port_number, service)
                VALUES (?, ?, ?)
            ''', (scan_id, port, ''))

def get_scan_history(limit=50, offset=0):
    """Get scan history"""
    init_db()
    with get_db_cursor() as cursor:
        cursor.execute('''
            SELECT * FROM scans 
            ORDER BY created_at DESC 
            LIMIT ? OFFSET ?
        ''', (limit, offset))
        rows = cursor.fetchall()
        return [dict(row) for row in rows]

def get_scan_by_id(scan_id):
    """Get specific scan with full details"""
    init_db()
    with get_db_cursor() as cursor:
        cursor.execute('SELECT * FROM scans WHERE scan_id = ?', (scan_id,))
        scan = cursor.fetchone()
        
        if not scan:
            return None
        
        scan = dict(scan)
        
        cursor.execute('SELECT * FROM vulnerabilities WHERE scan_id = ?', (scan_id,))
        scan['vulnerabilities'] = [dict(row) for row in cursor.fetchall()]
        
        cursor.execute('SELECT * FROM leaks WHERE scan_id = ?', (scan_id,))
        scan['leaks'] = [dict(row) for row in cursor.fetchall()]
        
        cursor.execute('SELECT * FROM ports WHERE scan_id = ?', (scan_id,))
        scan['ports_found'] = [dict(row) for row in cursor.fetchall()]
        
        return scan

def delete_scan(scan_id):
    """Delete a scan"""
    init_db()
    with get_db_cursor() as cursor:
        cursor.execute('DELETE FROM vulnerabilities WHERE scan_id = ?', (scan_id,))
        cursor.execute('DELETE FROM leaks WHERE scan_id = ?', (scan_id,))
        cursor.execute('DELETE FROM ports WHERE scan_id = ?', (scan_id,))
        cursor.execute('DELETE FROM scans WHERE scan_id = ?', (scan_id,))

def get_analytics(time_range='7d'):
    """Get analytics data"""
    init_db()
    
    days_map = {'24h': 1, '7d': 7, '30d': 30, '90d': 90}
    days = days_map.get(time_range, 7)
    since_timestamp = (datetime.now() - timedelta(days=days)).timestamp()
    
    with get_db_cursor() as cursor:
        cursor.execute('''
            SELECT COUNT(*) as total_scans,
                   SUM(total_vulns) as total_vulns,
                   SUM(critical_count) as critical,
                   SUM(high_count) as high,
                   SUM(medium_count) as medium,
                   SUM(low_count) as low,
                   AVG(risk_score) as avg_risk_score,
                   AVG(scan_duration) as avg_duration
            FROM scans WHERE created_at >= ?
        ''', (since_timestamp,))
        totals = dict(cursor.fetchone())
        
        cursor.execute('''
            SELECT vuln_type, COUNT(*) as count
            FROM vulnerabilities
            WHERE created_at >= ?
            GROUP BY vuln_type
            ORDER BY count DESC
        ''', (since_timestamp,))
        vuln_by_type = [dict(row) for row in cursor.fetchall()]
        
        cursor.execute('''
            SELECT date(created_at) as date,
                   COUNT(*) as scans,
                   SUM(total_vulns) as vulns
            FROM scans
            WHERE created_at >= ?
            GROUP BY date
            ORDER BY date
        ''', (since_timestamp,))
        timeline = [dict(row) for row in cursor.fetchall()]
        
        cursor.execute('''
            SELECT target, COUNT(*) as count,
                   AVG(risk_score) as avg_risk
            FROM scans
            WHERE created_at >= ?
            GROUP BY target
            ORDER BY count DESC
            LIMIT 10
        ''', (since_timestamp,))
        top_targets = [dict(row) for row in cursor.fetchall()]
        
        cursor.execute('''
            SELECT leak_type, COUNT(*) as count
            FROM leaks
            WHERE created_at >= ?
            GROUP BY leak_type
            ORDER BY count DESC
        ''', (since_timestamp,))
        leak_by_type = [dict(row) for row in cursor.fetchall()]
        
        return {
            'totals': totals,
            'vuln_by_type': vuln_by_type,
            'timeline': timeline,
            'top_targets': top_targets,
            'leak_by_type': leak_by_type,
            'time_range': time_range,
            'days': days
        }

def get_statistics():
    """Get overall statistics"""
    init_db()
    with get_db_cursor() as cursor:
        cursor.execute('''
            SELECT 
                COUNT(*) as total_scans,
                SUM(total_vulns) as total_vulnerabilities,
                SUM(critical_count) as total_critical,
                SUM(high_count) as total_high,
                SUM(medium_count) as total_medium,
                SUM(low_count) as total_low,
                MAX(risk_score) as max_risk_score,
                AVG(risk_score) as avg_risk_score,
                SUM(scan_duration) as total_scan_time
            FROM scans
        ''')
        return dict(cursor.fetchone())

def get_recent_activity(limit=10):
    """Get recent scan activity"""
    init_db()
    with get_db_cursor() as cursor:
        cursor.execute('''
            SELECT scan_id, target, risk_level, risk_score, 
                   total_vulns, created_at
            FROM scans
            ORDER BY created_at DESC
            LIMIT ?
        ''', (limit,))
        return [dict(row) for row in cursor.fetchall()]
