import sqlite3
from datetime import datetime
import json

class Database:
    def __init__(self, db_name='secureshield.db'):
        self.db_name = db_name
        self.init_database()
    
    def get_connection(self):
        return sqlite3.connect(self.db_name)
    
    def init_database(self):
        """Initialize database tables"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Threats table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                threat_type TEXT,
                source TEXT,
                detected_at TIMESTAMP,
                severity TEXT,
                details TEXT,
                status TEXT
            )
        ''')
        
        # Phishing attempts
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS phishing_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                message_content TEXT,
                sender TEXT,
                detected_at TIMESTAMP,
                is_malicious BOOLEAN
            )
        ''')
        
        # Spam calls
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS spam_calls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phone_number TEXT,
                call_time TIMESTAMP,
                duration INTEGER,
                is_spam BOOLEAN,
                reported_by TEXT
            )
        ''')
        
        # Ransomware events
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ransomware_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT,
                process_name TEXT,
                action TEXT,
                detected_at TIMESTAMP,
                blocked BOOLEAN
            )
        ''')
        
        # Social media alerts
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS social_media_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                platform TEXT,
                alert_type TEXT,
                details TEXT,
                detected_at TIMESTAMP,
                risk_level TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def save_phishing_attempt(self, url, message, result):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO phishing_attempts (url, message_content, sender, detected_at, is_malicious)
            VALUES (?, ?, ?, ?, ?)
        ''', (url, message, 'unknown', datetime.now(), result['is_phishing']))
        conn.commit()
        conn.close()
    
    def save_spam_call(self, phone_number, result):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO spam_calls (phone_number, call_time, duration, is_spam, reported_by)
            VALUES (?, ?, ?, ?, ?)
        ''', (phone_number, datetime.now(), 0, result['is_spam'], 'system'))
        conn.commit()
        conn.close()
    
    def save_ransomware_event(self, file_path, result):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO ransomware_events (file_path, process_name, action, detected_at, blocked)
            VALUES (?, ?, ?, ?, ?)
        ''', (file_path, result.get('process', 'unknown'), 'detected', datetime.now(), True))
        conn.commit()
        conn.close()
    
    def save_social_media_alert(self, result):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO social_media_alerts (platform, alert_type, details, detected_at, risk_level)
            VALUES (?, ?, ?, ?, ?)
        ''', ('generic', result.get('alert_type', 'unknown'), json.dumps(result), datetime.now(), result['risk_level']))
        conn.commit()
        conn.close()
    
    def get_dashboard_stats(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM phishing_attempts WHERE is_malicious = 1')
        phishing_count = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM spam_calls WHERE is_spam = 1')
        spam_count = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM ransomware_events')
        ransomware_count = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM social_media_alerts')
        social_count = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'phishing_detected': phishing_count,
            'spam_calls_blocked': spam_count,
            'ransomware_attempts': ransomware_count,
            'social_media_alerts': social_count,
            'total_threats': phishing_count + spam_count + ransomware_count + social_count
        }
    
    def get_recent_threats(self, limit=10):
        conn = self.get_connection()
        cursor = conn.cursor()
        
        threats = []
        
        # Get recent phishing
        cursor.execute('SELECT url, detected_at FROM phishing_attempts WHERE is_malicious = 1 ORDER BY detected_at DESC LIMIT ?', (limit,))
        for row in cursor.fetchall():
            threats.append({
                'type': 'Phishing',
                'source': row[0],
                'time': row[1]
            })
        
        conn.close()
        return threats[:limit]
    
    def get_total_threats(self):
        stats = self.get_dashboard_stats()
        return stats['total_threats']
