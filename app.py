from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import json
from datetime import datetime
import os

# Import detection modules
from modules.phishing_detector import PhishingDetector
from modules.spam_call_detector import SpamCallDetector
from modules.ransomware_detector import RansomwareDetector
from modules.social_media_safety import SocialMediaSafety
from modules.database import Database

app = Flask(__name__)
CORS(app)

# Initialize database
db = Database()

# Initialize detection modules
phishing_detector = PhishingDetector()
spam_detector = SpamCallDetector()
ransomware_detector = RansomwareDetector()
social_media_safety = SocialMediaSafety()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/dashboard/stats', methods=['GET'])
def get_dashboard_stats():
    """Get dashboard statistics"""
    stats = db.get_dashboard_stats()
    return jsonify(stats)

@app.route('/api/phishing/scan', methods=['POST'])
def scan_phishing():
    """Scan for phishing attempts"""
    data = request.json
    message = data.get('message', '')
    url = data.get('url', '')
    
    result = phishing_detector.analyze(message, url)
    
    # Save to database
    if result['is_phishing']:
        db.save_phishing_attempt(url, message, result)
    
    return jsonify(result)

@app.route('/api/calls/check', methods=['POST'])
def check_spam_call():
    """Check if a phone number is spam"""
    data = request.json
    phone_number = data.get('phone_number', '')
    
    result = spam_detector.check_number(phone_number)
    
    # Save to database
    if result['is_spam']:
        db.save_spam_call(phone_number, result)
    
    return jsonify(result)

@app.route('/api/ransomware/monitor', methods=['POST'])
def monitor_ransomware():
    """Monitor for ransomware activity"""
    data = request.json
    file_path = data.get('file_path', '')
    
    result = ransomware_detector.check_file(file_path)
    
    # Save to database
    if result['is_threat']:
        db.save_ransomware_event(file_path, result)
    
    return jsonify(result)

@app.route('/api/social/analyze', methods=['POST'])
def analyze_social_media():
    """Analyze social media safety"""
    data = request.json
    content = data.get('content', '')
    url = data.get('url', '')
    
    result = social_media_safety.analyze(content, url)
    
    # Save to database
    if result['risk_level'] != 'low':
        db.save_social_media_alert(result)
    
    return jsonify(result)

@app.route('/api/threats/recent', methods=['GET'])
def get_recent_threats():
    """Get recent threats"""
    threats = db.get_recent_threats(limit=10)
    return jsonify(threats)

@app.route('/api/honeypot/status', methods=['GET'])
def honeypot_status():
    """Get honeypot status"""
    status = {
        'active': True,
        'decoy_files': 15,
        'fake_endpoints': 8,
        'captured_attempts': db.get_total_threats()
    }
    return jsonify(status)

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    print("🚀 SecureShield System Starting...")
    print(f"📊 Dashboard: http://localhost:{port}")
    app.run(debug=False, host='0.0.0.0', port=port)
