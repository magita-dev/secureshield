import re
from urllib.parse import urlparse

class PhishingDetector:
    def __init__(self):
        # Common phishing keywords
        self.phishing_keywords = [
            'verify', 'account', 'suspended', 'urgent', 'click here',
            'confirm', 'password', 'security', 'update', 'expire',
            'bank', 'credit card', 'ssn', 'social security', 'prize',
            'winner', 'congratulations', 'claim', 'refund', 'tax'
        ]
        
        # Suspicious URL patterns
        self.suspicious_patterns = [
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP address
            r'[a-z0-9]{20,}',  # Long random strings
            r'\.tk$|\.ml$|\.ga$|\.cf$',  # Free domains
        ]
    
    def analyze(self, message, url):
        """Analyze message and URL for phishing"""
        score = 0
        reasons = []
        
        # Check message content
        if message:
            message_lower = message.lower()
            keyword_count = sum(1 for keyword in self.phishing_keywords if keyword in message_lower)
            if keyword_count >= 3:
                score += 40
                reasons.append(f"Contains {keyword_count} phishing keywords")
            elif keyword_count >= 2:
                score += 25
                reasons.append(f"Contains {keyword_count} phishing keywords")
        
        # Check URL
        if url:
            # Check for IP address
            if re.search(self.suspicious_patterns[0], url):
                score += 30
                reasons.append("URL contains IP address")
            
            # Check for suspicious TLD
            if re.search(self.suspicious_patterns[2], url):
                score += 25
                reasons.append("Suspicious domain extension")
            
            # Check for HTTPS
            if url.startswith('http://'):
                score += 15
                reasons.append("Not using HTTPS")
            
            # Check for long random strings
            if re.search(self.suspicious_patterns[1], url):
                score += 20
                reasons.append("Contains long random string")
        
        is_phishing = score >= 50
        
        return {
            'is_phishing': is_phishing,
            'confidence': min(score, 100),
            'reasons': reasons,
            'severity': 'high' if score >= 70 else 'medium' if score >= 50 else 'low'
        }
