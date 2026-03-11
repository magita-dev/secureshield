import re

class SocialMediaSafety:
    def __init__(self):
        # Dangerous keywords
        self.danger_keywords = [
            'hack', 'crack', 'steal', 'phishing', 'scam',
            'free money', 'click here', 'download now',
            'personal information', 'credit card', 'password'
        ]
        
        # Suspicious URL patterns
        self.suspicious_urls = [
            r'bit\.ly', r'tinyurl', r'goo\.gl',  # URL shorteners
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP addresses
        ]
    
    def analyze(self, content, url=''):
        """Analyze social media content for safety"""
        score = 0
        reasons = []
        alerts = []
        
        if content:
            content_lower = content.lower()
            
            # Check for dangerous keywords
            keyword_count = sum(1 for keyword in self.danger_keywords if keyword in content_lower)
            if keyword_count >= 2:
                score += 50
                reasons.append(f"Contains {keyword_count} dangerous keywords")
                alerts.append("Potential scam or phishing content")
            
            # Check for excessive caps
            if content.isupper() and len(content) > 20:
                score += 20
                reasons.append("Excessive use of capital letters")
            
            # Check for multiple exclamation marks
            if content.count('!') >= 3:
                score += 15
                reasons.append("Excessive exclamation marks")
        
        if url:
            # Check for URL shorteners
            for pattern in self.suspicious_urls:
                if re.search(pattern, url):
                    score += 30
                    reasons.append("Contains suspicious URL")
                    alerts.append("Suspicious link detected")
                    break
        
        # Determine risk level
        if score >= 60:
            risk_level = 'high'
        elif score >= 30:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        return {
            'risk_level': risk_level,
            'score': min(score, 100),
            'reasons': reasons,
            'alerts': alerts,
            'recommendation': 'Block' if risk_level == 'high' else 'Review' if risk_level == 'medium' else 'Safe'
        }
