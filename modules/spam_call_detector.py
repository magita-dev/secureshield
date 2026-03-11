import re

class SpamCallDetector:
    def __init__(self):
        # Known spam number patterns
        self.spam_patterns = [
            r'^1-800-',  # Toll-free
            r'^\+1-800-',
            r'^000',  # Invalid prefix
            r'^111',
        ]
        
        # Blacklist of known spam numbers
        self.blacklist = set([
            '1-800-SPAM-123',
            '000-000-0000',
            '111-111-1111',
        ])
    
    def check_number(self, phone_number):
        """Check if phone number is spam"""
        score = 0
        reasons = []
        
        # Check blacklist
        if phone_number in self.blacklist:
            score += 80
            reasons.append("Number in spam blacklist")
        
        # Check patterns
        for pattern in self.spam_patterns:
            if re.match(pattern, phone_number):
                score += 40
                reasons.append(f"Matches spam pattern")
                break
        
        # Check for repeated digits
        if re.search(r'(\d)\1{4,}', phone_number):
            score += 30
            reasons.append("Contains repeated digits")
        
        is_spam = score >= 50
        
        return {
            'is_spam': is_spam,
            'confidence': min(score, 100),
            'reasons': reasons,
            'recommendation': 'Block' if is_spam else 'Allow'
        }
