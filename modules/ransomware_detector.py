import os
import hashlib

class RansomwareDetector:
    def __init__(self):
        # Suspicious file extensions
        self.ransomware_extensions = [
            '.encrypted', '.locked', '.crypto', '.crypt',
            '.locky', '.cerber', '.zepto', '.thor'
        ]
        
        # Honeypot files (decoy files)
        self.honeypot_files = set()
        self.create_honeypot_files()
    
    def create_honeypot_files(self):
        """Create decoy files to detect ransomware"""
        honeypot_dir = 'honeypot_files'
        if not os.path.exists(honeypot_dir):
            os.makedirs(honeypot_dir)
        
        # Create some decoy files
        decoy_files = ['important_doc.txt', 'passwords.txt', 'financial_data.xlsx']
        for filename in decoy_files:
            filepath = os.path.join(honeypot_dir, filename)
            if not os.path.exists(filepath):
                with open(filepath, 'w') as f:
                    f.write('HONEYPOT FILE - DO NOT MODIFY')
            self.honeypot_files.add(filepath)
    
    def check_file(self, file_path):
        """Check if file shows signs of ransomware"""
        score = 0
        reasons = []
        
        # Check if it's a honeypot file
        if file_path in self.honeypot_files:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    content = f.read()
                    if 'HONEYPOT FILE - DO NOT MODIFY' not in content:
                        score += 90
                        reasons.append("Honeypot file was modified!")
        
        # Check file extension
        for ext in self.ransomware_extensions:
            if file_path.endswith(ext):
                score += 70
                reasons.append(f"Suspicious extension: {ext}")
                break
        
        # Check if file exists
        if not os.path.exists(file_path):
            score += 20
            reasons.append("File does not exist")
        
        is_threat = score >= 60
        
        return {
            'is_threat': is_threat,
            'confidence': min(score, 100),
            'reasons': reasons,
            'action': 'Quarantine' if is_threat else 'Monitor'
        }
