# SecureShield - Honeypot Defense System

## Quick Start (3 Minutes)

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the Application
```bash
python app.py
```

### 3. Open Browser
Navigate to: `http://localhost:5000`

## Features

✅ **Banking Phishing Detector** - Scans messages and URLs for phishing attempts
✅ **Spam Call Detector** - Identifies spam phone numbers
✅ **Ransomware Detector** - Monitors files and detects ransomware activity
✅ **Social Media Safety** - Analyzes social media content for threats
✅ **Honeypot System** - Decoy files and endpoints to trap attackers

## Testing the System

### Test Phishing Detector:
- **Message**: "URGENT! Your bank account has been suspended. Click here to verify your password immediately!"
- **URL**: "http://192.168.1.1/bank-login"
- **Expected**: HIGH RISK - Phishing Detected

### Test Spam Call Detector:
- **Phone**: "1-800-SPAM-123"
- **Expected**: SPAM DETECTED

### Test Ransomware Detector:
- **File Path**: "honeypot_files/important_doc.txt"
- **Expected**: Monitoring (Safe if not modified)

### Test Social Media Safety:
- **Content**: "FREE MONEY! Click here now! Enter your credit card details!"
- **Expected**: HIGH RISK

## Project Structure
```
secureshield/
├── app.py                      # Main Flask application
├── requirements.txt            # Dependencies
├── modules/
│   ├── database.py            # Database operations
│   ├── phishing_detector.py   # Phishing detection
│   ├── spam_call_detector.py  # Spam call detection
│   ├── ransomware_detector.py # Ransomware detection
│   └── social_media_safety.py # Social media analysis
├── templates/
│   └── index.html             # Web dashboard
└── honeypot_files/            # Decoy files (auto-created)
```

## Technologies Used
- **Backend**: Flask (Python)
- **Frontend**: HTML, CSS, JavaScript
- **Database**: SQLite
- **ML/NLP**: Pattern matching and rule-based detection

## Capstone Presentation Tips

1. **Start with Live Demo**: Show each module detecting threats
2. **Explain Honeypot**: Show the decoy files that trap attackers
3. **Show Dashboard**: Display real-time statistics
4. **Discuss Architecture**: Explain multi-layer defense approach
5. **Future Enhancements**: Mention ML integration, API expansion

## Budget: $0
All components are completely free and open-source.
