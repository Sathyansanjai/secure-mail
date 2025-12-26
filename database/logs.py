import sqlite3
import json

def log_email(sender, subject, phishing, confidence, reason="", action="", explanation=None):
    """Log email detection results to database with XAI explanation"""
    conn = sqlite3.connect("smail.db")
    c = conn.cursor()
    
    # Set action based on phishing status
    if action == "":
        action = "Moved to Trash" if phishing else "Delivered to Inbox"
    
    # Convert explanation dict to JSON string
    explanation_json = json.dumps(explanation) if explanation else "{}"
    
    c.execute("""
    INSERT INTO email_logs
    (sender, subject, phishing, reason, confidence, action, explanation)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (sender, subject, int(phishing), reason, confidence, action, explanation_json))
    conn.commit()
    conn.close()
