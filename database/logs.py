"""
Email logging functions with improved error handling.
"""
import json
from utils.database import get_db_connection
import logging

logger = logging.getLogger(__name__)


def log_email(sender, subject, phishing, confidence, reason="", action="", explanation=None, receiver=None, body=None, message_id=None):
    """
    Log email detection results to database with optional XAI explanation.
    Uses connection pooling for better performance.
    """
    if not action:
        action = "Moved to Trash" if phishing else "Delivered to Inbox"

    explanation_json = json.dumps(explanation) if explanation else "{}"

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Try with message_id first (newer schema)
            try:
                cursor.execute("""
                    INSERT INTO email_logs
                    (message_id, sender, receiver, subject, body, phishing, confidence, reason, action, explanation)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    message_id,
                    sender,
                    receiver,
                    subject,
                    body,
                    int(phishing),
                    confidence,
                    reason,
                    action,
                    explanation_json
                ))
            except Exception:
                # Fallback for older DBs without message_id column
                cursor.execute("""
                    INSERT INTO email_logs
                    (sender, receiver, subject, body, phishing, confidence, reason, action, explanation)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    sender,
                    receiver,
                    subject,
                    body,
                    int(phishing),
                    confidence,
                    reason,
                    action,
                    explanation_json
                ))
            
            conn.commit()
    except Exception as e:
        logger.error(f"Error logging email: {e}")
        # Don't raise - logging failures shouldn't break the app


def save_sent_mail(sender, to, subject, body):
    """
    Save emails sent by user to DB.
    Uses connection pooling for better performance.
    """
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO email_logs
                (sender, receiver, subject, body, phishing, confidence, reason, action)
                VALUES (?, ?, ?, ?, 0, 0, 'User Sent', 'Sent')
            """, (sender, to, subject, body))
            conn.commit()
    except Exception as e:
        logger.error(f"Error saving sent mail: {e}")
        # Don't raise - logging failures shouldn't break the app
