"""
Database initialization and management.
"""
import sqlite3
from config import config
import logging
import os

logger = logging.getLogger(__name__)

DB_PATH = config.DATABASE_PATH


def init_db():
    """Initialize database if it doesn't exist"""
    os.makedirs("database", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS email_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT,
        receiver TEXT,
        subject TEXT,
        body TEXT,
        phishing INTEGER,
        confidence REAL,
        reason TEXT,
        action TEXT,
        explanation TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # ---- Lightweight migration for older DBs (add missing columns) ----
    # Some earlier versions created `email_logs` without `message_id` column.
    cursor.execute("PRAGMA table_info(email_logs)")
    existing_cols = {row[1] for row in cursor.fetchall()}

    # Only add message_id if it doesn't exist (other columns are in CREATE TABLE)
    if "message_id" not in existing_cols:
        try:
            cursor.execute("ALTER TABLE email_logs ADD COLUMN message_id TEXT")
        except Exception as e:
            # Don't hard fail on migration; app should still run
            logger.warning(f"DB migration warning: could not add column message_id: {e}")

    conn.commit()
    conn.close()
    # Use plain ASCII to avoid encoding issues on Windows terminals
    logger.info("Database initialized")


def cleanup_old_logs(keep_last_n=500):
    """Keep only the most recent N email logs to optimize DB size"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM email_logs")
    current_count = cursor.fetchone()[0]

    if current_count <= keep_last_n:
        conn.close()
        print(f"No cleanup needed. Database has {current_count} logs")
        return

    cursor.execute("""
        DELETE FROM email_logs
        WHERE id NOT IN (
            SELECT id FROM email_logs
            ORDER BY created_at DESC
            LIMIT ?
        )
    """, (keep_last_n,))

    deleted = cursor.rowcount
    conn.commit()
    cursor.execute("VACUUM")
    conn.close()
    print(f"✓ Deleted {deleted} old logs, kept {keep_last_n} most recent")


def get_db_stats():
    """Display database statistics"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM email_logs")
    total = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM email_logs WHERE phishing = 1")
    phishing = cursor.fetchone()[0]

    safe = total - phishing

    cursor.execute("SELECT MIN(created_at) FROM email_logs")
    oldest = cursor.fetchone()[0]

    cursor.execute("SELECT MAX(created_at) FROM email_logs")
    newest = cursor.fetchone()[0]

    conn.close()

    print("\n" + "="*50)
    print("DATABASE STATISTICS")
    print("="*50)
    print(f"Total Emails:     {total}")
    print(f"Safe Emails:      {safe}")
    print(f"Phishing Blocked: {phishing}")
    print(f"Oldest Log:       {oldest}")
    print(f"Newest Log:       {newest}")
    print("="*50 + "\n")


def reset_scan_data():
    """Clear all email logs from the database"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM email_logs")
    conn.commit()
    cursor.execute("VACUUM")
    conn.close()
    logger.info("All scan data has been reset")
    return True
