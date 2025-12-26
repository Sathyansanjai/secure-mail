import sqlite3

import sqlite3

DB_NAME = "smail.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS email_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT,
        subject TEXT,
        body TEXT,
        phishing INTEGER,
        reason TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()
    print("✓ Database initialized")


def cleanup_old_logs(keep_last_n=500):
    """
    Keep only the most recent N email logs.
    This helps prevent the database from growing too large.
    
    Args:
        keep_last_n: Number of most recent logs to keep (default: 500)
    """
    conn = sqlite3.connect("smail.db")
    cursor = conn.cursor()
    
    # Count current logs
    cursor.execute("SELECT COUNT(*) FROM email_logs")
    current_count = cursor.fetchone()[0]
    print(f"Current email logs: {current_count}")
    
    if current_count <= keep_last_n:
        print(f"No cleanup needed. Database has {current_count} logs (keeping {keep_last_n})")
        conn.close()
        return
    
    # Delete old logs, keeping only the most recent N
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
    
    # Vacuum to reclaim disk space
    cursor.execute("VACUUM")
    
    conn.close()
    
    print(f"✓ Deleted {deleted} old logs")
    print(f"✓ Kept the {keep_last_n} most recent logs")
    print(f"✓ Database optimized")


def get_db_stats():
    """Display database statistics"""
    conn = sqlite3.connect("smail.db")
    cursor = conn.cursor()
    
    # Total logs
    cursor.execute("SELECT COUNT(*) FROM email_logs")
    total = cursor.fetchone()[0]
    
    # Phishing count
    cursor.execute("SELECT COUNT(*) FROM email_logs WHERE phishing = 1")
    phishing = cursor.fetchone()[0]
    
    # Safe count
    safe = total - phishing
    
    # Oldest log
    cursor.execute("SELECT MIN(created_at) FROM email_logs")
    oldest = cursor.fetchone()[0]
    
    # Newest log
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


if __name__ == "__main__":
    # Display current stats
    get_db_stats()
    
    # Ask user for confirmation
    print("This script will keep only the 500 most recent email logs.")
    print("All older logs will be permanently deleted.")
    response = input("\nContinue? (yes/no): ").strip().lower()
    
    if response == "yes":
        cleanup_old_logs(keep_last_n=500)
        print("\nUpdated statistics:")
        get_db_stats()
    else:
        print("Cleanup cancelled.")