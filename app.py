from flask import Flask, session, redirect, request, render_template, jsonify
from auth.google_oauth import get_flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from security.ml_detector import ml_predict
from security.auto_del import move_to_trash
from database.db import init_db
from database.logs import log_email
import base64, os, sqlite3

app = Flask(__name__)
app.secret_key = "smail_secret_key_change_in_production"
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

# Initialize DB
init_db()


# ---------------- Routes ----------------

@app.route("/")
def show_login():
    """Render login page"""
    return render_template("login.html")


@app.route("/start-oauth")
def start_oauth():
    """Start Google OAuth flow"""
    flow = get_flow()
    auth_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(auth_url)


@app.route("/callback")
def callback():
    """Google OAuth callback"""
    flow = get_flow()
    flow.fetch_token(authorization_response=request.url)
    creds = flow.credentials
    session["credentials"] = {
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri": creds.token_uri,
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "scopes": creds.scopes
    }
    return redirect("/main")


@app.route("/main")
def main():
    """Main app interface with sidebar"""
    if "credentials" not in session:
        return redirect("/")
    
    # Get user email
    creds = Credentials(**session["credentials"])
    service = build("gmail", "v1", credentials=creds)
    profile = service.users().getProfile(userId="me").execute()
    session["user_email"] = profile.get("emailAddress", "")
    
    return render_template("main.html", user_email=session.get("user_email", ""))


@app.route("/forgot-password")
def forgot_password():
    return render_template("forgot_password.html")


# ---------------- Helper ----------------

def get_body(payload):
    """Extract plain text from Gmail payload"""
    if "parts" in payload:
        for part in payload["parts"]:
            if part["mimeType"] == "text/plain":
                data = part["body"].get("data", "")
                if data:
                    return base64.urlsafe_b64decode(data).decode()
    elif "body" in payload and "data" in payload["body"]:
        return base64.urlsafe_b64decode(payload["body"]["data"]).decode()
    return ""


# ---------------- Content Routes ----------------

@app.route("/inbox")
def inbox_content():
    """Render inbox partial - ONLY safe emails (limited to 50)"""
    if "credentials" not in session:
        return redirect("/")

    creds = Credentials(**session["credentials"])
    service = build("gmail", "v1", credentials=creds)

    # Fetch latest 50 emails
    results = service.users().messages().list(userId="me", maxResults=50).execute()
    emails = []

    for m in results.get("messages", []):
        msg = service.users().messages().get(userId="me", id=m["id"]).execute()
        headers = msg["payload"]["headers"]
        sender = subject = ""
        for h in headers:
            if h["name"] == "From":
                sender = h["value"]
            if h["name"] == "Subject":
                subject = h["value"]

        body = get_body(msg["payload"])
        if not body:
            body = msg.get("snippet", "")
        
        is_phishing, confidence, reason, explanation = ml_predict(body)

        # Auto delete phishing mails
        if is_phishing:
            move_to_trash(service, m["id"])
            log_email(sender, subject, True, confidence, reason, "Moved to Trash", explanation)
        else:
            # Only add safe emails to inbox
            log_email(sender, subject, False, confidence, reason, "Delivered to Inbox", explanation)
            emails.append({
                "id": m["id"],
                "sender": sender,
                "subject": subject,
                "body": body[:200] + "..." if len(body) > 200 else body,
                "confidence": round(confidence * 100, 2)
            })

    return render_template("inbox.html", emails=emails)


@app.route("/phishing-logs")
def phishing_logs():
    """Render phishing detection logs with XAI explanations (limited to 100)"""
    import json
    from security.ml_detector import get_explanation_html
    
    conn = sqlite3.connect("smail.db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT sender, subject, reason, confidence, action, created_at, explanation 
        FROM email_logs 
        WHERE phishing = 1 
        ORDER BY created_at DESC 
        LIMIT 100
    """)
    data = cursor.fetchall()
    conn.close()
    
    phishing_emails = []
    for row in data:
        explanation_data = {}
        try:
            explanation_data = json.loads(row[6]) if row[6] else {}
        except:
            explanation_data = {}
        
        phishing_emails.append({
            "sender": row[0],
            "subject": row[1],
            "reason": row[2],
            "confidence": round(row[3] * 100, 2),
            "action": row[4],
            "date": row[5],
            "explanation": explanation_data,
            "explanation_html": get_explanation_html(explanation_data)
        })
    
    return render_template("pishing.html", emails=phishing_emails)


@app.route("/trash")
def trash_content():
    """Render trash partial (limited to 50)"""
    if "credentials" not in session:
        return redirect("/")

    creds = Credentials(**session["credentials"])
    service = build("gmail", "v1", credentials=creds)

    # Fetch emails in trash (limited to 50)
    results = service.users().messages().list(userId="me", labelIds=["TRASH"], maxResults=50).execute()
    trash_emails = []

    for m in results.get("messages", []):
        msg = service.users().messages().get(userId="me", id=m["id"]).execute()
        headers = msg["payload"]["headers"]
        sender = subject = ""
        for h in headers:
            if h["name"] == "From":
                sender = h["value"]
            if h["name"] == "Subject":
                subject = h["value"]

        body = msg.get("snippet", "")
        trash_emails.append({
            "id": m["id"],
            "sender": sender,
            "subject": subject,
            "body": body
        })

    return render_template("trash.html", emails=trash_emails)


# ---------------- API Routes ----------------

@app.route("/api/stats")
def get_stats():
    """Get statistics for dashboard - OPTIMIZED for large databases"""
    conn = sqlite3.connect("smail.db")
    cursor = conn.cursor()
    
    # Use COUNT(*) which is optimized and doesn't load actual data
    # Total emails
    cursor.execute("SELECT COUNT(*) FROM email_logs")
    total = cursor.fetchone()[0]
    
    # Phishing detected
    cursor.execute("SELECT COUNT(*) FROM email_logs WHERE phishing = 1")
    phishing = cursor.fetchone()[0]
    
    # Safe emails (calculated, not queried)
    safe = total - phishing
    
    conn.close()
    
    return jsonify({
        "total": total,
        "safe": safe,
        "phishing": phishing
    })


# ---------------- Logout ----------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ---------------- Run App ----------------
if __name__ == "__main__":
    app.run(debug=True, port=5000)