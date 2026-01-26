"""
Smail - Secure Mail Application
Main Flask application with improved error handling and scalability.
"""
from flask import Flask, session, redirect, request, render_template, jsonify
from auth.google_oauth import get_flow
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials
from security.ml_detector import ml_predict
from security.auto_del import move_to_trash, restore_from_trash, delete_permanently
from database.db import init_db, DB_PATH
from database.logs import log_email
from middleware.auth import require_auth, get_gmail_service
from middleware.errors import register_error_handlers, handle_error
from utils.database import get_db_connection, execute_query
from config import config
from werkzeug.security import check_password_hash, generate_password_hash
import base64
from email.message import EmailMessage
import sqlite3
import threading
import time
import logging
from concurrent.futures import ThreadPoolExecutor

# Configure logging
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.config['PERMANENT_SESSION_LIFETIME'] = config.PERMANENT_SESSION_LIFETIME
app.config['SESSION_COOKIE_SECURE'] = config.SESSION_COOKIE_SECURE
app.config['SESSION_COOKIE_HTTPONLY'] = config.SESSION_COOKIE_HTTPONLY
app.config['SESSION_COOKIE_SAMESITE'] = config.SESSION_COOKIE_SAMESITE

# Register error handlers
register_error_handlers(app)

# Initialize DB
init_db()
logger.info("Application initialized")


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


@app.route("/login", methods=["POST"])
def login_local():
    """
    Local email/password login (for demo/admin). On success, continue to Google OAuth to get Gmail access.
    """
    data = request.get_json() if request.is_json else request.form
    email = (data.get("email") or "").strip()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    configured_email, pwd_hash = _get_local_login_creds()
    if email.lower() != configured_email.lower() or not check_password_hash(pwd_hash, password):
        return jsonify({"error": "Invalid credentials"}), 401

    session["local_user"] = email
    # Proceed to Google OAuth to obtain Gmail access tokens
    return jsonify({"message": "Login ok", "redirect": "/start-oauth"})


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
        "scopes": creds.scopes,
        "expiry": creds.expiry.isoformat() if creds.expiry else None
    }
    return redirect("/main")


@app.route("/main")
@require_auth
def main():
    """Main app interface with sidebar"""
    try:
        service = get_gmail_service()
        if not service:
            return redirect("/")
        
        # Get user email
        if "user_email" not in session:
            profile = service.users().getProfile(userId="me").execute()
            session["user_email"] = profile.get("emailAddress", "")
        
        return render_template("main.html", user_email=session.get("user_email", ""))
    except Exception as e:
        logger.error(f"Error in main route: {e}")
        return handle_error(e, 500, is_api=False)


@app.route("/forgot-password")
def forgot_password():
    return render_template("forgot_password.html")


# ---------------- Helper Functions ----------------

def _get_local_login_creds():
    """
    Local (email/password) login credentials.
    For production, set LOCAL_LOGIN_EMAIL and LOCAL_LOGIN_PASSWORD (plaintext) or LOCAL_LOGIN_PASSWORD_HASH.
    Defaults are for demo only.
    """
    email = config.LOCAL_LOGIN_EMAIL
    pwd_plain = config.LOCAL_LOGIN_PASSWORD
    pwd_hash_env = config.LOCAL_LOGIN_PASSWORD_HASH

    if pwd_hash_env:
        pwd_hash = pwd_hash_env
    else:
        # Fall back to plain password (demo). Hash it on the fly.
        if not pwd_plain:
            pwd_plain = "admin123"
        pwd_hash = generate_password_hash(pwd_plain)
    return email, pwd_hash

def save_sent_mail(sender, subject, body, to=None):
    """Save sent mail to database"""
    try:
        log_email(
            sender=sender,
            subject=subject,
            phishing=False,
            confidence=1.0,
            reason="User Sent",
            action="Sent",
            explanation={},
            receiver=to,
            body=body,
            message_id=None,
        )
    except Exception as e:
        print(f"Error saving sent mail: {e}")

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
@app.route("/compose")
@require_auth
def compose():
    """Compose email page"""
    try:
        return render_template("compose.html")
    except Exception as e:
        logger.error(f"Compose template error: {e}")
        return handle_error(e, 500, is_api=False, retry_url="/compose")


@app.route("/all-mail")
@require_auth
def all_mail():
    """Render All Mail partial (fast, paginated)."""
    try:
        service = get_gmail_service()
        if not service:
            return handle_error("Gmail service unavailable", 500, is_api=False, retry_url="/all-mail")

        results = service.users().messages().list(userId="me", maxResults=25).execute()
        message_ids = [m["id"] for m in results.get("messages", [])]
        next_token = results.get("nextPageToken")

        emails = []
        for msg_id in message_ids:
            try:
                msg = service.users().messages().get(
                    userId="me",
                    id=msg_id,
                    format="metadata",
                    metadataHeaders=["From", "Subject"]
                ).execute()
                headers = msg["payload"]["headers"]
                sender = subject = ""
                for h in headers:
                    if h["name"] == "From":
                        sender = h["value"]
                    if h["name"] == "Subject":
                        subject = h["value"]
                body = (msg.get("snippet", "") or "")[:200]
                
                # Check labels for star and flag status
                labels = msg.get("labelIds", [])
                is_starred = "STARRED" in labels
                is_flagged = "IMPORTANT" in labels
                
                emails.append({
                    "id": msg_id,
                    "sender": sender,
                    "subject": subject,
                    "body": body,
                    "starred": is_starred,
                    "flagged": is_flagged
                })
            except Exception as e:
                logger.error(f"All-mail get error {msg_id}: {e}")
                continue

        return render_template("all_mail.html", emails=emails, next_page_token=next_token)
    except Exception as e:
        logger.error(f"Error in all_mail: {e}")
        return handle_error(e, 500, is_api=False, retry_url="/all-mail")


@app.route("/api/all-mail")
@require_auth
def api_all_mail():
    """Return JSON for All Mail pagination."""
    try:
        service = get_gmail_service()
        if not service:
            return jsonify({"error": "Gmail service unavailable"}), 500

        page_token = request.args.get("pageToken")
        results = service.users().messages().list(
            userId="me",
            maxResults=25,
            pageToken=page_token
        ).execute()

        message_ids = [m["id"] for m in results.get("messages", [])]
        next_token = results.get("nextPageToken")

        emails = []
        for msg_id in message_ids:
            try:
                msg = service.users().messages().get(
                    userId="me",
                    id=msg_id,
                    format="metadata",
                    metadataHeaders=["From", "Subject"]
                ).execute()
                headers = msg["payload"]["headers"]
                sender = subject = ""
                for h in headers:
                    if h["name"] == "From":
                        sender = h["value"]
                    if h["name"] == "Subject":
                        subject = h["value"]
                body = (msg.get("snippet", "") or "")[:200]
                
                # Check labels for star and flag status
                labels = msg.get("labelIds", [])
                is_starred = "STARRED" in labels
                is_flagged = "IMPORTANT" in labels
                
                emails.append({
                    "id": msg_id,
                    "sender": sender,
                    "subject": subject,
                    "body": body,
                    "starred": is_starred,
                    "flagged": is_flagged
                })
            except Exception as e:
                logger.error(f"All-mail api get error {msg_id}: {e}")
                continue

        return jsonify({"emails": emails, "nextPageToken": next_token})
    except Exception as e:
        logger.error(f"Error in api_all_mail: {e}")
        return jsonify({"error": str(e), "emails": [], "nextPageToken": None}), 500


@app.route("/send-mail", methods=["POST"])
@require_auth
def send_mail():
    """Send email via Gmail API"""
    try:
        service = get_gmail_service()
        if not service:
            return jsonify({"error": "Gmail service unavailable"}), 500

        # Support both form data and JSON
        if request.is_json:
            data = request.get_json()
            to = data.get("to")
            subject = data.get("subject")
            body = data.get("body")
        else:
            to = request.form.get("to")
            subject = request.form.get("subject")
            body = request.form.get("body")

        if not to or not subject or not body:
            return jsonify({"error": "All fields (to, subject, body) are required"}), 400

        # Validate email format
        if "@" not in to:
            return jsonify({"error": "Invalid email address"}), 400

        try:
            # Get user email from session or Gmail profile
            user_email = session.get("user_email")
            if not user_email:
                profile = service.users().getProfile(userId="me").execute()
                user_email = profile.get("emailAddress", "")
                session["user_email"] = user_email

            # Create email
            message = EmailMessage()
            message["To"] = to
            message["From"] = user_email
            message["Subject"] = subject
            message.set_content(body)

            # Encode email for Gmail API
            encoded_message = base64.urlsafe_b64encode(
                message.as_bytes()
            ).decode()

            # Send mail
            result = service.users().messages().send(
                userId="me",
                body={"raw": encoded_message}
            ).execute()

            # Save sent mail to DB
            from database.logs import save_sent_mail
            save_sent_mail(user_email, to, subject, body)

            return jsonify({
                "message": "Mail sent successfully",
                "message_id": result.get("id", "")
            })
        except HttpError as e:
            error_msg = f"Gmail API error: {str(e)}"
            logger.error(error_msg)
            return jsonify({"error": error_msg}), 500
        except Exception as e:
            error_msg = f"Failed to send mail: {str(e)}"
            logger.error(error_msg)
            return jsonify({"error": error_msg}), 500
    except Exception as e:
        logger.error(f"Error in send_mail: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/inbox")
@require_auth
def inbox_content():
    """Render inbox partial - safe only (fast). ML scan runs in background via /scan-emails."""
    try:
        service = get_gmail_service()
        if not service:
            return handle_error("Gmail service unavailable", 500, is_api=False, retry_url="/inbox")

        try:
            # Fetch latest INBOX emails (fast metadata only) - optimized with batch requests
            results = service.users().messages().list(
                userId="me",
                labelIds=["INBOX"],
                maxResults=config.EMAIL_BATCH_SIZE
            ).execute()
            emails = []
            
            message_ids = [m["id"] for m in results.get("messages", [])]
            
            if not message_ids:
                return render_template("inbox.html", emails=[])
        except HttpError as e:
            error_msg = f"Gmail API error: {str(e)}"
            logger.error(error_msg)
            return handle_error(error_msg, 500, is_api=False, retry_url="/inbox")
        except Exception as e:
            error_msg = f"Error fetching emails: {str(e)}"
            logger.error(error_msg)
            return handle_error(error_msg, 500, is_api=False, retry_url="/inbox")

        # Pull latest scan results for these messages from DB (one query) - optimized
        scan_map = {}
        try:
            if message_ids:
                placeholders = ",".join(["?"] * len(message_ids))
                results = execute_query(
                    f"""
                    SELECT message_id, phishing, confidence
                    FROM email_logs
                    WHERE message_id IN ({placeholders})
                    ORDER BY created_at DESC
                    """,
                    params=tuple(message_ids),
                    fetch_all=True
                )
                for row in results:
                    mid, phishing, conf = row[0], row[1], row[2]
                    # keep latest only
                    if mid and mid not in scan_map:
                        scan_map[mid] = {"phishing": int(phishing), "confidence": float(conf or 0.0)}
        except Exception as e:
            logger.error(f"Inbox scan map error: {e}")
        
        # Batch process emails more efficiently - limit concurrent requests
        def fetch_email_metadata(msg_id):
            try:
                msg = service.users().messages().get(
                    userId="me", 
                    id=msg_id, 
                    format='metadata', 
                    metadataHeaders=['From', 'Subject']
                ).execute()
                
                headers = msg["payload"]["headers"]
                sender = subject = ""
                for h in headers:
                    if h["name"] == "From":
                        sender = h["value"]
                    if h["name"] == "Subject":
                        subject = h["value"]

                body = msg.get("snippet", "")[:200]

                # If we already scanned it and it is phishing, hide it from Inbox
                if msg_id in scan_map and scan_map[msg_id].get("phishing") == 1:
                    return None

                confidence_pct = None
                if msg_id in scan_map and scan_map[msg_id].get("phishing") == 0:
                    confidence_pct = round(scan_map[msg_id].get("confidence", 0.0) * 100, 2)

                return {
                    "id": msg_id,
                    "sender": sender,
                    "subject": subject,
                    "body": body + "..." if len(body) >= 200 else body,
                    "confidence": confidence_pct,
                    "scanned": msg_id in scan_map,
                }
            except Exception as e:
                logger.error(f"Error processing email {msg_id}: {e}")
                return None
        
        try:
            # Use ThreadPoolExecutor for parallel fetching (max 5 concurrent)
            with ThreadPoolExecutor(max_workers=config.MAX_CONCURRENT_REQUESTS) as executor:
                results_list = list(executor.map(fetch_email_metadata, message_ids[:config.EMAIL_BATCH_SIZE]))
                emails = [email for email in results_list if email is not None]

            return render_template("inbox.html", emails=emails)
        except Exception as e:
            error_msg = f"Error processing emails: {str(e)}"
            logger.error(error_msg)
            return handle_error(error_msg, 500, is_api=False, retry_url="/inbox")
    except Exception as e:
        logger.error(f"Error in inbox_content: {e}")
        return handle_error(e, 500, is_api=False, retry_url="/inbox")


def _scan_latest_emails_background(max_results=30):
    """Background scan: run ML on latest emails and move phishing to trash + log with explanation."""
    # Avoid crashing if session expires; background scan is best-effort.
    try:
        # We can't use Flask session safely across threads without copying data.
        # So this function will be invoked with copied credentials.
        pass
    except Exception as e:
        print(f"Background scan init error: {e}")


@app.route("/scan-emails")
@require_auth
def scan_emails():
    """Trigger phishing scan in background to keep UI fast."""
    try:
        # Allow scanning more emails without blocking UI
    try:
        max_total = int(request.args.get("max", "200"))
    except Exception:
        max_total = 200
    try:
        page_size = int(request.args.get("pageSize", "50"))
    except Exception:
        page_size = 50
    max_total = max(10, min(max_total, 1000))  # keep bounded
    page_size = max(10, min(page_size, 100))

    # Copy creds so background thread doesn't rely on request context/session
    from middleware.auth import parse_credentials_from_session
    creds_dict = parse_credentials_from_session()
    if not creds_dict:
        return jsonify({"error": "Unauthorized"}), 401
    user_email = session.get("user_email")

    def worker():
        try:
            from googleapiclient.discovery import build
            creds = Credentials(**creds_dict)
            service = build("gmail", "v1", credentials=creds)

            scanned = 0
            page_token = None
            while scanned < max_total:
                results = service.users().messages().list(
                    userId="me",
                    maxResults=page_size,
                    q="-label:trash",
                    pageToken=page_token
                ).execute()
                message_ids = [m["id"] for m in results.get("messages", [])]
                page_token = results.get("nextPageToken")
                if not message_ids:
                    break

                for msg_id in message_ids:
                    if scanned >= max_total:
                        break

                    scanned += 1
                try:
                    msg = service.users().messages().get(
                        userId="me",
                        id=msg_id,
                        format="metadata",
                        metadataHeaders=["From", "Subject"]
                    ).execute()

                    # Skip if already in trash
                    if "TRASH" in (msg.get("labelIds", []) or []):
                        continue

                    headers = msg["payload"]["headers"]
                    sender = subject = ""
                    for h in headers:
                        if h["name"] == "From":
                            sender = h["value"]
                        if h["name"] == "Subject":
                            subject = h["value"]

                    body = (msg.get("snippet", "") or "")[:200]
                    if not body:
                        continue

                    is_phishing, confidence, reason, explanation = ml_predict(body)
                    if is_phishing:
                        move_to_trash(service, msg_id)
                        log_email(
                            sender=sender,
                            subject=subject,
                            phishing=True,
                            confidence=confidence,
                            reason=reason,
                            action="Moved to Trash",
                            explanation=explanation,
                            receiver=user_email,
                            body=body,
                            message_id=msg_id,
                        )
                    else:
                        log_email(
                            sender=sender,
                            subject=subject,
                            phishing=False,
                            confidence=confidence,
                            reason=reason,
                            action="Delivered to Inbox",
                            explanation=explanation,
                            receiver=user_email,
                            body=body,
                            message_id=msg_id,
                        )
                except HttpError as e:
                    print(f"Scan HttpError {msg_id}: {e}")
                except Exception as e:
                    print(f"Scan error {msg_id}: {e}")

                if not page_token:
                    break
        except Exception as e:
            print(f"Scan worker failed: {e}")

        threading.Thread(target=worker, daemon=True).start()
        return jsonify({"message": "Scan started", "max": max_total, "pageSize": page_size})
    except Exception as e:
        logger.error(f"Error in scan_emails: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/phishing-logs")
@require_auth
def phishing_logs():
    """Render phishing detection logs with XAI explanations (limited to 100)"""
    try:
    
    import json
    from security.ml_detector import get_explanation_html
    
        try:
            data = execute_query(
                """
                SELECT message_id, sender, subject, body, reason, confidence, action, created_at, explanation
                FROM email_logs
                WHERE phishing = 1
                ORDER BY created_at DESC
                LIMIT 100
                """,
                fetch_all=True
            )
        except Exception as e:
            logger.error(f"Phishing logs DB error: {e}")
            # Fallback for older DBs
            try:
                data = execute_query(
                    """
                    SELECT NULL as message_id, sender, subject, NULL as body, reason, confidence, action, created_at, explanation
                    FROM email_logs
                    WHERE phishing = 1
                    ORDER BY created_at DESC
                    LIMIT 100
                    """,
                    fetch_all=True
                )
            except Exception as e2:
                logger.error(f"Phishing logs fallback error: {e2}")
                return handle_error("Database error", 500, is_api=False, retry_url="/phishing-logs")
    
    phishing_emails = []
    for row in data:
        explanation_data = {}
        try:
            explanation_data = json.loads(row[8]) if row[8] else {}
        except:
            explanation_data = {}
        
        # row layout: (message_id, sender, subject, body, reason, confidence, action, created_at, explanation)
        body = (row[3] or "") if len(row) > 3 else ""
        body_preview = body[:200] + "..." if len(body) > 200 else body
        
        phishing_emails.append({
            "message_id": row[0],
            "sender": row[1],
            "subject": row[2],
            "body": body_preview,
            "reason": row[4],
            "confidence": round(row[5] * 100, 2),
            "action": row[6],
            "date": row[7],
            "explanation": explanation_data,
            "explanation_html": get_explanation_html(explanation_data)
        })
    
        return render_template("pishing.html", emails=phishing_emails)
    except Exception as e:
        logger.error(f"Error in phishing_logs: {e}")
        return handle_error(e, 500, is_api=False, retry_url="/phishing-logs")


@app.route("/trash")
@require_auth
def trash_content():
    """Render trash partial with phishing explanations (optimized, limited to 50)"""
    import json
    from security.ml_detector import get_explanation_html

    try:
        service = get_gmail_service()
        if not service:
            return handle_error("Gmail service unavailable", 500, is_api=False, retry_url="/trash")

    # Fetch emails in trash (limited to 50 for performance)
    results = service.users().messages().list(userId="me", labelIds=["TRASH"], maxResults=50).execute()
    trash_emails = []

    # Use format='metadata' for faster processing
    message_ids = [m["id"] for m in results.get("messages", [])]
    
    # Get phishing emails from database for explanations (join by message_id for reliability)
    for msg_id in message_ids:
        try:
            # Use metadata format to get only headers
            msg = service.users().messages().get(userId="me", id=msg_id, format='metadata', metadataHeaders=['From', 'Subject']).execute()
            headers = msg["payload"]["headers"]
            sender = subject = ""
            for h in headers:
                if h["name"] == "From":
                    sender = h["value"]
                if h["name"] == "Subject":
                    subject = h["value"]

            body = msg.get("snippet", "")[:200]  # Limit body length
            
            # Check if this email is in phishing logs (prefer message_id)
            try:
                phishing_data = execute_query(
                    """
                    SELECT reason, confidence, action, created_at, explanation
                    FROM email_logs
                    WHERE message_id = ? AND phishing = 1
                    ORDER BY created_at DESC
                    LIMIT 1
                    """,
                    params=(msg_id,),
                    fetch_one=True
                )
            except Exception:
                # Fallback for older DBs without message_id column
                phishing_data = execute_query(
                    """
                    SELECT reason, confidence, action, created_at, explanation
                    FROM email_logs
                    WHERE sender = ? AND subject = ? AND phishing = 1
                    ORDER BY created_at DESC
                    LIMIT 1
                    """,
                    params=(sender, subject),
                    fetch_one=True
                )
            is_phishing = phishing_data is not None
            
            email_data = {
                "id": msg_id,
                "sender": sender,
                "subject": subject,
                "body": body,
                "is_phishing": is_phishing
            }
            
            # Add phishing explanation if found
            if is_phishing:
                explanation_data = {}
                try:
                    explanation_data = json.loads(phishing_data[4]) if phishing_data[4] else {}
                except:
                    explanation_data = {}
                
                email_data.update({
                    "reason": phishing_data[0],
                    "confidence": round(phishing_data[1] * 100, 2),
                    "action": phishing_data[2],
                    "date": phishing_data[3],
                    "explanation": explanation_data,
                    "explanation_html": get_explanation_html(explanation_data)
                })
            
            trash_emails.append(email_data)
        except Exception as e:
            logger.error(f"Error processing trash email {msg_id}: {e}")
            continue
    
        return render_template("trash.html", emails=trash_emails)
    except Exception as e:
        logger.error(f"Error in trash route: {e}")
        return handle_error(e, 500, is_api=False, retry_url="/trash")


# ---------------- API Routes ----------------

@app.route("/api/stats")
@require_auth
def get_stats():
    """
    Get statistics for dashboard.

    IMPORTANT: counts should reflect the user's Gmail (like a real email app),
    not just local DB logs. We still use DB for phishing count (XAI logs).
    """
    try:
        total_gmail = 0
    inbox_gmail = 0

    # Gmail counts (fast)
    try:
        service = get_gmail_service()
        if service:
            profile = service.users().getProfile(userId="me").execute()
            total_gmail = int(profile.get("messagesTotal") or 0)

            inbox_label = service.users().labels().get(userId="me", id="INBOX").execute()
            inbox_gmail = int(inbox_label.get("messagesTotal") or 0)
    except Exception as e:
        print(f"Stats Gmail error: {e}")

    # DB phishing count (logs)
    phishing = 0
    try:
        result = execute_query(
            "SELECT COUNT(*) FROM email_logs WHERE phishing = 1",
            fetch_one=True
        )
        phishing = int(result[0] or 0) if result else 0
    except Exception as e:
        logger.error(f"Stats DB error: {e}")

    # For UI: treat inbox as "safe" (what user sees in inbox)
    safe = inbox_gmail
    total = total_gmail if total_gmail else safe + phishing

    return jsonify({"total": total, "safe": safe, "phishing": phishing})
    except Exception as e:
        logger.error(f"Error in stats route: {e}")
        return jsonify({"error": str(e), "total": 0, "safe": 0, "phishing": 0}), 500

@app.route("/api/restore-email", methods=["POST"])
@require_auth
def restore_email():
    """Restore email from trash to inbox"""
    try:
        data = request.get_json()
    message_id = data.get("message_id")
    
    if not message_id:
        return jsonify({"error": "Message ID required"}), 400
    
    service = get_gmail_service()
    if not service:
        return jsonify({"error": "Gmail service unavailable"}), 500
    
        if restore_from_trash(service, message_id):
            return jsonify({"message": "Email restored successfully"})
        else:
            return jsonify({"error": "Failed to restore email"}), 500
    except Exception as e:
        logger.error(f"Error in restore_email: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/delete-email", methods=["POST"])
@require_auth
def delete_email():
    """Permanently delete email"""
    try:
        data = request.get_json()
    message_id = data.get("message_id")
    
    if not message_id:
        return jsonify({"error": "Message ID required"}), 400
    
    service = get_gmail_service()
    if not service:
        return jsonify({"error": "Gmail service unavailable"}), 500
    
        if delete_permanently(service, message_id):
            return jsonify({"message": "Email deleted permanently"})
        else:
            return jsonify({"error": "Failed to delete email"}), 500
    except Exception as e:
        logger.error(f"Error in delete_email: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/view-email")
@require_auth
def view_email():
    """Get full email content"""
    try:
        message_id = request.args.get("message_id")
    if not message_id:
        return jsonify({"error": "Message ID required"}), 400
    
    service = get_gmail_service()
    if not service:
        return jsonify({"error": "Gmail service unavailable"}), 500
    
    try:
        msg = service.users().messages().get(
            userId="me",
            id=message_id,
            format="full"
        ).execute()
        
        headers = msg["payload"].get("headers", [])
        sender = subject = to = date = ""
        for h in headers:
            name = h["name"].lower()
            if name == "from":
                sender = h["value"]
            elif name == "subject":
                subject = h["value"]
            elif name == "to":
                to = h["value"]
            elif name == "date":
                date = h["value"]
        
        body = get_body(msg["payload"])
        snippet = msg.get("snippet", "")
        labels = msg.get("labelIds", [])
        
        return jsonify({
            "message_id": message_id,
            "sender": sender,
            "subject": subject,
            "to": to,
            "date": date,
            "body": body or snippet,
            "snippet": snippet,
            "labels": labels
        })
    except Exception as e:
        logger.error(f"Error viewing email: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/toggle-star", methods=["POST"])
@require_auth
def toggle_star():
    """Star or unstar an email"""
    try:
        data = request.get_json()
    message_id = data.get("message_id")
    star = data.get("star", False)
    
    if not message_id:
        return jsonify({"error": "Message ID required"}), 400
    
    service = get_gmail_service()
    if not service:
        return jsonify({"error": "Gmail service unavailable"}), 500
    
    try:
        if star:
            # Add STAR label
            service.users().messages().modify(
                userId="me",
                id=message_id,
                body={"addLabelIds": ["STARRED"]}
            ).execute()
        else:
            # Remove STAR label
            service.users().messages().modify(
                userId="me",
                id=message_id,
                body={"removeLabelIds": ["STARRED"]}
            ).execute()
        
        return jsonify({"message": "Star updated successfully"})
    except Exception as e:
        logger.error(f"Error toggling star: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/toggle-flag", methods=["POST"])
@require_auth
def toggle_flag():
    """Flag or unflag an email"""
    try:
        data = request.get_json()
    message_id = data.get("message_id")
    flag = data.get("flag", False)
    
    if not message_id:
        return jsonify({"error": "Message ID required"}), 400
    
    service = get_gmail_service()
    if not service:
        return jsonify({"error": "Gmail service unavailable"}), 500
    
    try:
        if flag:
            # Add IMPORTANT label (Gmail's flag equivalent)
            service.users().messages().modify(
                userId="me",
                id=message_id,
                body={"addLabelIds": ["IMPORTANT"]}
            ).execute()
        else:
            # Remove IMPORTANT label
            service.users().messages().modify(
                userId="me",
                id=message_id,
                body={"removeLabelIds": ["IMPORTANT"]}
            ).execute()
        
        return jsonify({"message": "Flag updated successfully"})
    except Exception as e:
        logger.error(f"Error toggling flag: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/check-new-emails")
@require_auth
def check_new_emails():
    """Check for new emails since last check and scan them immediately"""
    try:
        service = get_gmail_service()
    if not service:
        return jsonify({"error": "Gmail service unavailable"}), 500
    
    # Get last check time from session or use current time - 1 hour
    last_check = session.get("last_email_check")
    if not last_check:
        # First check - get emails from last hour
        import time
        last_check = int(time.time()) - 3600
        session["last_email_check"] = last_check
    
    try:
        # Use Gmail's history API for more efficient new email detection
        # Fallback to query if history not available
        history_id = session.get("last_history_id")
        
        if history_id:
            try:
                # Use history API for faster detection
                # Note: history().list() doesn't support labelIds, so we filter during processing
                history = service.users().history().list(
                    userId="me",
                    startHistoryId=history_id,
                    historyTypes=["messageAdded"]
                ).execute()
                
                message_ids = []
                for change in history.get("history", []):
                    for msg_added in change.get("messagesAdded", []):
                        msg_id = msg_added.get("message", {}).get("id")
                        if msg_id:
                            message_ids.append(msg_id)
                
                # Update history ID
                if "historyId" in history:
                    session["last_history_id"] = history["historyId"]
            except HttpError as e:
                # Fallback to query method
                if e.resp.status == 404:
                    # No history available, use query
                    import time
                    query_time = int(time.time()) - 3600
                    query = f"in:inbox after:{query_time}"
                    try:
                        results = service.users().messages().list(
                            userId="me",
                            labelIds=["INBOX"],
                            maxResults=50,
                            q=query
                        ).execute()
                        message_ids = [m["id"] for m in results.get("messages", [])]
                    except Exception as query_err:
                        print(f"Error in query fallback: {query_err}")
                        message_ids = []
                else:
                    print(f"History API error (non-404): {e}")
                    # Fallback to query method for any history error
                    import time
                    query_time = int(time.time()) - 3600
                    query = f"in:inbox after:{query_time}"
                    try:
                        results = service.users().messages().list(
                            userId="me",
                            labelIds=["INBOX"],
                            maxResults=50,
                            q=query
                        ).execute()
                        message_ids = [m["id"] for m in results.get("messages", [])]
                    except Exception as query_err:
                        print(f"Error in query fallback: {query_err}")
                        message_ids = []
            except Exception as e:
                print(f"Error in history API call: {e}")
                # Fallback to query method
                import time
                query_time = int(time.time()) - 3600
                query = f"in:inbox after:{query_time}"
                try:
                    results = service.users().messages().list(
                        userId="me",
                        labelIds=["INBOX"],
                        maxResults=50,
                        q=query
                    ).execute()
                    message_ids = [m["id"] for m in results.get("messages", [])]
                except Exception as query_err:
                    print(f"Error in query fallback: {query_err}")
                    message_ids = []
        else:
            # First time - get current history ID and recent emails
            try:
                profile = service.users().getProfile(userId="me").execute()
                session["last_history_id"] = profile.get("historyId")
            except Exception as e:
                print(f"Error getting profile: {e}")
                # Continue without history ID
            
            # Get recent emails from last hour
            import time
            query_time = int(time.time()) - 3600
            query = f"in:inbox after:{query_time}"
            try:
                results = service.users().messages().list(
                    userId="me",
                    labelIds=["INBOX"],
                    maxResults=50,
                    q=query
                ).execute()
                message_ids = [m["id"] for m in results.get("messages", [])]
            except Exception as e:
                print(f"Error fetching messages: {e}")
                message_ids = []
        
        if not message_ids:
            return jsonify({"new_emails": [], "count": 0})
        
        # Get user email
        user_email = session.get("user_email")
        if not user_email:
            profile = service.users().getProfile(userId="me").execute()
            user_email = profile.get("emailAddress", "")
            session["user_email"] = user_email
        
        new_emails = []
        
        # Scan each new email immediately
        for msg_id in message_ids:
            try:
                msg = service.users().messages().get(
                    userId="me",
                    id=msg_id,
                    format="metadata",
                    metadataHeaders=["From", "Subject", "Date"]
                ).execute()
                
                # Filter to only INBOX messages (history API doesn't support labelIds)
                labels = msg.get("labelIds", [])
                if "INBOX" not in labels:
                    continue
                
                headers = msg["payload"]["headers"]
                sender = subject = date = ""
                for h in headers:
                    if h["name"] == "From":
                        sender = h["value"]
                    elif h["name"] == "Subject":
                        subject = h["value"]
                    elif h["name"] == "Date":
                        date = h["value"]
                
                body = (msg.get("snippet", "") or "")[:200]
                
                # Scan immediately with ML
                is_phishing = False
                confidence = 0.0
                reason = "Safe email"
                
                if body:
                    is_phishing, confidence, reason, explanation = ml_predict(body)
                    
                    if is_phishing:
                        # Move to trash immediately
                        move_to_trash(service, msg_id)
                        log_email(
                            sender=sender,
                            subject=subject,
                            phishing=True,
                            confidence=confidence,
                            reason=reason,
                            action="Moved to Trash",
                            explanation=explanation,
                            receiver=user_email,
                            body=body,
                            message_id=msg_id,
                        )
                    else:
                        # Log as safe
                        log_email(
                            sender=sender,
                            subject=subject,
                            phishing=False,
                            confidence=confidence,
                            reason=reason,
                            action="Delivered to Inbox",
                            explanation=explanation,
                            receiver=user_email,
                            body=body,
                            message_id=msg_id,
                        )
                
                new_emails.append({
                    "id": msg_id,
                    "sender": sender,
                    "subject": subject,
                    "body": body,
                    "date": date,
                    "is_phishing": is_phishing,
                    "confidence": round(confidence * 100, 2) if confidence else 0,
                    "reason": reason
                })
            except Exception as e:
                print(f"Error processing new email {msg_id}: {e}")
                continue
        
        # Update last check time
        import time
        session["last_email_check"] = int(time.time())
        
        return jsonify({
            "new_emails": new_emails,
            "count": len(new_emails)
        })
    except Exception as e:
        logger.error(f"Error checking new emails: {e}")
        import traceback
        traceback.print_exc()
        # Always return valid JSON, even on error
        return jsonify({
            "error": str(e),
            "new_emails": [],
            "count": 0
        }), 500


# ---------------- Logout ----------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ---------------- Run App ----------------
if __name__ == "__main__":
    logger.info(f"Starting Smail application on {config.HOST}:{config.PORT}")
    app.run(debug=config.DEBUG, host=config.HOST, port=config.PORT)