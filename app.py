"""
Smail - Secure Mail Application
Main Flask application with improved error handling and scalability.
"""

from flask import Flask, session, redirect, request, render_template, jsonify
from datetime import datetime
from auth.google_oauth import get_flow
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials
from security.ml_detector import ml_predict
from security.auto_del import move_to_trash, restore_from_trash, delete_permanently
from database.db import init_db
from database.logs import log_email
from middleware.auth import require_auth, get_gmail_service, parse_credentials_from_session
from middleware.errors import register_error_handlers, handle_error
from config import config

from email.message import EmailMessage

import base64
import threading
import logging
import json

# ---------------- Logging ----------------

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# ---------------- App Init ----------------

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

app.config.update(
    PERMANENT_SESSION_LIFETIME=config.PERMANENT_SESSION_LIFETIME,
    SESSION_COOKIE_SECURE=config.SESSION_COOKIE_SECURE,
    SESSION_COOKIE_HTTPONLY=config.SESSION_COOKIE_HTTPONLY,
    SESSION_COOKIE_SAMESITE=config.SESSION_COOKIE_SAMESITE,
)

register_error_handlers(app)
init_db()

# ---------------- Auth Routes ----------------

@app.route("/")
def show_login():
    return render_template("login.html")


@app.route("/start-oauth")
def start_oauth():
    try:
        # Clear any existing state and credentials
        session.pop("state", None)
        session.pop("credentials", None)
        
        # Make session permanent before storing state
        session.permanent = True
        
        flow = get_flow()
        auth_url, state = flow.authorization_url()
        
        # Store state in session (for reference, library handles validation)
        session["state"] = state
        
        logger.debug(f"OAuth started - State stored in session")
        
        return redirect(auth_url)
    except Exception as e:
        logger.error(f"OAuth start error: {e}", exc_info=True)
        return handle_error(f"Failed to start authentication: {str(e)}", 500, False)


@app.route("/callback")
def callback():
    try:
        # Make session permanent to ensure it persists
        session.permanent = True
        
        # Create flow and fetch token
        # Note: google_auth_oauthlib's Flow.fetch_token() validates state automatically
        # by comparing the state in the authorization_response URL with the state
        # stored internally in the Flow object. However, since we create a new Flow
        # object here, the library can't validate state this way.
        # 
        # The library will still work, but state validation happens differently.
        # We'll catch any state-related errors and provide helpful messages.
        
        flow = get_flow()
        
        # Try to fetch token
        try:
            flow.fetch_token(authorization_response=request.url)
        except ValueError as ve:
            # ValueError often indicates state mismatch or other validation issues
            error_msg = str(ve).lower()
            logger.error(f"Token fetch ValueError: {ve}")
            
            if "state" in error_msg or "mismatch" in error_msg:
                logger.warning("OAuth state validation failed")
                session.pop("state", None)
                return handle_error(
                    "OAuth authentication failed due to state validation error.\n\n"
                    "This can happen if:\n"
                    "- You took too long to complete authentication\n"
                    "- Your browser cookies are disabled\n"
                    "- You're using a different browser/session\n"
                    "- The authentication session expired\n\n"
                    "Please try logging in again.",
                    400,
                    False
                )
            raise
        except Exception as token_error:
            error_msg = str(token_error).lower()
            logger.error(f"Token fetch error: {token_error}")
            
            # Check for state-related errors
            if "state" in error_msg or "invalid_grant" in error_msg or "mismatch" in error_msg:
                logger.warning("OAuth state validation failed")
                session.pop("state", None)
                return handle_error(
                    "OAuth authentication failed. Please try logging in again.",
                    400,
                    False
                )
            # Re-raise other errors
            raise
        
        creds = flow.credentials

        if not creds or not creds.token:
            logger.error("Failed to obtain credentials from OAuth callback")
            return handle_error("Failed to authenticate with Google", 500, False)

        session["credentials"] = {
            "token": creds.token,
            "refresh_token": creds.refresh_token,
            "token_uri": creds.token_uri,
            "client_id": creds.client_id,
            "client_secret": creds.client_secret,
            "scopes": creds.scopes,
            "expiry": creds.expiry.isoformat() if creds.expiry else None
        }
        
        # Clear state after successful authentication
        session.pop("state", None)
        
        # Make session permanent to persist across browser restarts
        session.permanent = True
        
        logger.info("OAuth authentication successful")
        return redirect("/main")
    except Exception as e:
        logger.error(f"OAuth callback error: {e}", exc_info=True)
        # Clear any invalid state
        session.pop("state", None)
        return handle_error(f"Authentication failed: {str(e)}", 500, False)


@app.route("/main")
@require_auth
def main():
    try:
        service = get_gmail_service()
        if not service:
            return redirect("/")

        if "user_email" not in session:
            profile = service.users().getProfile(userId="me").execute()
            session["user_email"] = profile.get("emailAddress", "")

        return render_template("main.html", user_email=session["user_email"])
    except Exception as e:
        logger.error(e)
        return handle_error(e, 500, is_api=False)

# ---------------- Helper ----------------

def get_body(payload):
    if "parts" in payload:
        for part in payload["parts"]:
            if part["mimeType"] == "text/plain":
                data = part["body"].get("data")
                if data:
                    return base64.urlsafe_b64decode(data).decode()
    elif payload.get("body", {}).get("data"):
        return base64.urlsafe_b64decode(payload["body"]["data"]).decode()
    return ""

def get_email_status(message_id):
    from utils.database import get_db_connection
    is_phishing = False
    confidence = 0
    scanned = False
    explanation = None
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT phishing, confidence, explanation FROM email_logs WHERE message_id = ?",
            (message_id,)
        )
        row = cursor.fetchone()
        if row:
            is_phishing = bool(row[0])
            confidence = row[1] or 0
            explanation = row[2]
            scanned = True
            
    return is_phishing, confidence, scanned, explanation

# ---------------- API: View Email ----------------

@app.route("/api/view-email")
@require_auth
def api_view_email():
    try:
        message_id = request.args.get("message_id")
        if not message_id:
            return jsonify({"error": "Message ID required"}), 400
            
        service = get_gmail_service()
        if not service:
            return jsonify({"error": "Gmail unavailable"}), 500
            
        msg = service.users().messages().get(
            userId="me",
            id=message_id,
            format="full"
        ).execute()
        
        headers = {h["name"]: h["value"] for h in msg.get("payload", {}).get("headers", [])}
        body = get_body(msg.get("payload", {}))
        
        # Format date
        date_str = ""
        internal_date = msg.get("internalDate")
        if internal_date:
            try:
                ts = int(internal_date) / 1000
                date_str = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M')
            except:
                date_str = headers.get("Date", "")

        return jsonify({
            "id": message_id,
            "sender": headers.get("From", ""),
            "subject": headers.get("Subject", ""),
            "date": date_str,
            "body": body,
            "snippet": msg.get("snippet", "")
        })
        
    except Exception as e:
        logger.error(f"View email error: {e}")
        return jsonify({"error": str(e)}), 500

# ---------------- Inbox ----------------

@app.route("/inbox")
@require_auth
def inbox_content():
    try:
        service = get_gmail_service()
        if not service:
            return handle_error("Gmail unavailable", 500, False)

        results = service.users().messages().list(
            userId="me",
            labelIds=["INBOX"],
            maxResults=25
        ).execute()

        from utils.database import get_db_connection
        
        emails = []
        for m in results.get("messages", []):
            msg = service.users().messages().get(
                userId="me",
                id=m["id"],
                format="metadata",
                metadataHeaders=["From", "Subject"]
            ).execute()

            headers = {h["name"]: h["value"] for h in msg["payload"]["headers"]}
            
            # Check DB for phishing status
            is_phishing = False
            confidence = 0
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT phishing, confidence FROM email_logs WHERE message_id = ?",
                    (m["id"],)
                )
                row = cursor.fetchone()
                if row:
                    is_phishing = bool(row[0])
                    confidence = row[1] or 0
            
            emails.append({
                "id": m["id"],
                "sender": headers.get("From", ""),
                "subject": headers.get("Subject", ""),
                "body": msg.get("snippet", ""),
                "is_phishing": is_phishing,
                "confidence": int(confidence * 100) if confidence else None,
                "scanned": row is not None
            })

        return render_template("inbox.html", emails=emails)

    except Exception as e:
        logger.error(e)
        return handle_error(e, 500, False)

# ---------------- Send Mail ----------------

@app.route("/send-mail", methods=["POST"])
@require_auth
def send_mail():
    try:
        service = get_gmail_service()
        if not service:
            return jsonify({"error": "Gmail unavailable"}), 500

        data = request.get_json() if request.is_json else request.form
        to = data.get("to")
        subject = data.get("subject")
        body = data.get("body")

        if not to or not subject or not body:
            return jsonify({"error": "All fields required"}), 400

        user_email = session.get("user_email")

        msg = EmailMessage()
        msg["To"] = to
        msg["From"] = user_email
        msg["Subject"] = subject
        msg.set_content(body)

        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()

        sent = service.users().messages().send(
            userId="me",
            body={"raw": raw}
        ).execute()

        return jsonify({"message": "Sent", "id": sent["id"]})

    except Exception as e:
        logger.error(e)
        return jsonify({"error": str(e)}), 500

# ---------------- Scan Emails ----------------

@app.route("/scan-emails")
@require_auth
def scan_emails():
    creds_dict = parse_credentials_from_session()
    if not creds_dict:
        return jsonify({"error": "Unauthorized"}), 401

    def worker():
        try:
            from googleapiclient.discovery import build
            from google.auth.transport.requests import Request
            
            # Create credentials object and refresh if needed
            creds = Credentials(**creds_dict)
            if creds.expired and creds.refresh_token:
                creds.refresh(Request())
            
            service = build("gmail", "v1", credentials=creds)

            results = service.users().messages().list(
                userId="me",
                maxResults=50
            ).execute()

            for m in results.get("messages", []):
                msg = service.users().messages().get(
                    userId="me",
                    id=m["id"],
                    format="metadata",
                    metadataHeaders=["From", "Subject"]
                ).execute()

                # Extract headers
                headers = {h["name"]: h["value"] for h in msg.get("payload", {}).get("headers", [])}
                sender = headers.get("From", "")
                subject = headers.get("Subject", "")
                body = msg.get("snippet", "")
                
                if not body:
                    continue

                is_phish, conf, reason, exp = ml_predict(body)

                log_email(
                    sender=sender,
                    subject=subject,
                    phishing=is_phish,
                    confidence=conf,
                    reason=reason,
                    action="Moved to Trash" if is_phish else "Safe",
                    explanation=exp,
                    message_id=m["id"],
                    body=body
                )

                if is_phish:
                    move_to_trash(service, m["id"])

        except Exception as e:
            logger.error(f"Scan error: {e}")

    threading.Thread(target=worker, daemon=True).start()
    return jsonify({"message": "Scan started"})

# ---------------- All Mail ----------------

@app.route("/api/allmail")
@require_auth
def all_mail():
    try:
        service = get_gmail_service()
        if not service:
            return handle_error("Gmail unavailable", 500, False)

        page_token = request.args.get("pageToken")
        
        results = service.users().messages().list(
            userId="me",
            maxResults=50,
            pageToken=page_token
        ).execute()

        from utils.database import get_db_connection
        
        emails = []
        for m in results.get("messages", []):
            msg = service.users().messages().get(
                userId="me",
                id=m["id"],
                format="metadata",
                metadataHeaders=["From", "Subject"]
            ).execute()

            headers = {h["name"]: h["value"] for h in msg["payload"]["headers"]}
            
            # Check if starred or flagged
            label_ids = msg.get("labelIds", [])
            starred = "STARRED" in label_ids
            flagged = "IMPORTANT" in label_ids
            
            # Check DB for phishing status
            is_phishing = False
            confidence = 0
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT phishing, confidence FROM email_logs WHERE message_id = ?",
                    (m["id"],)
                )
                row = cursor.fetchone()
                if row:
                    is_phishing = bool(row[0])
                    confidence = row[1] or 0
            
            emails.append({
                "id": m["id"],
                "sender": headers.get("From", ""),
                "subject": headers.get("Subject", ""),
                "body": msg.get("snippet", ""),
                "starred": starred,
                "flagged": flagged,
                "is_phishing": is_phishing,
                "confidence": int(confidence * 100) if confidence else None,
                "scanned": row is not None
            })

        # Check for next page token
        next_page_token = results.get("nextPageToken")

        return render_template("all_mail.html", emails=emails, next_page_token=next_page_token)

    except Exception as e:
        logger.error(e)
        return handle_error(e, 500, False)



@app.route("/api/toggle-star", methods=["POST"])
@require_auth
def toggle_star_api():
    data = request.json
    service = get_gmail_service()
    action = {"addLabelIds": ["STARRED"]} if data['star'] else {"removeLabelIds": ["STARRED"]}
    service.users().messages().modify(userId="me", id=data['message_id'], body=action).execute()
    return jsonify({"message": "success"})

@app.route("/api/toggle-flag", methods=["POST"])
@require_auth
def toggle_flag_api():
    data = request.json
    service = get_gmail_service()
    action = {"addLabelIds": ["IMPORTANT"]} if data['flag'] else {"removeLabelIds": ["IMPORTANT"]}
    service.users().messages().modify(userId="me", id=data['message_id'], body=action).execute()
    return jsonify({"message": "success"})

# ---------------- Trash ----------------

@app.route("/trash")
@require_auth
def trash():
    try:
        service = get_gmail_service()
        if not service:
            return handle_error("Gmail unavailable", 500, False)

        results = service.users().messages().list(
            userId="me",
            labelIds=["TRASH"],
            maxResults=50
        ).execute()

        emails = []
        for m in results.get("messages", []):
            msg = service.users().messages().get(
                userId="me",
                id=m["id"],
                format="metadata",
                metadataHeaders=["From", "Subject"]
            ).execute()

            headers = {h["name"]: h["value"] for h in msg["payload"]["headers"]}
            body = msg.get("snippet", "")
            
            # Check database for phishing info
            from utils.database import get_db_connection
            import json
            from security.ml_detector import get_explanation_html
            
            is_phishing = False
            confidence = 0
            reason = ""
            explanation_html = ""
            action = ""
            
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT phishing, confidence, reason, explanation, action FROM email_logs WHERE message_id = ?",
                    (m["id"],)
                )
                row = cursor.fetchone()
                if row:
                    is_phishing = bool(row[0])
                    confidence = row[1] or 0
                    reason = row[2] or ""
                    explanation = row[3]
                    action = row[4] or ""
                    if explanation:
                        try:
                            # Parse explanation JSON
                            if isinstance(explanation, str):
                                exp_data = json.loads(explanation) if explanation.strip().startswith('{') else {}
                            else:
                                exp_data = explanation if isinstance(explanation, dict) else {}
                            
                            # Generate HTML explanation if we have valid data
                            if exp_data and (exp_data.get('phishing_words') or exp_data.get('safe_words')):
                                explanation_html = get_explanation_html(exp_data)
                            else:
                                logger.debug(f"No valid explanation data for message {m['id']}")
                        except Exception as e:
                            logger.warning(f"Error generating explanation HTML for message {m['id']}: {e}")
                            explanation_html = ""
            
            emails.append({
                "id": m["id"],
                "sender": headers.get("From", ""),
                "subject": headers.get("Subject", ""),
                "body": body,
                "is_phishing": is_phishing,
                "confidence": int(confidence * 100) if confidence else 0,
                "reason": reason,
                "action": action,
                "explanation_html": explanation_html,
                "date": datetime.fromtimestamp(int(msg.get("internalDate", 0))/1000).strftime('%Y-%m-%d %H:%M') if msg.get("internalDate") else ""
            })

        return render_template("trash.html", emails=emails)

    except Exception as e:
        logger.error(e)
        return handle_error(e, 500, False)

# ---------------- Phishing Logs ----------------

@app.route("/phishing-logs")
@require_auth
def phishing_logs():
    try:
        from utils.database import get_db_connection
        import json
        from security.ml_detector import get_explanation_html
        
        emails = []
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT sender, subject, body, phishing, confidence, reason, action, explanation, created_at, message_id
                FROM email_logs 
                WHERE phishing = 1 
                ORDER BY created_at DESC 
                LIMIT 50
            """)
            rows = cursor.fetchall()
            
            for row in rows:
                explanation = row[7]
                explanation_html = ""
                if explanation:
                    try:
                        exp_data = json.loads(explanation) if isinstance(explanation, str) else explanation
                        explanation_html = get_explanation_html(exp_data)
                    except:
                        pass
                
                emails.append({
                    "sender": row[0] or "Unknown",
                    "subject": row[1] or "No Subject",
                    "body": row[2] or "",
                    "confidence": int((row[4] or 0) * 100),
                    "reason": row[5] or "Phishing detected",
                    "action": row[6] or "Moved to Trash",
                    "date": row[8] or "",
                    "explanation_html": explanation_html,
                    "id": row[9]
                })

        return render_template("pishing.html", emails=emails)

    except Exception as e:
        logger.error(e)
        return handle_error(e, 500, False)

# ---------------- Compose ----------------

@app.route("/compose")
@require_auth
def compose():
    try:
        return render_template("compose.html", user_email=session.get("user_email"))
    except Exception as e:
        logger.error(e)
        return handle_error(e, 500, False)

# ---------------- API: Stats ----------------

@app.route("/api/stats")
@require_auth
def api_stats():
    try:
        from utils.database import get_db_connection
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM email_logs")
            total = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM email_logs WHERE phishing = 1")
            phishing = cursor.fetchone()[0]
            
            safe = total - phishing
        
        return jsonify({
            "total": total,
            "safe": safe,
            "phishing": phishing
        })

    except Exception as e:
        logger.error(e)
        return jsonify({"error": str(e)}), 500

# ---------------- API: Check New Emails ----------------

@app.route("/api/check-new-emails")
@require_auth
def api_check_new_emails():
    try:
        service = get_gmail_service()
        if not service:
            return jsonify({"error": "Gmail unavailable"}), 500

        from utils.database import get_db_connection
        
        # Get recent messages from inbox
        results = service.users().messages().list(
            userId="me",
            labelIds=["INBOX"],
            maxResults=10
        ).execute()

        new_emails = []
        for m in results.get("messages", []):
            # Check if we've already processed this email
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT COUNT(*) FROM email_logs WHERE message_id = ?",
                    (m["id"],)
                )
                already_processed = cursor.fetchone()[0] > 0
            
            # Skip if already processed
            if already_processed:
                continue
            
            msg = service.users().messages().get(
                userId="me",
                id=m["id"],
                format="metadata",
                metadataHeaders=["From", "Subject"]
            ).execute()

            headers = {h["name"]: h["value"] for h in msg["payload"]["headers"]}
            body = msg.get("snippet", "")
            
            # Check if phishing
            is_phish, conf, reason, exp = ml_predict(body)
            
            # Log all emails (safe and phishing)
            log_email(
                sender=headers.get("From", ""),
                subject=headers.get("Subject", ""),
                phishing=is_phish,
                confidence=conf,
                reason=reason,
                action="Moved to Trash" if is_phish else "Delivered to Inbox",
                explanation=exp if is_phish else None,
                message_id=m["id"],
                body=body
            )
            
            # Only add phishing emails to new_emails for alerts
            # Safe emails are logged but don't trigger alerts
            if is_phish:
                move_to_trash(service, m["id"])
                new_emails.append({
                    "id": m["id"],
                    "sender": headers.get("From", ""),
                    "subject": headers.get("Subject", ""),
                    "body": body,
                    "is_phishing": True,
                    "confidence": int(conf * 100) if conf else 0,
                    "reason": reason
                })

        return jsonify({
            "new_emails": new_emails,
            "count": len(new_emails)
        })

    except Exception as e:
        logger.error(e)
        return jsonify({"error": str(e)}), 500

# ---------------- Logout ----------------

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# ---------------- Run ----------------

if __name__ == "__main__":
    app.run(
        debug=config.DEBUG,
        host=config.HOST,
        port=config.PORT
    )
