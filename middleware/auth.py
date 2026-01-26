"""
Authentication middleware for session and token management.
Provides decorators and utilities for secure session handling.
"""
from functools import wraps
from flask import session, redirect, jsonify, request
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


def parse_credentials_from_session():
    """Parse credentials from session, handling expiry conversion safely"""
    if "credentials" not in session:
        return None
    
    try:
        creds_dict = dict(session["credentials"])
        
        # Handle expiry conversion - Credentials requires datetime object, not string
        expiry_value = creds_dict.get("expiry")
        parsed_expiry = None
        
        if expiry_value is not None:
            if isinstance(expiry_value, str):
                try:
                    # Parse ISO format string to datetime
                    expiry_str = expiry_value.replace('Z', '+00:00')
                    parsed_expiry = datetime.fromisoformat(expiry_str)
                except (ValueError, AttributeError, TypeError) as e:
                    logger.warning(f"Error parsing expiry string '{expiry_value}': {e}")
                    parsed_expiry = None
            elif isinstance(expiry_value, datetime):
                parsed_expiry = expiry_value
        
        # Only include expiry if we have a valid datetime object
        if parsed_expiry is not None:
            creds_dict["expiry"] = parsed_expiry
        else:
            creds_dict.pop("expiry", None)
        
        return creds_dict
    except Exception as e:
        logger.error(f"Error parsing credentials from session: {e}")
        return None


def refresh_credentials_if_needed(creds_dict):
    """
    Refresh OAuth credentials if expired.
    Returns (updated_creds_dict, success)
    """
    if not creds_dict:
        return None, False
    
    try:
        creds = Credentials(**creds_dict)
        
        # Check if token is expired and refresh if needed
        if creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                
                # Update session with refreshed token
                updated_creds = {
                    "token": creds.token,
                    "refresh_token": creds.refresh_token,
                    "token_uri": creds.token_uri,
                    "client_id": creds.client_id,
                    "client_secret": creds.client_secret,
                    "scopes": creds.scopes,
                    "expiry": creds.expiry.isoformat() if creds.expiry else None
                }
                
                session["credentials"] = updated_creds
                logger.info("Token refreshed successfully")
                return updated_creds, True
            except Exception as refresh_error:
                logger.error(f"Error refreshing token: {refresh_error}")
                # Token refresh failed - session expired or invalid
                session.pop("credentials", None)
                return None, False
        
        return creds_dict, True
    except Exception as e:
        logger.error(f"Error in refresh_credentials_if_needed: {e}")
        return None, False


def get_gmail_service():
    """
    Get Gmail service from session credentials with automatic token refresh.
    Returns service object or None if authentication fails.
    """
    creds_dict = parse_credentials_from_session()
    if not creds_dict:
        return None
    
    try:
        # Refresh credentials if needed
        creds_dict, success = refresh_credentials_if_needed(creds_dict)
        if not success:
            return None
        
        # Create Credentials object
        creds = Credentials(**creds_dict)
        
        # Build and return service
        return build("gmail", "v1", credentials=creds)
    except HttpError as e:
        error_str = str(e).lower()
        if "invalid_grant" in error_str or "token" in error_str or "expired" in error_str:
            logger.warning("Token expired or invalid, clearing session")
            session.pop("credentials", None)
        return None
    except Exception as e:
        logger.error(f"Error building Gmail service: {e}")
        return None


def require_auth(f):
    """
    Decorator to require authentication for a route.
    Returns JSON error for API routes, HTML error for page routes.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "credentials" not in session:
            # Check if this is an API route (expects JSON)
            if request.path.startswith("/api/") or request.is_json or request.accept_mimetypes.accept_json:
                return jsonify({"error": "Unauthorized", "message": "Session expired. Please log in again."}), 401
            else:
                # For page routes, return HTML error
                return (
                    '<div class="error-container">'
                    '<h2>Session Expired</h2>'
                    '<p>Your session has expired or authentication failed. Please log in again.</p>'
                    '<button class="retry-btn" onclick="window.location.href=\'/\'">Go to Login</button>'
                    '</div>',
                    401
                )
        
        # Verify credentials are still valid
        service = get_gmail_service()
        if not service:
            # Credentials exist but are invalid
            if request.path.startswith("/api/") or request.is_json or request.accept_mimetypes.accept_json:
                return jsonify({
                    "error": "Session Expired",
                    "message": "Your Google OAuth token has expired. Please log out and log back in."
                }), 401
            else:
                return (
                    '<div class="error-container">'
                    '<h2>Session Expired</h2>'
                    '<p>Your Google OAuth token has expired. Please <a href="/logout">log out</a> and log back in.</p>'
                    '<button class="retry-btn" onclick="window.location.href=\'/logout\'">Go to Login</button>'
                    '</div>',
                    401
                )
        
        # Pass service to route function
        return f(*args, **kwargs)
    
    return decorated_function


def require_auth_optional(f):
    """
    Decorator for routes that work with or without authentication.
    Passes None as service if not authenticated.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        service = None
        if "credentials" in session:
            service = get_gmail_service()
        return f(service=service, *args, **kwargs)
    
    return decorated_function
