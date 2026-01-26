"""
Error handling middleware and utilities.
Provides centralized error handling for the application.
"""
from flask import jsonify, render_template_string
import logging
import traceback

logger = logging.getLogger(__name__)

# HTML error template
ERROR_TEMPLATE = """
<div class="error-container">
    <div class="error-icon">
        <i class="fas fa-exclamation-triangle"></i>
    </div>
    <h2>{{ title }}</h2>
    <p>{{ message }}</p>
    {% if details %}
    <ul class="error-list">
        {% for detail in details %}
        <li>{{ detail }}</li>
        {% endfor %}
    </ul>
    {% endif %}
    <div class="error-actions">
        {% if show_retry %}
        <button class="retry-btn" onclick="loadPage('{{ retry_url }}')">
            <i class="fas fa-redo"></i> Retry
        </button>
        {% endif %}
        {% if show_login %}
        <button class="refresh-btn" onclick="window.location.href='/'">
            <i class="fas fa-sign-in-alt"></i> Go to Login
        </button>
        {% endif %}
        {% if show_refresh %}
        <button class="refresh-btn" onclick="window.location.reload()">
            <i class="fas fa-sync-alt"></i> Refresh Page
        </button>
        {% endif %}
    </div>
    {% if error_details %}
    <p class="error-details">Error: {{ error_details }}</p>
    {% endif %}
</div>
"""


def handle_error(error, status_code=500, is_api=False, retry_url=None):
    """
    Centralized error handler.
    
    Args:
        error: Exception or error message string
        status_code: HTTP status code
        is_api: Whether this is an API route (returns JSON)
        retry_url: URL to retry the request
    
    Returns:
        Error response (JSON for API, HTML for pages)
    """
    error_message = str(error) if error else "An unexpected error occurred"
    
    # Log the error
    logger.error(f"Error {status_code}: {error_message}")
    if isinstance(error, Exception):
        logger.error(traceback.format_exc())
    
    # Determine error type
    error_str = error_message.lower()
    is_auth_error = (
        status_code == 401 or
        "unauthorized" in error_str or
        "session expired" in error_str or
        "token" in error_str and "expired" in error_str or
        "invalid_grant" in error_str
    )
    
    is_network_error = (
        "failed to fetch" in error_str or
        "network" in error_str or
        "connection" in error_str
    )
    
    # Prepare error response
    if is_api:
        return jsonify({
            "error": "Session Expired" if is_auth_error else "Error",
            "message": error_message,
            "status_code": status_code
        }), status_code
    
    # HTML response
    title = "Session Expired" if is_auth_error else "Error"
    message = (
        "Your session has expired or authentication failed. Please log in again."
        if is_auth_error
        else error_message
    )
    
    details = []
    if is_auth_error:
        details = [
            "Your Google OAuth token has expired",
            "Please log out and log back in to refresh your session"
        ]
    elif is_network_error:
        details = [
            "Network connection issues",
            "Session may have expired - please refresh the page",
            "Server temporarily unavailable"
        ]
    
    return render_template_string(
        ERROR_TEMPLATE,
        title=title,
        message=message,
        details=details,
        show_retry=retry_url is not None and not is_auth_error,
        show_login=is_auth_error,
        show_refresh=not is_auth_error,
        retry_url=retry_url or "",
        error_details=error_message if not is_auth_error else None
    ), status_code


def register_error_handlers(app):
    """Register global error handlers for the Flask app"""
    
    @app.errorhandler(401)
    def unauthorized(error):
        return handle_error(error, 401, is_api=False)
    
    @app.errorhandler(403)
    def forbidden(error):
        return handle_error(error, 403, is_api=False)
    
    @app.errorhandler(404)
    def not_found(error):
        return handle_error("Page not found", 404, is_api=False)
    
    @app.errorhandler(500)
    def internal_error(error):
        return handle_error(error, 500, is_api=False)
    
    @app.errorhandler(Exception)
    def handle_exception(error):
        """Catch-all exception handler"""
        logger.exception("Unhandled exception")
        return handle_error(error, 500, is_api=False)
