"""
Centralized configuration management for Smail application.
Supports environment variables and sensible defaults.
"""
import os
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).parent

# Flask Configuration
class Config:
    """Base configuration with sensible defaults"""
    # Flask secret key - MUST be set in production via environment variable
    SECRET_KEY = os.environ.get("SECRET_KEY", "smail_secret_key_change_in_production")
    
    # Session configuration
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "False").lower() == "true"
    SESSION_COOKIE_HTTPONLY = True
    # Use "Lax" for SameSite to allow OAuth redirects, or "None" if using HTTPS
    SESSION_COOKIE_SAMESITE = os.environ.get("SESSION_COOKIE_SAMESITE", "Lax")
    PERMANENT_SESSION_LIFETIME = int(os.environ.get("PERMANENT_SESSION_LIFETIME", 3600))  # 1 hour default
    
    # OAuth Configuration
    OAUTHLIB_INSECURE_TRANSPORT = os.environ.get("OAUTHLIB_INSECURE_TRANSPORT", "1")
    OAUTH_CLIENT_SECRET_FILE = os.environ.get("OAUTH_CLIENT_SECRET_FILE", "client_secret.json")
    OAUTH_REDIRECT_URI = os.environ.get("OAUTH_REDIRECT_URI", "http://localhost:5000/callback")
    OAUTH_SCOPES = [
        "https://www.googleapis.com/auth/gmail.modify"
    ]
    
    # Database Configuration
    DATABASE_DIR = BASE_DIR / "database"
    DATABASE_PATH = DATABASE_DIR / "smail.db"
    DATABASE_POOL_SIZE = int(os.environ.get("DATABASE_POOL_SIZE", "5"))
    
    # Local Login Configuration
    LOCAL_LOGIN_EMAIL = os.environ.get("LOCAL_LOGIN_EMAIL", "admin@example.com")
    LOCAL_LOGIN_PASSWORD = os.environ.get("LOCAL_LOGIN_PASSWORD")
    LOCAL_LOGIN_PASSWORD_HASH = os.environ.get("LOCAL_LOGIN_PASSWORD_HASH")
    
    # Application Settings
    DEBUG = os.environ.get("FLASK_DEBUG", "False").lower() == "true"
    HOST = os.environ.get("FLASK_HOST", "0.0.0.0")
    PORT = int(os.environ.get("FLASK_PORT", 5000))
    
    # Email Scanning Configuration
    MAX_SCAN_RESULTS = int(os.environ.get("MAX_SCAN_RESULTS", "200"))
    SCAN_PAGE_SIZE = int(os.environ.get("SCAN_PAGE_SIZE", "50"))
    EMAIL_CHECK_INTERVAL = int(os.environ.get("EMAIL_CHECK_INTERVAL", "5"))  # seconds
    
    # Performance Settings
    MAX_CONCURRENT_REQUESTS = int(os.environ.get("MAX_CONCURRENT_REQUESTS", "5"))
    EMAIL_BATCH_SIZE = int(os.environ.get("EMAIL_BATCH_SIZE", "30"))
    
    # Logging
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
    LOG_FILE = os.environ.get("LOG_FILE", "smail.log")

# Create instance
config = Config()

# Ensure database directory exists
config.DATABASE_DIR.mkdir(exist_ok=True)
