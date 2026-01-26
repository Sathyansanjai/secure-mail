"""
Google OAuth flow management using centralized configuration.
"""
from google_auth_oauthlib.flow import Flow
from config import config
import os

# Set OAuth insecure transport if configured
if config.OAUTHLIB_INSECURE_TRANSPORT == "1" or config.OAUTHLIB_INSECURE_TRANSPORT.lower() == "true":
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"


def get_flow():
    """
    Create and return OAuth flow using centralized configuration.
    
    Returns:
        Flow: Configured OAuth flow object
    """
    return Flow.from_client_secrets_file(
        config.OAUTH_CLIENT_SECRET_FILE,
        scopes=config.OAUTH_SCOPES,
        redirect_uri=config.OAUTH_REDIRECT_URI
    )
