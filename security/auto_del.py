"""
Email management functions for moving, restoring, and deleting emails.
"""
import logging
from googleapiclient.errors import HttpError

logger = logging.getLogger(__name__)


def move_to_trash(service, message_id):
    """
    Move email to trash using Gmail API
    
    Args:
        service: Gmail API service object
        message_id: ID of the message to move to trash
    
    Returns:
        bool: True if successful, False otherwise
    """
    if not service or not message_id:
        logger.warning("Invalid service or message_id provided to move_to_trash")
        return False
    
    try:
        service.users().messages().trash(
            userId="me",
            id=message_id
        ).execute()
        logger.info(f"Successfully moved message {message_id} to trash")
        return True
    except HttpError as e:
        logger.error(f"HTTP error moving message {message_id} to trash: {e}")
        return False
    except Exception as e:
        logger.error(f"Error moving message {message_id} to trash: {e}")
        return False


def restore_from_trash(service, message_id):
    """
    Restore email from trash to inbox using Gmail API
    
    Args:
        service: Gmail API service object
        message_id: ID of the message to restore
    
    Returns:
        bool: True if successful, False otherwise
    """
    if not service or not message_id:
        logger.warning("Invalid service or message_id provided to restore_from_trash")
        return False
    
    try:
        service.users().messages().untrash(
            userId="me",
            id=message_id
        ).execute()
        logger.info(f"Successfully restored message {message_id} from trash")
        return True
    except HttpError as e:
        logger.error(f"HTTP error restoring message {message_id} from trash: {e}")
        return False
    except Exception as e:
        logger.error(f"Error restoring message {message_id} from trash: {e}")
        return False


def delete_permanently(service, message_id):
    """
    Permanently delete email using Gmail API
    
    Args:
        service: Gmail API service object
        message_id: ID of the message to delete permanently
    
    Returns:
        bool: True if successful, False otherwise
    """
    if not service or not message_id:
        logger.warning("Invalid service or message_id provided to delete_permanently")
        return False
    
    try:
        service.users().messages().delete(
            userId="me",
            id=message_id
        ).execute()
        logger.info(f"Successfully deleted message {message_id} permanently")
        return True
    except HttpError as e:
        logger.error(f"HTTP error deleting message {message_id} permanently: {e}")
        return False
    except Exception as e:
        logger.error(f"Error deleting message {message_id} permanently: {e}")
        return False