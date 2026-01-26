"""
Database utility functions with connection pooling and better error handling.
"""
import sqlite3
import threading
from contextlib import contextmanager
from config import config
import logging

logger = logging.getLogger(__name__)

# Thread-local storage for database connections
_local = threading.local()


@contextmanager
def get_db_connection():
    """
    Context manager for database connections.
    Uses thread-local storage to reuse connections within the same thread.
    """
    if not hasattr(_local, 'connection') or _local.connection is None:
        try:
            _local.connection = sqlite3.connect(
                str(config.DATABASE_PATH),
                check_same_thread=False,
                timeout=10.0
            )
            _local.connection.row_factory = sqlite3.Row
            logger.debug("Created new database connection")
        except sqlite3.Error as e:
            logger.error(f"Error creating database connection: {e}")
            raise
    
    try:
        yield _local.connection
    except sqlite3.Error as e:
        logger.error(f"Database error: {e}")
        _local.connection.rollback()
        raise
    finally:
        # Don't close connection, keep it for thread reuse
        pass


def close_db_connection():
    """Close the thread-local database connection"""
    if hasattr(_local, 'connection') and _local.connection:
        try:
            _local.connection.close()
        except Exception as e:
            logger.error(f"Error closing database connection: {e}")
        finally:
            _local.connection = None


def execute_query(query, params=None, fetch_one=False, fetch_all=False):
    """
    Execute a database query safely.
    
    Args:
        query: SQL query string
        params: Query parameters (tuple or dict)
        fetch_one: Return single row
        fetch_all: Return all rows
    
    Returns:
        Query result based on fetch flags
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            
            if fetch_one:
                return cursor.fetchone()
            elif fetch_all:
                return cursor.fetchall()
            else:
                conn.commit()
                return cursor.rowcount
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Query execution error: {e}")
            raise
