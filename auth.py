import sqlite3
import hashlib
import os
import logging

DB_PATH = os.path.join(os.path.dirname(__file__), 'users.db')
logger = logging.getLogger(__name__)


def _get_conn():
    conn = sqlite3.connect(DB_PATH)
    return conn


def init_db():
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        '''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
        '''
    )
    conn.commit()
    conn.close()


def _hash_password(password: str) -> str:
    # simple SHA256 hash; salt with fixed string for demonstration
    salt = 'phishingsalt'
    return hashlib.sha256((salt + password).encode('utf-8')).hexdigest()


def register_user(username: str, password: str) -> tuple[bool, str]:
    """Return (success, message)"""
    if not username or not password:
        return False, 'username and password required'
    conn = _get_conn()
    cur = conn.cursor()
    try:
        pw_hash = _hash_password(password)
        cur.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                    (username, pw_hash))
        conn.commit()
        return True, 'user created'
    except sqlite3.IntegrityError:
        return False, 'username already exists'
    finally:
        conn.close()


def verify_user(username: str, password: str) -> bool:
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return False
    stored_hash = row[0]
    return stored_hash == _hash_password(password)


def user_exists(username: str) -> bool:
    """Return True if a user exists for the given username."""
    if not username:
        return False
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute('SELECT 1 FROM users WHERE username = ?', (username,))
    row = cur.fetchone()
    conn.close()
    return bool(row)


def send_password_reset_message(username: str) -> str:
    """Mock password-reset sender for demo app with generic safe response."""
    exists = user_exists(username)
    if exists:
        logger.info("Password reset message queued for user '%s'", username)

    # Always return a generic message to avoid leaking which usernames exist.
    return "If this account exists, a password reset message has been sent."
