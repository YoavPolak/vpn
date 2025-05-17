import os
import logging
from threading import Lock
from sqlcipher3 import dbapi2 as sqlite  # Use sqlcipher3 for encrypted SQLite

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

class SessionDB:
    """
    A thread-safe class for managing encrypted session data using SQLCipher.
    Stores session_id, AES key, and authentication token.
    """
    def __init__(self, db_path='database/session_data.db', encryption_key="my_encryption_key"):
        """
        Initialize the SessionDB instance.
        Creates the encrypted database and tables if they do not exist.
        """
        self.db_path = db_path
        self.conn = None
        self.cursor = None
        self._lock = Lock()
        # Get encryption key from env or argument
        self.encryption_key = encryption_key or os.environ.get('SQLCIPHER_KEY')
        if not self.encryption_key:
            raise ValueError("Encryption key must be provided via argument or SQLCIPHER_KEY environment variable.")
        self._ensure_db()

    def _ensure_db(self):
        """
        Ensure the encrypted database exists and is initialized.
        """
        try:
            db_exists = os.path.exists(self.db_path)
            # Connect using sqlcipher3
            self.conn = sqlite.connect(self.db_path, check_same_thread=False)
            # Set the encryption key
            self.conn.execute(f"PRAGMA key = '{self.encryption_key}';")
            self.cursor = self.conn.cursor()
            if not db_exists:
                self._create_tables()
        except sqlite.Error as e:
            logging.error(f"Database initialization error: {e}")

    def _create_tables(self):
        """
        Create the session_data table if it doesn't exist.
        """
        try:
            with self._lock:
                self.cursor.execute('''
                    CREATE TABLE IF NOT EXISTS session_data (
                        session_id TEXT PRIMARY KEY,
                        aes_key BLOB,
                        auth_token BLOB
                    )
                ''')
                self.conn.commit()
        except sqlite.Error as e:
            logging.error(f"Error creating tables: {e}")

    def store_session_data(self, session_id, aes_key, auth_token):
        """
        Store or update session data for a given session_id.
        """
        try:
            with self._lock:
                self.cursor.execute('''
                    INSERT OR REPLACE INTO session_data (session_id, aes_key, auth_token)
                    VALUES (?, ?, ?)
                ''', (session_id, aes_key, auth_token))
                self.conn.commit()
        except sqlite.Error as e:
            logging.error(f"Error storing session data for session_id={session_id}: {e}")

    def retrieve_session_data(self, session_id):
        """
        Retrieve AES key and auth token for a given session_id.
        Returns:
            tuple: (aes_key, auth_token) if found, else None
        """
        try:
            with self._lock:
                self.cursor.execute('''
                    SELECT aes_key, auth_token FROM session_data WHERE session_id = ?
                ''', (session_id,))
                row = self.cursor.fetchone()
                if row:
                    return row
                else:
                    logging.warning(f"No session data found for session_id={session_id}")
                    return None
        except sqlite.Error as e:
            logging.error(f"Error retrieving session data for session_id={session_id}: {e}")
            return None

    def session_exists(self, session_id):
        """
        Check if a session exists for the given session_id.
        Returns:
            bool: True if session exists, False otherwise.
        """
        try:
            with self._lock:
                self.cursor.execute('''
                    SELECT 1 FROM session_data WHERE session_id = ? LIMIT 1
                ''', (session_id,))
                return self.cursor.fetchone() is not None
        except sqlite.Error as e:
            logging.error(f"Error checking session existence for session_id={session_id}: {e}")
            return False

    def remove_session(self, session_id):
        """
        Delete session data for the given session_id from the database.
        """
        try:
            with self._lock:
                self.cursor.execute('''
                    DELETE FROM session_data WHERE session_id = ?
                ''', (session_id,))
                self.conn.commit()
                logging.info(f"Removed session data for session_id={session_id}")
        except sqlite.Error as e:
            logging.error(f"Error removing session data for session_id={session_id}: {e}")

    def close(self):
        """
        Close the database connection safely.
        """
        try:
            with self._lock:
                if self.conn:
                    self.conn.close()
        except sqlite.Error as e:
            logging.error(f"Error closing database: {e}")
