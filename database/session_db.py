import os
import logging
import requests
import sqlite3

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')


class SessionDB:
    def __init__(self, db_path='database/session_data.db'):
        self.db_path = db_path
        self.conn = None
        self.cursor = None
        self._ensure_db()

    def _ensure_db(self):
        try:
            db_exists = os.path.exists(self.db_path)
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.cursor = self.conn.cursor()
            if not db_exists:
                self._create_tables()
        except sqlite3.Error as e:
            logging.error(f"Database initialization error: {e}")

    def _create_tables(self):
        try:
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS session_data (
                    session_id TEXT PRIMARY KEY,
                    aes_key BLOB,
                    auth_token BLOB
                )
            ''')
            self.conn.commit()
        except sqlite3.Error as e:
            logging.error(f"Error creating tables: {e}")

    def store_session_data(self, session_id, aes_key, auth_token):
        try:
            self.cursor.execute('''
                INSERT OR REPLACE INTO session_data (session_id, aes_key, auth_token)
                VALUES (?, ?, ?)
            ''', (session_id, aes_key, auth_token))
            self.conn.commit()
        except sqlite3.Error as e:
            logging.error(f"Error storing session data for session_id={session_id}: {e}")

    def retrieve_session_data(self, session_id):
        """
        returns (aes_key : blob, auth_token: text)
        """
        try:
            self.cursor.execute('''
                SELECT aes_key, auth_token FROM session_data WHERE session_id = ?
            ''', (session_id,))
            row = self.cursor.fetchone()
            if row:
                return row  # returns (aes_key, auth_token)
            else:
                logging.warning(f"No session data found for session_id={session_id}")
                return None
        except sqlite3.Error as e:
            logging.error(f"Error retrieving session data for session_id={session_id}: {e}")
            return None

    def session_exists(self, session_id):
        try:
            self.cursor.execute('''
                SELECT 1 FROM session_data WHERE session_id = ? LIMIT 1
            ''', (session_id,))
            return self.cursor.fetchone() is not None
        except sqlite3.Error as e:
            logging.error(f"Error checking session existence for session_id={session_id}: {e}")
            return False

    def remove_session(self, session_id):
        """
        Deletes session data from the database.
        """
        try:
            self.cursor.execute('''
                DELETE FROM session_data WHERE session_id = ?
            ''', (session_id,))
            self.conn.commit()
            logging.info(f"Removed session data for session_id={session_id}")
        except sqlite3.Error as e:
            logging.error(f"Error removing session data for session_id={session_id}: {e}")

    def close(self):
        try:
            if self.conn:
                self.conn.close()
        except sqlite3.Error as e:
            logging.error(f"Error closing database: {e}")