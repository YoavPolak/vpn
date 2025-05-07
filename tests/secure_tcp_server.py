import socket
import os
import logging
import uuid
import json
import requests
import sqlite3
import threading
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')


class SecureDatabase:
    def __init__(self, db_path='session_data.db'):
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


class SecureTCPServer:
    def __init__(self, host='0.0.0.0', port=4443):
        self.host = host
        self.port = port
        self.socket = None
        self.db = SecureDatabase()

        self.parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
        self.private_key = self.parameters.generate_private_key()
        self.public_key = self.private_key.public_key()

    def _encrypt(self, key, plaintext):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        return iv + encryptor.update(plaintext) + encryptor.finalize()

    def _decrypt(self, key, ciphertext):
        iv = ciphertext[:16]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext[16:]) + decryptor.finalize()

    def _derive_key(self, shared_key):
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_key)

    def _recv_all(self, conn, length):
        data = b""
        while len(data) < length:
            chunk = conn.recv(length - len(data))
            if not chunk:
                raise ConnectionError("Socket connection broken")
            data += chunk
        return data

    def verify_auth_token(self, auth_token: str) -> bool:
        url = "https://localhost:8443/validate_token"
        data = {'token': auth_token}
        try:
            response = requests.post(url, json=data, verify=False)
            return response.status_code == 200
        except Exception as e:
            logging.error(f"Token verification failed: {e}")
            return False

    def handle_connection(self, conn, addr):
        try:
            with conn:
                client_hello = conn.recv(1024).decode('utf-8')
                if client_hello != "Client Hello":
                    conn.sendall(b"ERROR: Invalid Client Hello.")
                    return

                # Send server's public key
                server_pub = self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                conn.sendall(server_pub)

                # Receive client public key
                client_pub_pem = b""
                while True:
                    chunk = conn.recv(1024)
                    client_pub_pem += chunk
                    if b"END PUBLIC KEY-----" in chunk:
                        break

                client_public_key = serialization.load_pem_public_key(client_pub_pem, backend=default_backend())

                # Receive auth token
                token_length = int.from_bytes(self._recv_all(conn, 4), byteorder='big')
                auth_token = self._recv_all(conn, token_length).decode('utf-8')
                logging.info(f"[{addr}] Received auth token.")

                if not self.verify_auth_token(auth_token):
                    conn.sendall(b"ERROR: Token verification failed.")
                    return

                session_id = str(uuid.uuid4())
                shared_key = self.private_key.exchange(client_public_key)
                client_shared_key = self._derive_key(shared_key)
                self.db.store_session_data(session_id, client_shared_key, auth_token)
                logging.info(f"[{addr}] Stored session {session_id}")

                # Receive encrypted message with length prefix
                encrypted_msg_len = int.from_bytes(self._recv_all(conn, 4), byteorder='big')
                encrypted_msg = self._recv_all(conn, encrypted_msg_len)
                try:
                    message = self._decrypt(client_shared_key, encrypted_msg)
                    logging.info(f"[{addr}] Message from session {session_id}: {message.decode()}")
                except Exception:
                    error = self._encrypt(client_shared_key, b"ERROR: Message decryption failed.")
                    conn.sendall(len(error).to_bytes(4, byteorder='big') + error)
                    return

                # Send encrypted reply (length-prefixed)
                reply = session_id.encode()
                encrypted_reply = self._encrypt(client_shared_key, reply)
                reply_len = len(encrypted_reply).to_bytes(4, byteorder='big')
                conn.sendall(reply_len + encrypted_reply)

        except Exception as e:
            logging.error(f"[{addr}] Exception: {e}")
            try:
                conn.sendall(b"ERROR: Internal server error.")
            except:
                pass

    def start(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        print(f"[+] SecureTCPServer listening on {self.host}:{self.port}")

        try:
            while True:
                conn, addr = self.socket.accept()
                print(f"[+] Connection from {addr}")
                threading.Thread(target=self.handle_connection, args=(conn, addr), daemon=True).start()
        except KeyboardInterrupt:
            print("\n[!] Server interrupted.")
        finally:
            self.close()

    def close(self):
        if self.socket:
            self.socket.close()
        self.db.close()
        print("[*] Server shut down.")

def main():
    server = SecureTCPServer()
    server.start()

if __name__ == '__main__':
    main()
#Maybe add a function in the db to ask for a new ip addr
#TODO add ip thing here too and send it to the client