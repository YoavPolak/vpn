import socket
import os
import logging
import uuid
import json
import requests
import threading
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
#TODO import db

from database.session_db import SessionDB

class TCPServer:
    def __init__(self, host='0.0.0.0', port=4443):
        self.host = host
        self.port = port
        self.socket = None
        self.db = SessionDB()

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
        print(f"[TCP] Server listening on {self.host}:{self.port}")

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
    try:
        server = TCPServer()
        server.start()
    except Exception as e:
        logging.exception("Fatal error in tcp server main")

if __name__ == '__main__':
    main()