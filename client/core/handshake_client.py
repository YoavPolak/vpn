import socket
import os
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import threading


class TCPClient:
    def __init__(self, host='127.0.0.1', port=4443, auth_token="sample_token"):
        self.host = host
        self.port = port
        self.auth_token = auth_token
        self.shared_key = None
        self.socket = None

    def __del__(self):
        print("Handshake instance deleted")

    def _encrypt(self, key, plaintext):
        try:
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
            encryptor = cipher.encryptor()
            return iv + encryptor.update(plaintext) + encryptor.finalize()
        except Exception as e:
            print(f"[!] Encryption error: {e}")
            return b""

    def _decrypt(self, key, ciphertext):
        try:
            iv = ciphertext[:16]
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
            decryptor = cipher.decryptor()
            return decryptor.update(ciphertext[16:]) + decryptor.finalize()
        except Exception as e:
            print(f"[!] Decryption error: {e}")
            return b""

    def _derive_key(self, shared_key):
        try:
            return HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
                backend=default_backend()
            ).derive(shared_key)
        except Exception as e:
            print(f"[!] Key derivation error: {e}")
            return None

    def _recv_all(self, length):
        """Ensure full data of specific length is received."""
        data = b""
        while len(data) < length:
            chunk = self.socket.recv(length - len(data))
            if not chunk:
                raise ConnectionError("Socket connection broken")
            data += chunk
        return data

    def perform(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
        except Exception as e:
            print(f"[!] Connection error: {e}")
            return

        try:
            # Step 1: Send "Client Hello"
            self.socket.sendall(b"Client Hello")

            # Step 2: Receive server's public key
            server_pub_pem = b""
            while True:
                chunk = self.socket.recv(1024)
                server_pub_pem += chunk
                if b"END PUBLIC KEY-----" in chunk:
                    break

            try:
                server_public_key = serialization.load_pem_public_key(server_pub_pem, backend=default_backend())
            except Exception as e:
                print(f"[!] Failed to load server public key: {e}")
                return

            # Step 3: Generate client key pair
            parameters = server_public_key.parameters()
            private_key = parameters.generate_private_key()
            public_key = private_key.public_key()

            client_pub_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            self.socket.sendall(client_pub_pem)

            # Step 4: Send the auth_token to the server
            token_length = len(self.auth_token).to_bytes(4, byteorder='big')
            self.socket.sendall(token_length + self.auth_token.encode('utf-8'))

            # Step 5: Derive shared key
            shared_key = private_key.exchange(server_public_key)
            self.shared_key = self._derive_key(shared_key)
            if not self.shared_key:
                return

            # Step 6: Send encrypted message with length prefix
            message = b"Hello from secure client!"
            encrypted_message = self._encrypt(self.shared_key, message)
            msg_len = len(encrypted_message).to_bytes(4, byteorder='big')
            self.socket.sendall(msg_len + encrypted_message)

            # Step 7: Receive encrypted reply with length prefix
            reply_len_bytes = self._recv_all(4)
            reply_len = int.from_bytes(reply_len_bytes, byteorder='big')
            encrypted_reply = self._recv_all(reply_len)
            reply = self._decrypt(self.shared_key, encrypted_reply)

            if reply.startswith(b"ERROR:"):
                print(f"[!] Server Error: {reply.decode()}")
            else:
                print("[+] Server response:", reply.decode())
                return reply, self.shared_key

        except Exception as e:
            print(f"[!] Client error: {e}")
        finally:
            self.close()

    def close(self):
        try:
            if self.socket:
                self.socket.close()
        except Exception as e:
            print(f"[!] Socket close error: {e}")

def main():
    auth_token = None
    client = TCPClient(auth_token=auth_token)
    client.perform()
    print("[*] Client connection closed.")

if __name__ == '__main__':
    main()
