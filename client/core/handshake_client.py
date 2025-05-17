import socket
import os
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import threading


class TCPClient:
    """
    TCPClient handles a secure Diffie-Hellman handshake with the server
    using asymmetric key exchange and AES symmetric encryption.
    """

    def __init__(self, host='127.0.0.1', port=4443, auth_token="sample_token"):
        """
        Initialize the TCP client.

        Args:
            host (str): Server IP address.
            port (int): Server TCP port.
            auth_token (str): Authentication token to identify the client.
        """
        self.host = host
        self.port = port
        self.auth_token = auth_token
        self.shared_key = None
        self.socket = None

    def __del__(self):
        print("Handshake instance deleted")

    def _encrypt(self, key, plaintext):
        """
        Encrypt plaintext using AES-CFB mode.

        Args:
            key (bytes): AES key.
            plaintext (bytes): Data to encrypt.

        Returns:
            bytes: IV + ciphertext.
        """
        try:
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
            encryptor = cipher.encryptor()
            return iv + encryptor.update(plaintext) + encryptor.finalize()
        except Exception as e:
            print(f"[!] Encryption error: {e}")
            return b""

    def _decrypt(self, key, ciphertext):
        """
        Decrypt AES-CFB encrypted ciphertext.

        Args:
            key (bytes): AES key.
            ciphertext (bytes): IV + encrypted data.

        Returns:
            bytes: Decrypted plaintext.
        """
        try:
            iv = ciphertext[:16]
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
            decryptor = cipher.decryptor()
            return decryptor.update(ciphertext[16:]) + decryptor.finalize()
        except Exception as e:
            print(f"[!] Decryption error: {e}")
            return b""

    def _derive_key(self, shared_key):
        """
        Derive a 256-bit key from a shared secret using HKDF.

        Args:
            shared_key (bytes): The shared key from DH key exchange.

        Returns:
            bytes: Derived AES key.
        """
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
        """
        Receive exact number of bytes from the socket.

        Args:
            length (int): Number of bytes to receive.

        Returns:
            bytes: Received data.
        """
        data = b""
        while len(data) < length:
            chunk = self.socket.recv(length - len(data))
            if not chunk:
                raise ConnectionError("Socket connection broken")
            data += chunk
        return data

    def perform(self):
        """
        Perform the full client-side handshake:
        - Sends hello
        - Receives server public key
        - Sends client public key and token
        - Derives AES key
        - Exchanges encrypted messages

        Returns:
            tuple: (server reply, shared AES key) on success, None otherwise
        """
        try:
            # Establish TCP connection
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
        except Exception as e:
            print(f"[!] Connection error: {e}")
            return

        try:
            # Step 1: Send "Client Hello"
            self.socket.sendall(b"Client Hello")

            # Step 2: Receive server's public key (PEM format)
            server_pub_pem = b""
            while True:
                chunk = self.socket.recv(1024)
                server_pub_pem += chunk
                if b"END PUBLIC KEY-----" in chunk:
                    break

            # Load server's public key
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

            # Step 4: Send auth_token with length prefix
            token_length = len(self.auth_token).to_bytes(4, byteorder='big')
            self.socket.sendall(token_length + self.auth_token.encode('utf-8'))

            # Step 5: Perform key exchange
            shared_key = private_key.exchange(server_public_key)
            self.shared_key = self._derive_key(shared_key)
            if not self.shared_key:
                return

            # Step 6: Send encrypted test message
            message = b"Hello from secure client!"
            encrypted_message = self._encrypt(self.shared_key, message)
            msg_len = len(encrypted_message).to_bytes(4, byteorder='big')
            self.socket.sendall(msg_len + encrypted_message)

            # Step 7: Receive and decrypt reply
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
        """
        Cleanly close the socket connection.
        """
        try:
            if self.socket:
                self.socket.close()
        except Exception as e:
            print(f"[!] Socket close error: {e}")


def main():
    """
    Entry point for running handshake manually (test mode).
    """
    auth_token = None
    client = TCPClient(auth_token=auth_token)
    client.perform()
    print("[*] Client connection closed.")


if __name__ == '__main__':
    main()