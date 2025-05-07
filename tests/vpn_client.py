import socket
import time
from threading import Thread, Timer, Lock
import logging
from enum import Enum, auto
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from vpn.utils.encryption_methods import *
from vpn.utils.valid_ip import is_valid_ip
import requests
from requests.exceptions import RequestException
import os
from .vpn_protocol import vpn_protocol as proto
from .tcp_handshake_client import SecureTCPClient

from vpn import tun, ip, net

from enum import Enum, auto
from queue import Queue
from concurrent.futures import ThreadPoolExecutor


class VPNClient:
    def __init__(self, tun_device_name: str, tun_device_ip: str, server_address: tuple) -> None:
        self.tun_device_name = tun_device_name
        self.tun_device_ip = tun_device_ip
        self.server_address = server_address

        #cryptography Variables
        self.aes_key = None

        # Initialize the TUN device
        self.tun_dev = tun.Device(self.tun_device_name, self.tun_device_ip)

        # Initialize the socket for communication with the VPN server
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Placeholder for session data
        self.auth_token = None #Save it as a string but i can save it in bytes which is better ask nir
        self.session_id = None

        # Queue for packets
        self.packet_queue = Queue()

        # ThreadPoolExecutor for concurrent tasks
        self.executor = ThreadPoolExecutor(max_workers=2)
        self.lock = Lock()
        self.running = True

    def signup(self, domain:str, username, password, email):
        try:
            response = requests.post(f"https://{domain}:8443/signup", json={
                "username": username,
                "email": email,
                "password": password
            }, verify=False)
            return response
        except requests.RequestException as e:
            return e.response

    def receive_token(self, username: str, password: str, domain : str) -> bool:
        """Authenticate the user against the central server."""
        url = f"https://{domain}:8443/login"
        login_data = {
            "username": username,
            "password": password
        }

        try:
            response = requests.post(url, json=login_data, verify=False, timeout=5)
            response.raise_for_status()  # Raises HTTPError for bad responses (4xx or 5xx)

            data = response.json()
            self.auth_token = data.get("session_token")

            if self.auth_token:
                print("Login successful!")
                print("Auth Token:", self.auth_token)
                return True
            else:
                print("Login failed: No session token received.")
                return False

        except RequestException as e:
            print(f"Request error during login: {e}")
            return False
        except ValueError:
            # .json() raised an error, likely due to invalid JSON
            print("Login failed: Invalid response format (not JSON).")
            return False

    def handle_new_packet_proccessing(self, packet: bytes) -> bytes | None:
        """
            Processes an incoming VPN packet from the server.

            Steps:
            1. Verifies the HMAC to ensure the packet's integrity and authenticity.
            2. Decrypts the VPN payload using the client's session AES key.
            3. Checks if the decrypted content is an error message.
            - If it is, logs the error and discards the packet.
            4. Extracts and returns the encapsulated payload if valid.

            Returns:
                The decrypted inner payload (e.g., IP packet) if successful,
                or None if the packet is invalid, tampered, or contains an error message.
        """
        try:
            # Assume auth_token is valid for now
            encrypted_vpn_pkt = proto.extract_vpn_packet(packet, self.auth_token.encode())
            
            if encrypted_vpn_pkt is None:
                print("[!] HMAC verification failed — packet may be tampered or invalid.")
                return None

            # Attempt to decrypt the VPN packet
            decrypted_vpn_pkt = aes_decrypt(self.aes_key, encrypted_vpn_pkt)

            # Check for error message from server
            if decrypted_vpn_pkt.startswith(b"ERROR:"):
                print("[!] Server Error:", decrypted_vpn_pkt.decode())
                return None  # Or return the message if you want to propagate it

            # Extract and return the actual payload (without version byte)
            payload = proto.extract_payload(decrypted_vpn_pkt)
            return payload

        except Exception as e:
            print(f"[!] Packet processing error: {e}")
            return None

    def set_tun_dev_up (self):
        self.tun_dev.addr = self.tun_device_ip
        self.tun_dev.up()

    def receive_tun_ip(self, retries=3, timeout=2) -> str | None:
        def send_hello():
            """Send UDP HELLO to initiate IP request."""
            hello_pkt = proto.build_vpn_packet(b"UDP HELLO")
            encrypted = aes_encrypt(self.aes_key, hello_pkt)
            udp_pkt = proto.build_udp_packet(encrypted, self.auth_token.encode(), self.session_id)
            self.server_sock.sendto(udp_pkt, self.server_address)

        def send_ack():
            """Acknowledge successful receipt of TUN IP."""
            ack_pkt = proto.build_vpn_packet(b"TUN OK")
            encrypted = aes_encrypt(self.aes_key, ack_pkt)
            udp_pkt = proto.build_udp_packet(encrypted, self.auth_token.encode(), self.session_id)
            self.server_sock.sendto(udp_pkt, self.server_address)

        def handle_response(packet: bytes) -> str:
            """Decrypt and extract IP from server response."""
            enc_vpn_pkt = proto.extract_vpn_packet(packet, self.auth_token.encode())
            if enc_vpn_pkt is None:
                raise ValueError("[!] HMAC verification failed — packet may be tampered or invalid.")

            decrypted = aes_decrypt(self.aes_key, enc_vpn_pkt)
            if decrypted.startswith(b"ERROR:"):
                raise ValueError(f"[!] Server Error: {decrypted.decode()}")

            ip_bytes = proto.extract_payload(decrypted)
            ip_str = ip_bytes.decode()
            if not is_valid_ip(ip_str):
                raise ValueError(f"Invalid IP address received: {ip_str}")

            return ip_str

        attempt = 0
        while attempt < retries:
            try:
                send_hello()
                self.server_sock.settimeout(timeout)

                packet, _ = self.server_sock.recvfrom(4096)
                tun_ip = handle_response(packet)
                send_ack()

                return tun_ip

            except (socket.timeout, Exception) as e:
                logging.warning(f"[Attempt {attempt + 1}/{retries}] Failed to receive TUN IP: {e}")
                attempt += 1
                time.sleep(1)

            finally:
                self.server_sock.settimeout(None)  # Always restore blocking mode

        logging.error("Exceeded maximum retries to receive TUN IP.")
        return None

    def start(self) -> None:
        """Start the VPN client."""
        try:
            tun_ip = self.receive_tun_ip()
            if not tun_ip: #TODO error
                logging.info("Unable to receive tun ip, using fallback ip.")
            else:
                # self.tun_device_ip = tun_ip
                pass

            print(f"TUN IP is: {self.tun_device_ip}")
            self.set_tun_dev_up()

            response_thread = Thread(target=self.on_response, daemon=True)
            response_thread.start()

            while self.running:
                try:
                    packet = self.tun_dev.read()
                    self.packet_queue.put(packet)
                    self.executor.submit(self.process_packet_from_queue)
                except Exception as e:
                    logging.error(f"Error reading from TUN device: {e}")
                    break
        finally:
            self.running = False
            self.server_sock.close()
            self.executor.shutdown(wait=True)
            logging.info("VPN Client shut down.")

    def process_packet_from_queue(self):
        """Process packets from the queue."""
        while not self.packet_queue.empty():
            try:
                packet = self.packet_queue.get()
                vpn_pkt = proto.build_vpn_packet(packet)
                encrypted_vpn_pkt = aes_encrypt(self.aes_key, vpn_pkt)
                udp_pkt = proto.build_udp_packet(encrypted_vpn_pkt, self.auth_token.encode(), self.session_id)

                self.server_sock.sendto(udp_pkt, self.server_address)
            except Exception as e:
                logging.error(f"Failed to process/send packet: {e}")

    def on_response(self) -> None:
        """Handle incoming responses from the VPN server."""
        while True:
            try:
                packet, addr = self.server_sock.recvfrom(4096)
                logging.info("Received packet from server")
                payload = self.handle_new_packet_proccessing(packet)
                if payload is not None:
                    try:
                        self.tun_dev.write(payload)
                    except Exception as e:
                        logging.error(f"Failed to write to TUN device: {e}")
            except socket.error as e:
                logging.error(f"Socket error in response thread: {e}")
                break

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def main() -> None:
    # Server address to connect to
    server_addr = ('127.0.0.1', 3000)

    # Initialize and start the VPN client
    vpn_client = VPNClient(tun_device_name='tun1', tun_device_ip='10.1.0.1', server_address=server_addr)

    # User credentials for login
    test = "test"
    vpn_client.receive_token(test, test, "localhost")

    #Handshake
    client = SecureTCPClient(auth_token=vpn_client.auth_token)
    vpn_client.session_id, vpn_client.aes_key = client.perform()

    print("[*] Client connection closed.")
    vpn_client.start()


if __name__ == '__main__':
    main()