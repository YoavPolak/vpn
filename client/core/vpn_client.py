import socket
import time
from threading import Thread, Lock
import logging
from typing import Tuple
import requests
from requests.exceptions import RequestException
import os
from queue import Queue
from concurrent.futures import ThreadPoolExecutor

# Module imports
from vpn.protocol.vpn_protocol import VPNProtocol as proto
from .handshake_client import TCPClient
from utils.encryption_methods import aes_decrypt, aes_encrypt
from utils.valid_ip import is_valid_ip

from vpn import tun, ip, net

# Constants
BUFFER_SIZE = 65535  # Max UDP packet size
class VPNClient:
    """
    A class to represent a VPN client.
    
    Manages TUN interface communication, encryption/decryption,
    and VPN server interaction via UDP and TCP.
    """

    def __init__(self, tun_device_name: str, tun_device_ip: str, server_address: tuple) -> None:
        """
        Initialize the VPN client.
        
        Args:
            tun_device_name (str): Name of the TUN device.
            tun_device_ip (str): IP address assigned to the TUN device.
            server_address (tuple): Tuple of server IP and port.
        """
        self.tun_device_name = tun_device_name
        self.tun_device_ip = tun_device_ip
        self.server_address = server_address

        # Cryptographic key used for session
        self.aes_key = None

        # TUN device setup
        self.tun_dev = tun.Device(self.tun_device_name, self.tun_device_ip)

        # Socket for communication with VPN server (UDP)
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Authentication/session
        self.auth_token = None  # Consider using bytes instead of string
        self.session_id = None

        # Thread-safe queue for outgoing packets
        self.packet_queue = Queue()

        # ThreadPoolExecutor to handle concurrent packet sending
        self.executor = ThreadPoolExecutor(max_workers=2)
        self.lock = Lock()
        self.running = True

        self.prod = False

    def signup(self, domain: str, username, password, email):
        """
        Sign up a new user via the central server.
        
        Args:
            domain (str): Domain name of the auth server.
        """
        try:
            response = requests.post(
                f"https://{domain}:8443/signup",
                json={"username": username, "email": email, "password": password},
                verify=False
            )
            return response
        except requests.RequestException as e:
            return e.response

    def receive_token(self, username: str, password: str, domain: str) -> bool:
        """
        Authenticate user and receive a session token.
        
        Returns:
            bool: True if authentication was successful, else False.
        """
        url = f"https://{domain}:8443/login"
        login_data = {"username": username, "password": password}

        try:
            response = requests.post(url, json=login_data, verify=False, timeout=5)
            response.raise_for_status()

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
            print("Login failed: Invalid response format (not JSON).")
            return False

    def handle_new_packet_proccessing(self, packet: bytes) -> bytes | None:
        """
        Process an incoming packet from the VPN server.

        Decrypts and validates payload, returning original IP packet if valid.
        
        Args:
            packet (bytes): Incoming UDP VPN packet.
            
        Returns:
            bytes | None: Decrypted payload or None if invalid.
        """
        try:
            encrypted_vpn_pkt = proto.extract_vpn_packet(packet, self.auth_token.encode())
            if encrypted_vpn_pkt is None:
                print("[!] HMAC verification failed — packet may be tampered or invalid.")
                return None

            decrypted_vpn_pkt = aes_decrypt(self.aes_key, encrypted_vpn_pkt)

            if decrypted_vpn_pkt.startswith(b"ERROR:"):
                print("[!] Server Error:", decrypted_vpn_pkt.decode())
                return None

            payload = proto.extract_payload(decrypted_vpn_pkt)
            return payload

        except Exception as e:
            print(f"[!] Packet processing error: {e}")
            return None

    def set_tun_dev_up(self):
        """
        Set up and activate the TUN device.
        """
        self.tun_dev.addr = self.tun_device_ip
        self.tun_dev.up()

    def receive_tun_ip(self, retries=3, timeout=2) -> str | None:
        """
        Obtain the TUN device IP address from the server.
        
        Args:
            retries (int): Max number of retry attempts.
            timeout (int): Timeout in seconds for UDP response.

        Returns:
            str | None: IP address assigned by the server or None.
        """
        def send_hello():
            hello_pkt = proto.build_vpn_packet(b"UDP HELLO")
            encrypted = aes_encrypt(self.aes_key, hello_pkt)
            udp_pkt = proto.build_udp_packet(encrypted, self.auth_token.encode(), self.session_id)
            self.server_sock.sendto(udp_pkt, self.server_address)

        def send_ack():
            ack_pkt = proto.build_vpn_packet(b"TUN OK")
            encrypted = aes_encrypt(self.aes_key, ack_pkt)
            udp_pkt = proto.build_udp_packet(encrypted, self.auth_token.encode(), self.session_id)
            self.server_sock.sendto(udp_pkt, self.server_address)

        def handle_response(packet: bytes) -> str:
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
                self.server_sock.settimeout(None)

        logging.error("Exceeded maximum retries to receive TUN IP.")
        return None

    def start(self) -> None:
        """
        Start the VPN client event loop. This reads packets from TUN,
        encrypts and sends them to the VPN server, while listening
        to responses in a background thread.
        """
        try:
            tun_ip = self.receive_tun_ip()
            if not tun_ip:
                logging.info("Unable to receive TUN IP, using fallback IP.")
            else:
                # Future use: dynamically assign the IP
                if self.prod:
                    self.tun_device_ip = tun_ip #TODO

            print(f"TUN IP is: {self.tun_device_ip}")
            print(f"Actual TUN IP is: {tun_ip}")
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
            self.executor.shutdown(wait=True)

            if self.server_sock:
                self.server_sock.close()
                self.server_sock = None

            if self.tun_dev:
                self.tun_dev.close()
                self.tun_dev = None

            logging.info("VPN Client shut down.")

    def process_packet_from_queue(self):
        """
        Fetch a packet from the queue and send it to the server.
        """
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
        """
        Listen for UDP packets from the VPN server and write them to TUN.
        """
        while self.running:
            try:
                packet, addr = self.server_sock.recvfrom(BUFFER_SIZE)
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


# Disable certificate warnings for testing/development
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def main() -> None:
    """
    Entry point of the VPN client program.
    
    Performs login, handshake, and starts the VPN event loop.
    """
    server_addr = ('127.0.0.1', 3000)

    vpn_client = VPNClient(
        tun_device_name='tun1',
        tun_device_ip='10.1.0.1',
        server_address=server_addr
    )

    # Example login credentials
    test = "test"
    vpn_client.receive_token(test, test, "localhost")

    # Perform handshake to receive session ID and encryption key
    client = TCPClient(auth_token=vpn_client.auth_token)
    vpn_client.session_id, vpn_client.aes_key = client.perform()

    print("[*] Client connection closed.")
    vpn_client.start()


if __name__ == '__main__':
    main()
