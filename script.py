import socket
from threading import Thread
import logging
from enum import Enum, auto
import time
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from vpn.utils.encryption_methods import *
from vpn.utils.valid_ip import is_valid_ip
import requests
from requests.exceptions import RequestException
import os
from .vpn_protocol import vpn_protocol as proto

from vpn import tun, ip, net

from enum import Enum, auto
from queue import Queue
from concurrent.futures import ThreadPoolExecutor
import select

class State(Enum):
    UNINITIALIZED = auto()         # No attempt yet
    HANDSHAKE_STARTED = auto()     # Sent initial request
    TOKEN_RECEIVED = auto()        # Got token from central server
    AUTHENTICATED = auto()         # Token validated, handshake successed, ready to proceed
    FAILED = auto()                # Some failure happened
    TIMEOUT = auto()               # Request timed out
    INVALID_RESPONSE = auto()      # Server sent junk

#Need to add ERROR HANDLING
class VPNClient:
    #Add state handling too
    # INITIAL, HANDSHAKE, SECURED...
    def __init__(self, tun_device_name: str, tun_device_ip: str, server_address: tuple) -> None:
        self.tun_device_name = tun_device_name
        self.tun_device_ip = tun_device_ip
        self.server_address = server_address

        #cryptography Variables
        self._private_key, self._public_key = generate_rsa_keys()
        self.aes_key = None

        # Initialize the TUN device
        self.tun_dev = tun.Device(self.tun_device_name, self.tun_device_ip)

        # Initialize the socket for communication with the VPN server
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Placeholder for session token
        self.session_token = None #In the server it's called auth_token so change it later #TODO

        #init state
        self.state: State = State.UNINITIALIZED

        # Queue for packets
        self.packet_queue = Queue()

        # ThreadPoolExecutor for concurrent tasks
        self.executor = ThreadPoolExecutor(max_workers=2)

    def signup(self, domain:str, username, password, email):
        try:
            response = requests.post(f"http://{domain}:8000/signup", json={
                "username": username,
                "email": email,
                "password": password
            })
            print(response.json())
            return response.status_code == 200
        except:
            return False

    def receive_token(self, username: str, password: str, domain : str) -> bool:
        """Authenticate the user against the central server."""
        url = f"http://{domain}:8000/login"
        login_data = {
            "username": username,
            "password": password
        }

        try:
            response = requests.post(url, json=login_data, timeout=5)
            response.raise_for_status()  # Raises HTTPError for bad responses (4xx or 5xx)

            data = response.json()
            self.session_token = data.get("session_token")

            if self.session_token:
                print("Login successful!")
                print("Session Token:", self.session_token)
                self.state = State.TOKEN_RECEIVED
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

    def handle_handshake(self): #TODO Need to handle error cases
        try:
            sock = self.server_sock
            sock.sendto(proto.PROTO_VERSION, self.server_address)

            serialized_server_public_key, _ = sock.recvfrom(4096)
            server_public_key = serialization.load_pem_public_key(serialized_server_public_key)
            self.aes_key = os.urandom(32)  # AES-256 key
            #Client Packet -> rsa_encrypted[ VPN1|AES_Key|Session_Token|Public_Client_key ]

            # Create the message to send (including AES key, session token, and public key)
            serialized_public_key = self._public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            handshake_response = self.build_handshake_response(server_public_key, serialized_public_key)
            
            # Send the encrypted message
            print("Sending encrypted message...")
            sock.sendto(handshake_response, self.server_address)

            res, _ = sock.recvfrom(4096)  #From now on, all communication is encrypted with aes 256
            if(res.startswith(b'ERROR')):#TODO finish this weird error handaling
                raise Exception
            print(res) #Check for errors
            decrypted_res = aes_decrypt(self.aes_key, res)
            print(decrypted_res)
            if (not decrypted_res.startswith(b"Handshake successful.")): raise Exception

            tun_ip = decrypted_res.split(b"\n\n")[1].decode()
            if not is_valid_ip(tun_ip):
                raise ValueError(f"Invalid IP address provided: {tun_ip}")

            self.tun_device_ip = tun_ip

            self.state = State.AUTHENTICATED #Client is authenticated to the vpn server
        except Exception as e:
            print("Handshake failed.")
            print(f"Error from server: {res.decode()}")
            print(f"Provided error: {e}")

    def build_handshake_response(self, server_public_key, serialized_public_key) -> bytes:#TODO: Maybe change the 'VPN1'
        encrypted_aes_key = encrypt_with_rsa(server_public_key, self.aes_key)
        encrypted_session_token = encrypt_with_rsa(server_public_key, self.session_token.encode())

        return proto.PROTO_VERSION + b"\n\n" + encrypted_aes_key + b"\n\n" + encrypted_session_token + b"\n\n" + serialized_public_key

    def handle_new_packet_proccessing(self, packet: bytes) -> bytes | None:
        try:
            encrypted_vpn_pkt = proto.extract_vpn_packet(packet, self.session_token.encode()) 
            if encrypted_vpn_pkt == None: return None
            decrypted_vpn_pkt = aes_decrypt(self.aes_key, encrypted_vpn_pkt)
            payload = proto.extract_payload(decrypted_vpn_pkt)
            return payload
        except Exception as e:
            print(e)
    
    def set_tun_dev_up (self, tun_ip : str = '10.1.0.1'):
        self.tun_dev.addr = tun_ip
        self.tun_dev.up()

    def login(self, username: str, password: str, domain : str):
            if self.state == State.UNINITIALIZED:
                self.receive_token(username, password, "localhost")
            if self.state == State.TOKEN_RECEIVED:
                self.handle_handshake()

    def disconnect(self):
        sock = self.server_sock
        sock.sendto(b'', self.server_address)
        print("Disconnected")
        self.state = State.TOKEN_RECEIVED

    def start(self) -> None:
        """Start the VPN client."""
        self.set_tun_dev_up()

        # Use select to ensure non-blocking operation with socket
        response_thread = Thread(target=self.on_response)
        response_thread.start()

        while True:
            packet = self.tun_dev.read()
            self.packet_queue.put(packet)  
            self.executor.submit(self.process_packet_from_queue)
            time.sleep(0.01)  # Add a slight delay to avoid busy waiting and reduce CPU usage

        response_thread.join()
        self.server_sock.close()

    def process_packet_from_queue(self):
        while not self.packet_queue.empty():
            packet = self.packet_queue.get() 
            vpn_pkt = proto.build_vpn_packet(packet)
            encrypted_vpn_pkt = aes_encrypt(self.aes_key, vpn_pkt)
            udp_pkt = proto.build_udp_packet(encrypted_vpn_pkt, self.session_token.encode())
            self.server_sock.sendto(udp_pkt, self.server_address)

    def on_response(self) -> None:
        """Handle incoming responses from the VPN server."""
        while True:
            ready = select.select([self.server_sock], [], [], 1)
            if ready[0]:
                packet, addr = self.server_sock.recvfrom(4069)
                payload = self.handle_new_packet_proccessing(packet)
                if payload != None:
                    self.tun_dev.write(payload)

