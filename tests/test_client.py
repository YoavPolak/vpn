import socket
from threading import Thread, Timer
import logging
from enum import Enum
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from vpn.utils.encryption_methods import *
import requests
import os
from .vpn_protocol import vpn_protocol as proto

from vpn import tun, ip, net
#Need to add ERROR HANDLING
class VPNClient:
    #Add state handling too
    # INITIAL, HANDSHAKE, SECURED...
    def __init__(self, tun_device_name: str, tun_device_ip: str, server_address: tuple, username: str, password: str) -> None:
        self.tun_device_name = tun_device_name
        self.tun_device_ip = tun_device_ip
        self.server_address = server_address
        self.username = username
        self.password = password

        #cryptography Variables
        self._private_key, self._public_key = generate_rsa_keys()
        self._aes_key = None

        # Initialize the TUN device
        self.tun_dev = tun.Device(self.tun_device_name, self.tun_device_ip)

        # Initialize the socket for communication with the VPN server
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Placeholder for session token
        self.session_token = None #In the server it called auth_token so change it later #TODO

        #VPN Headers
        self.proto_version = b"VPN1"

    def _signup(self) -> bool:
        url = f"{BASE_URL}/signup"
        payload = {
            "username": "testuser1",
            "password": "testpassword"
        }
        
        response = requests.post(url, json=payload)
        print("Signup Response:", response.json())
        return response.status_code == 200

    def _login(self) -> bool:
        """Authenticate the user against the central server."""
        url = "http://localhost:8000/login"

        # Define the login credentials
        login_data = {
            "username": self.username, 
            "password": self.password
        }

        # Send the POST request to the central server
        response = requests.post(url, json=login_data)

        # Check if the request was successful
        if response.status_code == 200:
            # Successfully authenticated, handle the response (e.g., extract session token)
            data = response.json()
            self.session_token = data.get("session_token")
            print("Login successful!")
            print("Session Token:", self.session_token)
            return True
        else:
            # Authentication failed
            print("Login failed:", response.json().get("detail"))
            return False

    def handle_handshake(self) -> bool: #TODO Need to handle error cases
        try:
            sock = self.server_sock
            sock.sendto(b"VPN1", self.server_address)

            serialized_server_public_key, _ = sock.recvfrom(4096)
            server_public_key = serialization.load_pem_public_key(serialized_server_public_key)
            self.aes_key = os.urandom(32)  # AES-256
            #Client Packet -> rsa_encrypted[ VPN1|AES_Key|Session_Token|Public_Client_key ]

            # Create the message to send (including AES key, session token, and public key)
            serialized_public_key = self._public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            #TODO Build a real function to create this data e.g build_handshake_response
            msg = b"VPN1\n\n" + encrypt_with_rsa(server_public_key, self.aes_key) + b"\n\n" + encrypt_with_rsa(server_public_key, self.session_token.encode()) + b"\n\n" + serialized_public_key
            # Send the encrypted message
            print("Sending encrypted message...")
            sock.sendto(msg, self.server_address)

            res, _ = sock.recvfrom(4096)  #From now on, all communication is encrypted with aes 256
            if(res.startswith(b'ERROR')): # TODO MTU TO READ 1504
                raise Exception
            print(res) #Check for errors
            print(aes_decrypt(self.aes_key, res))
            return True
        except Exception as e:
            print(f"Error from server: {res.decode()}")
            return False

    def build_handshake_response(self, ) -> bytes:
        pass

    def handle_new_packet_proccessing(self, packet: bytes) -> bytes | None:
        #Need to add the logic of checking if the packet is correct using the vpn_protocol
        #1. Will use extract_vpn_packet(packet, client_auth_token) -> encrypted payload
        #2. decrypt packet using shared aes key with the client
        #3. protocl.extract_payload(packet) -> inner_packet
        #forward it to the right function
        try:
            # FOR NOW I assume all auth_tokens are not expired yet.
            encrypted_vpn_pkt = proto.extract_vpn_packet(packet, self.session_token.encode()) #Returns the encrypted vpn_packet, with aes encryption
            if encrypted_vpn_pkt == None: return None #Handle bad hmac or dont forward it idk
            decrypted_vpn_pkt = aes_decrypt(self.aes_key, encrypted_vpn_pkt)
            payload = proto.extract_payload(decrypted_vpn_pkt)
            return payload
        except Exception as e:
            print(e)
           
    def start(self) -> None:
        """Start the VPN client."""
        # First, authenticate the user
        if not self._login():
            return  # Stop if login fails
        if not self.handle_handshake():
            return

        # Bring the TUN device up
        #TODO Implement the things that it takes the ip from the server or something but it might not be neccessery
        self.tun_dev.up()

        # Create a separate thread to handle the response from the server
        response_thread = Thread(target=self.on_response)
        response_thread.start()

        # Main loop for reading from TUN device and sending data to the server
        while True:
            packet = self.tun_dev.read()
            # TODO: save packets to pcap file (you can implement this feature here)
            # encrypted_packet = aes_encrypt(self.aes_key, packet)
            # self.server_sock.sendto(encrypted_packet, self.server_address)
            """
            1. Build vpn packet
            2. encrypt vpn packet
            3. build udp packet
            4. send to server udp packet
            """
            vpn_pkt = proto.build_vpn_packet(packet)
            encrypted_vpn_pkt = aes_encrypt(self.aes_key, vpn_pkt)
            udp_pkt = proto.build_udp_packet(encrypted_vpn_pkt, self.session_token.encode())
            self.server_sock.sendto(udp_pkt, self.server_address)

        # Ensure the response thread finishes before exiting
        response_thread.join()
        self.server_sock.close()

    def on_response(self) -> None:
        """Handle incoming responses from the VPN server."""
        while True:
            packet, addr = self.server_sock.recvfrom(4069)
            # decrypted_packet = aes_decrypt(self.aes_key, packet)
            print("Received packet from the server")
            # self.tun_dev.write(decrypted_packet)
            payload = self.handle_new_packet_proccessing(packet)
            if payload != None: self.tun_dev.write(payload)


def main() -> None:
    # Server address to connect to
    server_addr = ('127.0.0.1', 3000)

    # User credentials for login
    username = "testuser3"
    password = "testpassword"

    # Initialize and start the VPN client
    vpn_client = VPNClient(tun_device_name='tun1', tun_device_ip='10.1.0.1', server_address=server_addr, username=username, password=password)
    vpn_client.start()


if __name__ == '__main__':
    main()