import socket
from threading import Thread, Timer
import logging
from enum import Enum
from typing import Tuple
import sqlite3
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from vpn.utils.encryption_methods import *
import requests
import os
from .vpn_protocol import vpn_protocol as proto

from vpn import tun, ip, net

class ClientState(Enum):
    HANDSHAKE = 1
    AUTHENTICATED = 2
    DISCONNECTED = 3
    TIMED_OUT = 4  # Used for clients that timed out during handshake


class Server:
    def __init__(self, bind_port: int, bind_addr: str = '0.0.0.0') -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._addr = (bind_addr, bind_port)
        self._threads = []
        self._tun_device = None

        self._nat = net.NAT()
        self._addr_allocator = net.AddrAllocator('10.0.0.0/24')
        self._clients = {}  # Keep track of clients states for now {client_addr : STATE, ...}
        self._clients_db = {} # Keep track of clients for now   {client_addr : [AES_Key, (AUTH_TOKEN, expiration_time) ]}
        # For now it uses it this way. But later I believe it will be handles from the state handler or db and the client will be deleted after expired
        self._private_key, self._public_key = generate_rsa_keys()

        #Common variables
        self.handshake_response : bytes = b"Handshake successful."


    def route_traffic_to(self, tun_dev: 'tun.Device') -> 'Server':
        self._tun_device = tun_dev
        return self

    def start(self) -> None:
        self._sock.bind(self._addr)

        self._tun_read_thread = Thread(target=self.on_tun_recv)
        self._tun_read_thread.start()

        while True:
            packet, client_addr = self._sock.recvfrom(4096) #4096 #Calculate how many bytes I should read instead #1549
            if packet:
                new_thread = Thread(target=self.on_packet, args=(packet, client_addr,))
                new_thread.start()
            else:
                self.disconnect_client(client_addr)

    def on_tun_recv(self) -> None:
        while True:
            packet = bytearray(self._tun_device.read())
            logging.debug('tun0 recv: %s', packet)

            client_addr = self._nat.in_(packet)
            if client_addr is not None:
                logging.debug("conn send: %s", packet)

                """
                1. Build vpn_packet
                2. encrypt vpn packet
                3. build udp packet
                4. send to server udp packet
                """
                vpn_pkt = proto.build_vpn_packet(packet)
                cl_aes_key = self._clients_db[client_addr][0]
                encrypted_vpn_pkt = aes_encrypt(cl_aes_key, vpn_pkt)
                cl_auth_tkn = self._clients_db[client_addr][1][0]
                udp_pkt = proto.build_udp_packet(encrypted_vpn_pkt, cl_auth_tkn.encode())
                self._sock.sendto(udp_pkt, client_addr)

    #This is need to be done
    def on_packet(self, packet: bytes, client_addr: net.Address) -> None:
        logging.debug('Received packet from %s: %s', client_addr, packet)

        if client_addr not in self._clients:
            # Initialize client state to HANDSHAKE for handshake
            self.init_handshake(packet, client_addr)
            #ClientState.HANDSHAKE
        else:
            # Checks client state before handling the packet 
            current_state = self._clients.get(client_addr, ClientState.DISCONNECTED)

            #For now I assume every step works
            if current_state == ClientState.HANDSHAKE:
                self.handle_handshake(packet, client_addr)  # RSA key exchange and share creds, to authenticate the user.
                #ClientState.AUTHENTICATED
            elif current_state == ClientState.AUTHENTICATED:
                payload = self.handle_new_packet_proccessing(packet, client_addr)
                if payload: self.dev_handle_data_packet(payload, client_addr)

            elif current_state == ClientState.TIMED_OUT:
                logging.warning(f"Handshake timed out for {client_addr}.")
                self.send_error_response(client_addr, "Handshake timeout")
                #TODO add the logic in the client to handle this
                #TODO add the logic to handle TIMEOUT in the server
                #Possibly make something with redis that when i user is timed out maybe wait like 5 min till he can try again or something
            elif current_state == ClientState.DISCONNECTED:
                #TODO clean the data maybe, need to think about it
                pass
                #TODO do it with redis like clean everything
            else:
                logging.warning(f"Unexpected packet from {client_addr} in state {current_state}.")

    def init_handshake(self, packet: bytes, client_addr: net.Address) -> None:
        try:
            if packet[:4] != proto.PROTO_VERSION: #Change it later
                logging.error(f"Invalid handshake packet from {client_addr}")
                # self._clients[client_addr] = ClientState.TIMED_OUT
                return

            # Send server's public key to the client
            serialized_public_key = self._public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            self._sock.sendto(serialized_public_key, client_addr)

            self._clients[client_addr] = ClientState.HANDSHAKE
            logging.info(f"Initiating handshake with {client_addr}")
        except Exception as e:
            print(f"[*]ERROR initiating handshake for {client_addr}:", e)

    def handle_handshake(self, packet: bytes, client_addr: net.Address) -> None:
        logging.info(f"Handling handshake from {client_addr}")   
        """
        Client Packet -> 
        rsa_encrypted[VPN1|AES_Key|Session_Token|Public_Client_key]
        """
        try:
            # Step 1: Parse the encrypted packet to get the AES key and auth_token
            encrypted_aes_key, encrypted_auth_token, ser_client_pub_key = self.parse_handshake(packet) #used to be decrypted_packet
            client_pub_key = serialization.load_pem_public_key(ser_client_pub_key)

            # Step 2: Decrypt the entire handshake packet using the server's private RSA key
            aes_key = decrypt_with_rsa(self._private_key, encrypted_aes_key)
            auth_token = decrypt_with_rsa(self._private_key, encrypted_auth_token).decode()
            
            # Step 3: Verify the authentication token via HTTP
            expiration_time = self.verify_auth_token(auth_token)
            if not expiration_time:
                logging.warning(f"Authentication failed for {client_addr} with token {auth_token}")
                self._clients[client_addr] = ClientState.DISCONNECTED
                self.send_error_response(client_addr, "Authentication failed.")
                return

            # Step 6: Update client state to AUTHENTICATED in memory
            self._clients[client_addr] = ClientState.AUTHENTICATED
            self._clients_db[client_addr] = [aes_key, (auth_token, expiration_time)]

            # Step 7: Respond to the client (encrypt the response before sending)
            encrypted_response = aes_encrypt(aes_key, self.create_handshake_response(client_addr))
            self._sock.sendto(encrypted_response, client_addr)

            logging.info(f"Handshake successful with {client_addr}. AES key established.")
            print("Handshake successful")
        except Exception as e:
            print(e)
            self.send_error_response(client_addr, "Authentication failed. and Handshake failed") #Maybe send it using AES

    def create_handshake_response(self, client_addr : net.Address) -> bytes:
        """Create a handshake success response message"""
        return self.handshake_response + b"\n\n" + self._addr_allocator.new(hash(client_addr)).encode()

    def verify_auth_token(self, auth_token: str) -> bool | str: #HTTP things No need to touch it
        """Verify auth_token by sending a request to an external service"""
        url = "http://localhost:8000/validate_token"
        data = {'token': auth_token}

        # Send the POST request to verify the token
        response = requests.post(url, json=data)

        # Handle the response status code and extract expirationTime
        if response.status_code == 200:
            try:
                # Parse the response JSON
                response_data = response.json()
                # Check if 'expirationTime' is in the response
                expiration_time = response_data.get('expirationTime')
                if expiration_time:
                    logging.info(f"Token verification successful for {auth_token}. Expiration time: {expiration_time}")
                    print(expiration_time)
                    return expiration_time
                else:
                    logging.warning(f"Token verification successful, but no expirationTime found for {auth_token}.")
                
                return True
            except ValueError:
                logging.error(f"Failed to parse JSON response for {auth_token}.")
                return False
        else:
            logging.warning(f"Token verification failed for {auth_token} with status code {response.status_code}.")
            return False

    def parse_handshake(self, packet: bytes):
        """Parse the handshake packet into the AES key and auth token"""
        header, enc_aes_key, enc_auth_token, pub_key = packet.split(b'\n\n')
        return enc_aes_key, enc_auth_token, pub_key

    def handle_new_packet_proccessing(self, packet: bytes, client_addr: net.Address) -> bytes | None:
        """
        1. Will use extract_vpn_packet(packet, client_auth_token) -> encrypted payload
        2. decrypt packet using shared aes key with the client
        3. protocl.extract_payload(packet) -> inner_packet
        forward it to the right function
        self._clients_db[client_addr] = [aes_key, (auth_token, expiration_time)]
        """
        try:
            # FOR NOW I assume all auth_tokens are not expired yet.
            cl_auth_tkn = self._clients_db[client_addr][1][0]
            encrypted_vpn_pkt = proto.extract_vpn_packet(packet, cl_auth_tkn.encode()) #Returns the encrypted vpn_packet, with aes encryption
    
            if encrypted_vpn_pkt == None: return None #Handle bad hmac or dont forward it idk
    
            cl_aes_key = self._clients_db[client_addr][0]
            decrypted_vpn_pkt = aes_decrypt(cl_aes_key, encrypted_vpn_pkt)
    
            payload = proto.extract_payload(decrypted_vpn_pkt)
            return payload
        except Exception as e:
            print(e)
    
    def dev_handle_data_packet(self, packet: bytes, client_addr: net.Address) -> None:
        """Handle decrypted/Inner packets after successful authentication"""
        logging.debug(f"Handling data from {client_addr}")
        packet = bytearray(packet)

        new_tun_ip = self._addr_allocator.new(hash(client_addr)) #Send virtual ip to client.
        self._nat.out(packet, new_tun_ip, client_addr)

        logging.debug('tun0 send: %s', packet)
        self._tun_device.write(packet)

    def disconnect_client (self, client_addr: net.Address):
        if client_addr in self._clients:
            del self._clients[client_addr]
            del self._clients_db[client_addr]
        print(f"{client_addr} disconnected")
    def send_error_response(self, client_addr: net.Address, message: str) -> None:
        """Send an error response to the client"""
        error_response = f"ERROR: {message}".encode()
        self._sock.sendto(error_response, client_addr)
        self._clients[client_addr] = ClientState.DISCONNECTED
        logging.error(f"Sent error to {client_addr}: {message}")


if __name__ == "__main__":
    tun_dev = tun.Device('tun0', '10.0.0.1')
    tun_dev.up()

    server = Server(3000).route_traffic_to(tun_dev)
    server.start()
