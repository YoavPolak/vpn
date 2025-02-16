import socket
from threading import Thread
import requests
from . import tun
from .utils.encryption_methods import generate_rsa_keys

class VPNClient:
    def __init__(self, tun_device_name: str, tun_device_ip: str, server_address: tuple, username: str, password: str) -> None:
        self.tun_device_name = tun_device_name
        self.tun_device_ip = tun_device_ip
        self.server_address = server_address
        self.username = username
        self.password = password

        #Crypto Variables
        self._private_key, self._public_key = generate_rsa_keys()
        self._aes_key = None

        # Initialize the TUN device
        self.tun_dev = tun.Device(self.tun_device_name, self.tun_device_ip)

        # Initialize the socket for communication with the VPN server
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Placeholder for session token
        self.session_token = None

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

    def handle_RSA_key_exchange(self):
        sock = self.server_sock
        client_protocol.send_msg_plaintext(sock, "Client hello")
        sock.sendto("ClientHello", self.server_address)
        serialized_server_public_key = client_protocol.get_msg_plaintext(sock)
        
        server_public_key = serialization.load_pem_public_key(serialized_server_public_key)
        print("server publickey: ", server_public_key)
        self.aes_key = os.urandom(32)  # AES-256
        print("aes key: ", self.aes_key)
        encrypted_aes_key = encrypt_with_rsa(server_public_key, self.aes_key)
        client_protocol.send_msg_plaintext(sock, encrypted_aes_key)

    def handle_TLS_handshake(self):
        pass

    def start(self) -> None:
        """Start the VPN client."""
        # First, authenticate the user
        if not self._login():
            return  # Stop if login fails

        #add TLS handshake here

        # Bring the TUN device up
        self.tun_dev.up()

        # Create a separate thread to handle the response from the server
        response_thread = Thread(target=self.on_response)
        response_thread.start()

        # Main loop for reading from TUN device and sending data to the server
        while True:
            packet = self.tun_dev.read()
            # TODO: save packets to pcap file (you can implement this feature here)
            self.server_sock.sendto(packet, self.server_address)

        # Ensure the response thread finishes before exiting
        response_thread.join()
        self.server_sock.close()

    def on_response(self) -> None:
        """Handle incoming responses from the VPN server."""
        while True:
            packet, addr = self.server_sock.recvfrom(4069)
            print("Received packet from the server")
            self.tun_dev.write(packet)


def main() -> None:
    # Server address to connect to
    server_addr = ('127.0.0.1', 3000)

    # User credentials for login
    username = "client1"
    password = "password123"

    # Initialize and start the VPN client
    vpn_client = VPNClient(tun_device_name='tun1', tun_device_ip='10.1.0.1', server_address=server_addr, username=username, password=password)
    vpn_client.start()


if __name__ == '__main__':
    main()