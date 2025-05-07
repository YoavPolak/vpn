import select
import socket
import queue  # For TUN write queue
from threading import Thread, Lock
import logging
from concurrent.futures import ThreadPoolExecutor  # Thread pool for incoming UDP packets
import time

from vpn.utils.encryption_methods import aes_encrypt, aes_decrypt
from vpn import tun, net
from .vpn_protocol import vpn_protocol as proto
from .secure_tcp_server import SecureDatabase


class UDPServer:
    def __init__(self, bind_port: int, bind_addr: str = '0.0.0.0') -> None:
        """
        Initializes the UDP Server with port binding, client database, and NAT routing.
        """
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP socket setup
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Reuse address if needed
            self._addr = (bind_addr, bind_port)
            self._threads = []  # Thread list for managing client connections
            self._tun_device = None  # TUN device, will route packets through VPN

            self._nat = net.NAT()  # NAT router for packet translation
            self._addr_allocator = net.AddrAllocator('10.0.0.0/24')

            self.db = SecureDatabase()  # Shared with TCP handshake server
            self._client_sessions: dict = {}
            self._lock = Lock()  # Lock to ensure thread safety for shared resources
            self.client_last_seen = {}  # Track the last time a client was seen

            self.executor = ThreadPoolExecutor(max_workers=100)  # Efficient thread pool

            self._tun_write_queue = queue.Queue()  # TUN write queue
            self._tun_writer_thread = Thread(target=self._tun_writer_loop)
            self._tun_writer_thread.daemon = True
            self._tun_writer_thread.start()  # Start TUN writer
        except Exception as e:
            logging.exception("Error initializing UDPServer")

    def route_traffic_to(self, tun_dev: 'tun.Device') -> 'UDPServer':
        """
        Route traffic from the UDP server to the provided TUN device.
        """
        self._tun_device = tun_dev
        return self

    def start(self) -> None:
        """
        Starts the UDP server, binding it to the specified address and port.
        """
        try:
            self._sock.bind(self._addr)
            print(f"[UDP] Server listening on {self._addr}")

            # Create and start the thread that reads from the TUN device
            self._tun_read_thread = Thread(target=self.on_tun_recv)
            self._tun_read_thread.start()

            while True:
                try:
                    self.cleanup_clients()  # Periodically clean up disconnected clients
                    packet, client_addr = self._sock.recvfrom(4096)
                    if packet:
                        self.executor.submit(self.on_packet, packet, client_addr)
                except Exception as e:
                    logging.exception("Error in UDP receive loop")
        except Exception as e:
            logging.exception("Error starting UDPServer")

    def on_tun_recv(self) -> None:
        """
        Thread method that listens for packets from the TUN device
        and sends them to the appropriate client over UDP.
        """
        try:
            tun_fd = self._tun_device.fileno()  # Get file descriptor for select()

            while True:
                ready, _, _ = select.select([tun_fd], [], [], 0.5)
                if not ready:
                    continue

                try:
                    packet = bytearray(self._tun_device.read())  # Read data from TUN
                    logging.debug('tun0 recv: %s', packet)

                    client_addr = self._nat.in_(packet)
                    if client_addr is None:
                        continue

                    session_id = self._client_sessions.get(client_addr)
                    if not session_id:
                        logging.error(f"[UDP] No session found for client {client_addr}")
                        continue

                    vpn_pkt = proto.build_vpn_packet(packet)
                    aes_key, auth_token = self.db.retrieve_session_data(session_id)
                    encrypted_vpn_pkt = aes_encrypt(aes_key, vpn_pkt)

                    udp_pkt = proto.build_udp_packet(encrypted_vpn_pkt, auth_token.encode(), session_id.encode())
                    self._sock.sendto(udp_pkt, client_addr)
                except Exception as e:
                    logging.exception("Error processing packet from TUN device")
        except Exception as e:
            logging.exception("TUN listener thread failed to start")

    def on_packet(self, packet: bytes, client_addr: net.Address) -> None:
        """
        Handles each incoming UDP packet from clients. It checks if the packet is valid,
        decrypts it, and routes it to the TUN device if successful.
        """
        try:
            with self._lock:
                session_id_bytes = proto.extract_session_id(packet)
                session_id = session_id_bytes.decode()

                if not self.db.session_exists(session_id):
                    logging.warning(f"[UDP] Unauthorized packet from {client_addr}")
                    self.send_error_response(client_addr, "Unauthorized client.")
                    return

                if client_addr not in self._client_sessions:
                    response = self.perform_tun_handshake(packet, session_id, client_addr)
                    return

                # Update the last seen time for the client
                self.client_last_seen[client_addr] = time.time()

                payload = self.handle_new_packet(packet, client_addr, session_id)
                if payload:
                    self.write_to_tun(payload, client_addr)
        except Exception as e:
            logging.exception(f"[UDP] Exception in on_packet from {client_addr}")

    def handle_new_packet(self, packet: bytes, client_addr: net.Address, session_id: str) -> bytes | None:
        """
        Decrypts the incoming packet and extracts the payload.
        Returns the decrypted payload or None if invalid.
        """
        try:
            aes_key, auth_token = self.db.retrieve_session_data(session_id)
            encrypted_vpn_pkt = proto.extract_vpn_packet(packet, auth_token.encode())

            if not encrypted_vpn_pkt:
                self.send_error_response(client_addr, "Failed to extract VPN packet.")
                return None

            decrypted_vpn_pkt = aes_decrypt(aes_key, encrypted_vpn_pkt)
            return proto.extract_payload(decrypted_vpn_pkt)
        except Exception as e:
            logging.error(f"[UDP] Error decrypting packet from {client_addr}: {e}")
            self.send_error_response(client_addr, "Decryption error.")
            return None

    def write_to_tun(self, packet: bytes, client_addr: net.Address):
        """
        Enqueues the decrypted payload to be written to the TUN device and handles NAT translation.
        """
        try:
            packet = bytearray(packet)

            # Translate and enqueue the packet to the TUN writer
            new_tun_ip = self._addr_allocator.new(hash(client_addr))
            print(new_tun_ip)
            self._nat.out(packet, new_tun_ip, client_addr)

            self._tun_write_queue.put(packet)  # Enqueue packet for TUN writer thread
        except Exception as e:
            logging.exception(f"Error writing to TUN for {client_addr}")

    def _tun_writer_loop(self):
        """
        Continuously write packets to the TUN device from the queue.
        """
        try:
            while True:
                packet = self._tun_write_queue.get()
                if packet is None:
                    break  # For future shutdown support
                self._tun_device.write(packet)
        except Exception as e:
            logging.exception("TUN writer loop error")

    def send_error_response(self, client_addr: net.Address, error_message: str) -> None:
        """
        Sends an error response to a client.
        If the client is unknown, the error is sent unencrypted.
        """
        try:
            session_id = self._client_sessions.get(client_addr)

            if session_id:
                try:
                    aes_key, auth_token = self.db.retrieve_session_data(session_id)
                    error_pkt = proto.build_error_packet(
                        error_message, session_id.encode(), aes_key, auth_token.encode()
                    )
                except Exception as e:
                    logging.error(f"[UDP] Failed to build encrypted error packet: {e}")
                    return
            else:
                # Unauthorized client — send plaintext error
                logging.warning(f"[UDP] Sending unencrypted error to unauthorized client: {client_addr}")
                error_pkt = proto.build_error_packet(error_message)

            self._sock.sendto(error_pkt, client_addr)
            logging.info(f"[UDP] Sent error response to {client_addr}: {error_message}")
        except Exception as e:
            logging.error(f"[UDP] Failed to send error response: {e}")

    def remove_client(self, client_addr):
        """
        Removes the client session and any associated data when they disconnect.
        """
        try:
            with self._lock:
                if client_addr in self._client_sessions:
                    session_id = self._client_sessions.get(client_addr)
                    self.db.remove_session(session_id) # remove session data from database
                    del self._client_sessions[client_addr]
                    logging.info(f"Removed session for {client_addr}")
                else:
                    logging.warning(f"Tried to remove unknown client: {client_addr}")
        except Exception as e:
            logging.exception(f"Error removing client {client_addr}")

    def cleanup_nat_translation(self, client_addr):
        """
        Clean up NAT translation for a disconnected client.
        """
        try:
            tun_ip = self._addr_allocator.new(hash(client_addr))
            self._nat.remove_translation(tun_ip, client_addr)
            logging.info(f"NAT translation removed for {client_addr}")
        except Exception as e:
            logging.exception(f"Error cleaning NAT for {client_addr}")

    def cleanup_virtual_ip(self, client_addr):
        """
        Clean up the allocated virtual IP when the client disconnects.
        """
        try:
            self._addr_allocator.release(hash(client_addr))
            logging.info(f"Virtual IP released for {client_addr}")
        except Exception as e:
            logging.exception(f"Error releasing virtual IP for {client_addr}")

    def cleanup_clients(self): # TODO add disconnect for a client
        """
        Periodically checks for clients who haven't sent packets in a while
        and removes them from the session database.
        """
        try:
            current_time = time.time()
            timeout_threshold = 10  # e.g., 5 seconds

            for client_addr, last_seen in list(self.client_last_seen.items()):
                if current_time - last_seen > timeout_threshold:
                    self.remove_client(client_addr)
                    self.cleanup_nat_translation(client_addr)
                    self.cleanup_virtual_ip(client_addr)
                    del self.client_last_seen[client_addr]
                    logging.info(f"Client {client_addr} has been disconnected due to inactivity.")
        except Exception as e:
            logging.exception("Error during cleanup_clients")

    def perform_tun_handshake(self, packet, session_id: str, client_addr: net.Address) -> bool | None:
        """
        Handles the initial UDP-based handshake for assigning a TUN IP address to the client.
        """
        try:
            session_data = self.db.retrieve_session_data(session_id)
            if not session_data:
                logging.error(f"No session data found for session ID: {session_id}")
                return

            aes_key, auth_token = session_data

            encrypted_vpn_pkt = proto.extract_vpn_packet(packet, auth_token.encode())
            if encrypted_vpn_pkt is None:
                logging.warning(f"HMAC verification failed for packet from {client_addr}")
                return

            decrypted_pkt = aes_decrypt(aes_key, encrypted_vpn_pkt)
            payload = proto.extract_payload(decrypted_pkt)

            if payload == b"UDP HELLO":
                new_tun_ip = self._addr_allocator.new(hash(client_addr))
                vpn_response = proto.build_vpn_packet(new_tun_ip.encode())
                encrypted_response = aes_encrypt(aes_key, vpn_response)
                udp_response = proto.build_udp_packet(encrypted_response, auth_token.encode(), session_id.encode())

                self._sock.sendto(udp_response, client_addr)
                logging.info(f"Sent TUN IP {new_tun_ip} to client {client_addr}")

            elif payload == b"TUN OK":
                self._client_sessions[client_addr] = session_id
                logging.info(f"TUN IP confirmed by client {client_addr}. Session established.")
                return True

            else:
                logging.warning(f"Unexpected payload from {client_addr}: {payload}")
        except Exception as e:
            logging.exception(f"Error during TUN handshake with {client_addr}")


def main():
    try:
        tun_dev = tun.Device('tun0', '10.0.0.1')
        tun_dev.up()

        server = UDPServer(3000).route_traffic_to(tun_dev)
        server.start()
    except Exception as e:
        logging.exception("Fatal error in main")


if __name__ == "__main__":
    main()