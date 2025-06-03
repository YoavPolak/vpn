import select
import socket
import queue
from threading import Thread, Lock
import logging
from concurrent.futures import ThreadPoolExecutor
import time

# Internal module imports
from utils.encryption_methods import aes_encrypt, aes_decrypt
from vpn import tun, net
from vpn.protocol.vpn_protocol import VPNProtocol as proto
from database.session_db import SessionDB

# Constants
BUFFER_SIZE = 65535  # Max UDP packet size
class UDPServer:
    """
    Handles encrypted communication with clients over UDP, routing traffic through a TUN device.
    It supports NAT, session tracking, secure packet exchange, and automatic cleanup of stale clients.
    """

    def __init__(self, bind_port: int, bind_addr: str = '0.0.0.0') -> None:
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._addr = (bind_addr, bind_port)

            self._tun_device = None
            self._nat = net.NAT()
            self._addr_allocator = net.AddrAllocator('10.0.0.0/24')

            self.db = SessionDB()
            self._client_sessions = {}  # Maps client address -> session_id
            self.client_last_seen = {}  # Tracks last activity per client
            self._lock = Lock()  # Ensures thread-safe access to shared data

            self.executor = ThreadPoolExecutor(max_workers=100)

            # TUN packet write queue
            self._tun_write_queue = queue.Queue()
            self._tun_writer_thread = Thread(target=self._tun_writer_loop, daemon=True)
            self._tun_writer_thread.start()
        except Exception as e:
            logging.exception("Error initializing UDPServer")

    def route_traffic_to(self, tun_dev: 'tun.Device') -> 'UDPServer':
        """
        Attaches a TUN device for routing decrypted client traffic.
        """
        self._tun_device = tun_dev
        return self

    def start(self) -> None:
        """
        Main server loop. Binds UDP socket and listens for packets. Spawns threads for TUN reads and packet handling.
        """
        try:
            self._sock.bind(self._addr)
            print(f"[UDP] Server listening on {self._addr}")

            self._tun_read_thread = Thread(target=self.on_tun_recv)
            self._tun_read_thread.start()

            while True:
                self.cleanup_clients()
                packet, client_addr = self._sock.recvfrom(BUFFER_SIZE)#4096
                if packet:
                    self.executor.submit(self.on_packet, packet, client_addr)
        except Exception:
            logging.exception("Error starting UDPServer")

    def on_tun_recv(self) -> None:
        """
        Continuously reads packets from the TUN device and routes them back to clients via UDP.
        """
        try:
            tun_fd = self._tun_device.fileno()

            while True:
                ready, _, _ = select.select([tun_fd], [], [], 0.5)
                if not ready:
                    continue

                try:
                    packet = bytearray(self._tun_device.read())
                    logging.debug('tun0 recv: %s', packet)

                    client_addr = self._nat.in_(packet)
                    if not client_addr:
                        continue

                    session_id = self._client_sessions.get(client_addr)
                    if not session_id:
                        logging.error(f"[UDP] No session found for client {client_addr}")
                        continue

                    aes_key, auth_token = self.db.retrieve_session_data(session_id)
                    vpn_pkt = proto.build_vpn_packet(packet)
                    encrypted_pkt = aes_encrypt(aes_key, vpn_pkt)

                    udp_pkt = proto.build_udp_packet(encrypted_pkt, auth_token.encode(), session_id.encode())
                    self._sock.sendto(udp_pkt, client_addr)

                except Exception:
                    logging.exception("Error processing TUN packet")
        except Exception:
            logging.exception("TUN listener thread failed")

    def on_packet(self, packet: bytes, client_addr: net.Address) -> None:
        """
        Handles incoming UDP packets from clients. Verifies session, decrypts, and writes to TUN.
        """
        try:
            with self._lock:
                session_id = proto.extract_session_id(packet).decode()

                if not self.db.session_exists(session_id):
                    logging.warning(f"[UDP] Unauthorized packet from {client_addr}")
                    self.send_error_response(client_addr, "Unauthorized client.")
                    return

                # First-time contact: run handshake
                if client_addr not in self._client_sessions:
                    self.perform_tun_handshake(packet, session_id, client_addr)
                    return

                self.client_last_seen[client_addr] = time.time()
                payload = self.handle_new_packet(packet, client_addr, session_id)

                if payload:
                    self.write_to_tun(payload, client_addr)
        except Exception:
            logging.exception(f"[UDP] Packet handling error from {client_addr}")

    def handle_new_packet(self, packet: bytes, client_addr: net.Address, session_id: str) -> bytes | None:
        """
        Extracts and decrypts the VPN payload from the UDP packet.
        """
        try:
            aes_key, auth_token = self.db.retrieve_session_data(session_id)
            encrypted_vpn_pkt = proto.extract_vpn_packet(packet, auth_token.encode())

            if not encrypted_vpn_pkt:
                self.send_error_response(client_addr, "Failed to extract VPN packet.")
                return None

            decrypted_vpn_pkt = aes_decrypt(aes_key, encrypted_vpn_pkt)
            return proto.extract_payload(decrypted_vpn_pkt)
        except Exception:
            logging.exception(f"[UDP] Decryption error from {client_addr}")
            self.send_error_response(client_addr, "Decryption failed.")
            return None

    def write_to_tun(self, packet: bytes, client_addr: net.Address):
        """
        Routes decrypted payloads to the TUN device and applies NAT translation.
        """
        try:
            packet = bytearray(packet)
            new_tun_ip = self._addr_allocator.new(hash(client_addr))
            self._nat.out(packet, new_tun_ip, client_addr)
            self._tun_write_queue.put(packet)
        except Exception:
            logging.exception(f"Error writing to TUN for {client_addr}")

    def _tun_writer_loop(self):
        """
        Continuously writes queued packets to the TUN device.
        """
        try:
            while True:
                packet = self._tun_write_queue.get()
                if packet is None:
                    break
                self._tun_device.write(packet)
        except Exception:
            logging.exception("TUN writer loop failure")

    def send_error_response(self, client_addr: net.Address, error_message: str) -> None:
        """
        Sends an error packet to the client. If session is valid, encrypts it.
        """
        try:
            session_id = self._client_sessions.get(client_addr)

            if session_id:
                try:
                    aes_key, auth_token = self.db.retrieve_session_data(session_id)
                    error_pkt = proto.build_error_packet(
                        error_message, session_id.encode(), aes_key, auth_token.encode()
                    )
                except Exception:
                    logging.error(f"[UDP] Encrypted error packet creation failed for {client_addr}")
                    return
            else:
                error_pkt = proto.build_error_packet(error_message)

            self._sock.sendto(error_pkt, client_addr)
            logging.info(f"[UDP] Sent error to {client_addr}: {error_message}")
        except Exception:
            logging.exception("Failed to send error response")

    def remove_client(self, client_addr):
        """
        Removes a client session and associated data.
        """
        try:
            with self._lock:
                if client_addr in self._client_sessions:
                    session_id = self._client_sessions.pop(client_addr)
                    self.db.remove_session(session_id)
                    logging.info(f"Session removed for {client_addr}")
        except Exception:
            logging.exception(f"Error removing client {client_addr}")

    def cleanup_nat_translation(self, client_addr):
        """
        Removes NAT mapping for the disconnected client.
        """
        try:
            tun_ip = self._addr_allocator.new(hash(client_addr))
            self._nat.remove_translation(tun_ip, client_addr)
            logging.info(f"NAT translation removed for {client_addr}")
        except Exception:
            logging.exception(f"NAT cleanup error for {client_addr}")

    def cleanup_virtual_ip(self, client_addr):
        """
        Releases the client's virtual IP from the allocator.
        """
        try:
            self._addr_allocator.release(hash(client_addr))
            logging.info(f"Virtual IP released for {client_addr}")
        except Exception:
            logging.exception(f"Virtual IP release error for {client_addr}")

    def cleanup_clients(self):
        """
        Disconnects inactive clients after timeout.
        """
        try:
            now = time.time()
            timeout = 10000  # seconds

            for client_addr, last_seen in list(self.client_last_seen.items()):
                if now - last_seen > timeout:
                    self.remove_client(client_addr)
                    self.cleanup_nat_translation(client_addr)
                    self.cleanup_virtual_ip(client_addr)
                    del self.client_last_seen[client_addr]
                    logging.info(f"Disconnected inactive client {client_addr}")
        except Exception:
            logging.exception("Error during client cleanup")

    def perform_tun_handshake(self, packet, session_id: str, client_addr: net.Address) -> bool | None:
        """
        Handles initial TUN IP allocation and confirms readiness from client.
        """
        try:
            session_data = self.db.retrieve_session_data(session_id)
            if not session_data:
                logging.error(f"No session data for session_id: {session_id}")
                return

            aes_key, auth_token = session_data
            encrypted_pkt = proto.extract_vpn_packet(packet, auth_token.encode())

            if not encrypted_pkt:
                logging.warning(f"Invalid HMAC from {client_addr}")
                return

            decrypted_pkt = aes_decrypt(aes_key, encrypted_pkt)
            payload = proto.extract_payload(decrypted_pkt)

            if payload == b"UDP HELLO":
                tun_ip = self._addr_allocator.new(hash(client_addr))
                response_pkt = proto.build_vpn_packet(tun_ip.encode())
                encrypted = aes_encrypt(aes_key, response_pkt)
                udp_response = proto.build_udp_packet(encrypted, auth_token.encode(), session_id.encode())

                self._sock.sendto(udp_response, client_addr)
                logging.info(f"Sent TUN IP {tun_ip} to client {client_addr}")

            elif payload == b"TUN OK":
                self._client_sessions[client_addr] = session_id
                logging.info(f"TUN handshake complete with {client_addr}")
                return True

            else:
                logging.warning(f"Unexpected payload during handshake from {client_addr}: {payload}")
        except Exception:
            logging.exception(f"TUN handshake error with {client_addr}")


# === Entry Point ===
def main():
    try:
        tun_dev = tun.Device('tun0', '10.0.0.1')
        tun_dev.up()

        server = UDPServer(3000).route_traffic_to(tun_dev)
        server.start()
    except Exception:
        logging.exception("Fatal error in UDP server")

if __name__ == "__main__":
    main()