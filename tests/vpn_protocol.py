"""
encrypted
+--------------------+--------------------------------------------------+--------------------------------------------------+
|     Session ID     |                 Encrypted Packet                 |                    HMAC                          |
+--------------------+--------------------------------------------------+--------------------------------------------------+
|  0x000174          |  0x93a5f3b41f2c20e7...                           |  0x9a6f8d7bdb47c91a9f3f2437ac0198f92b149b92b7fdf |
|  (4 bytes)         |  (Encrypted header and payload, variable length) |  (32 bytes: HMAC-SHA-256)                        |
|                    |                                                  |  (HMAC SHA256 over the entire encrypted packet)  |
+--------------------+--------------------------------------------------+--------------------------------------------------+
the purpose if the hmac is to make sure the encrypted packet isnt corapted
Encapsulated Packet

+--------------------+----------------------------+
|      Version       |    Encapsulated Payload    |
+--------------------+----------------------------+
|   0x01 (1 byte)    |  actual encapsulated data  |
|                    |  A.K.A Inner Packet        |
|                    |                            |
+--------------------+----------------------------+

[ session_id (36 bytes) | AES-encrypted payload | HMAC (32 bytes) ]
"""

import struct
import os

from .hmac import generate_hmac, verify_hmac
from vpn.utils.encryption_methods import aes_encrypt, aes_decrypt

class vpn_protocol:
    PROTO_VERSION: bytes = b"VPN1"
    VERSION = 1
    HMAC_SIZE = 32  # SHA-256 output is 32 bytes
    SESSION_ID_FIELD_SIZE = 36

    @staticmethod
    def build_udp_packet(encrypted_payload: bytes, auth_token: bytes, session_id: bytes) -> bytes:
        """
        Constructs full UDP VPN packet: [Session ID][Encrypted][HMAC]
        """
        payload_hmac = generate_hmac(encrypted_payload, auth_token)
        return session_id + encrypted_payload + payload_hmac

    @staticmethod
    def extract_vpn_packet(packet: bytes, auth_token: bytes) -> bytes | None:
        """
        Extract and verify the encrypted part from received VPN UDP packet.
        """
        encrypted_packet = packet[vpn_protocol.SESSION_ID_FIELD_SIZE:-vpn_protocol.HMAC_SIZE]
        hmac_field = packet[-vpn_protocol.HMAC_SIZE:]

        if verify_hmac(encrypted_packet, hmac_field, auth_token):
            return encrypted_packet
        return None
    
    def extract_session_id (packet: bytes) -> bytes:
        """
        Extract Session id from received VPN UDP packet.
        """
        return packet[:vpn_protocol.SESSION_ID_FIELD_SIZE]

    @staticmethod
    def build_vpn_packet(inner_payload: bytes, version: int = 1) -> bytes:
        """
        Add version header and wrap inner payload.
        """
        version_byte = struct.pack('B', version)
        return version_byte + inner_payload

    @staticmethod
    def extract_payload(packet: bytes) -> bytes | None:
        """
        Validate and return decrypted payload (excluding version byte).
        """
        if vpn_protocol.verify_vpn_packet(packet):
            return packet[1:]
        return None

    @staticmethod
    def verify_vpn_packet(packet: bytes, version: int = 1) -> bool:
        return packet[0] == version

    @staticmethod
    def build_error_packet(error_message: str, session_id: bytes = b'ERR!', aes_key: bytes = None, auth_token: bytes = None) -> bytes:
        """
        Builds a VPN error packet. If AES key and auth_token are provided, it encrypts and adds HMAC.
        Otherwise, sends plaintext (for unauthorized clients).
        """
        payload = f"ERROR:{error_message}".encode()

        if aes_key and auth_token:
            vpn_payload = vpn_protocol.build_vpn_packet(payload)
            encrypted_payload = aes_encrypt(aes_key, vpn_payload)
            hmac_field = generate_hmac(encrypted_payload, auth_token)
            return session_id + encrypted_payload + hmac_field
        else:
            # Fallback: Plain error (unauthenticated), padded to match general packet structure
            return session_id + payload  # No encryption, no HMAC