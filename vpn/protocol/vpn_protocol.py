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

from .hmac_utils import generate_hmac, verify_hmac
from utils.encryption_methods import aes_encrypt, aes_decrypt

class VPNProtocol:
    PROTO_VERSION: bytes = b"VPN1"  # Protocol version identifier
    VERSION = 1  # Current protocol version number
    HMAC_SIZE = 32  # HMAC-SHA-256 output size is 32 bytes
    SESSION_ID_FIELD_SIZE = 36  # Size of the session ID in bytes

    @staticmethod
    def build_udp_packet(encrypted_payload: bytes, auth_token: bytes, session_id: bytes) -> bytes:
        """
        Constructs a full UDP VPN packet consisting of:
        [Session ID] + [Encrypted Payload] + [HMAC]
        
        Args:
        - encrypted_payload: The payload data that has been encrypted using AES.
        - auth_token: Authentication token used for generating the HMAC.
        - session_id: Unique session ID for this VPN communication.
        
        Returns:
        - A concatenated byte string containing the full packet.
        """
        # Generate HMAC over the encrypted payload using the provided auth token
        payload_hmac = generate_hmac(encrypted_payload, auth_token)
        # Return the combined packet: session ID + encrypted payload + HMAC
        return session_id + encrypted_payload + payload_hmac

    @staticmethod
    def extract_vpn_packet(packet: bytes, auth_token: bytes) -> bytes | None:
        """
        Extracts and verifies the encrypted part of the VPN UDP packet.
        This checks the validity of the packet using HMAC.

        Args:
        - packet: The received UDP packet containing the session ID, encrypted payload, and HMAC.
        - auth_token: The token used to verify the HMAC of the packet.
        
        Returns:
        - The decrypted payload if HMAC is valid, otherwise None.
        """
        # Extract the encrypted portion of the packet (excluding session ID and HMAC)
        encrypted_packet = packet[VPNProtocol.SESSION_ID_FIELD_SIZE:-VPNProtocol.HMAC_SIZE]
        # Extract the HMAC portion of the packet
        hmac_field = packet[-VPNProtocol.HMAC_SIZE:]

        # Verify the HMAC. If valid, return the encrypted packet.
        if verify_hmac(encrypted_packet, hmac_field, auth_token):
            return encrypted_packet
        return None  # Return None if the HMAC is invalid

    @staticmethod
    def extract_session_id(packet: bytes) -> bytes:
        """
        Extracts the session ID from the received VPN UDP packet.

        Args:
        - packet: The received UDP packet.

        Returns:
        - The session ID part of the packet (first 36 bytes).
        """
        return packet[:VPNProtocol.SESSION_ID_FIELD_SIZE]

    @staticmethod
    def build_vpn_packet(inner_payload: bytes, version: int = 1) -> bytes:
        """
        Adds a version header and wraps the inner payload to form the VPN packet.
        
        Args:
        - inner_payload: The actual data to be encapsulated in the VPN packet.
        - version: The version of the protocol (default is 1).

        Returns:
        - A VPN packet consisting of the version byte followed by the inner payload.
        """
        # Pack the version as a single byte
        version_byte = struct.pack('B', version)
        # Return the concatenated version byte and inner payload
        return version_byte + inner_payload

    @staticmethod
    def extract_payload(packet: bytes) -> bytes | None:
        """
        Extracts the decrypted payload from the received VPN packet after validating it.
        This removes the version byte and returns the inner payload.

        Args:
        - packet: The received VPN packet (with version header).

        Returns:
        - The decrypted payload (excluding version byte) if the packet is valid.
        - None if the packet is invalid.
        """
        # Validate the packet and check if the version matches
        if VPNProtocol.verify_vpn_packet(packet):
            # Return the inner payload by slicing off the version byte
            return packet[1:]
        return None  # Return None if the packet is invalid

    @staticmethod
    def verify_vpn_packet(packet: bytes, version: int = 1) -> bool:
        """
        Verifies if the VPN packet has the correct version.

        Args:
        - packet: The received packet.
        - version: The expected protocol version (default is 1).

        Returns:
        - True if the packet has the expected version, otherwise False.
        """
        return packet[0] == version

    @staticmethod
    def build_error_packet(error_message: str, session_id: bytes = b'ERR!', aes_key: bytes = None, auth_token: bytes = None) -> bytes:
        """
        Builds a VPN error packet.
        If AES key and auth_token are provided, the error message is encrypted and HMAC is added.
        Otherwise, sends a plaintext error message (for unauthorized clients).

        Args:
        - error_message: The error message to be sent.
        - session_id: The session ID for the error packet (default is 'ERR!').
        - aes_key: AES key for encrypting the payload (optional).
        - auth_token: Authentication token for HMAC (optional).
        
        Returns:
        - The full error packet (with or without encryption and HMAC).
        """
        # Create the error message as a byte string
        payload = f"ERROR:{error_message}".encode()

        # If AES key and auth token are provided, encrypt the payload and add HMAC
        if aes_key and auth_token:
            vpn_payload = VPNProtocol.build_vpn_packet(payload)
            encrypted_payload = aes_encrypt(aes_key, vpn_payload)  # Encrypt the payload with AES
            hmac_field = generate_hmac(encrypted_payload, auth_token)  # Generate HMAC for the encrypted payload
            # Return the session ID + encrypted payload + HMAC
            return session_id + encrypted_payload + hmac_field
        else:
            # If no encryption or HMAC, just send the plaintext error message
            return session_id + payload  # No encryption or HMAC, just plain error message