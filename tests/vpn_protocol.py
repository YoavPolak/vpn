"""
encrypted
+--------------------+--------------------------------------------------+--------------------------------------------------+
|   Length Field     |                 Encrypted Packet                 |                    HMAC                          |
+--------------------+--------------------------------------------------+--------------------------------------------------+
|  0x000174          |  0x93a5f3b41f2c20e7...                           |  0x9a6f8d7bdb47c91a9f3f2437ac0198f92b149b92b7fdf |
|  (2 bytes)         |  (Encrypted header and payload, variable length) |  (32 bytes: HMAC-SHA-256)                        |
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
"""

# You can handle retransmission or error handling here if needed

import struct
from .hmac import generate_hmac, verify_hmac
from vpn.utils.encryption_methods import aes_encrypt, aes_decrypt

class vpn_protocol:

    # Build length field
    @staticmethod
    def build_len_field(packet: bytes) -> bytes:
        length = len(packet)
        # Pack the length as a 2-byte (16-bit) integer
        return struct.pack('!H', length)

    # Build UDP packet
    @staticmethod
    def build_udp_packet(encrypted_payload: bytes, auth_token) -> bytes:
        payload_hmac = generate_hmac(encrypted_payload, auth_token)
        len_field = vpn_protocol.build_len_field(payload_hmac + encrypted_payload)
        return len_field + encrypted_payload + payload_hmac

    @staticmethod
    def extract_vpn_packet(packet: bytes, auth_token) -> bytes | None:
        len_field = packet[:2]
        encrypted_packet = packet[2:-32]  # Remove the last 32 bytes for HMAC
        hmac_field = packet[-32:]  # Last 32 bytes for SHA256 HMAC
        if verify_hmac(encrypted_packet, hmac_field, auth_token):
            return encrypted_packet
        return None  # Return None if verification fails

    @staticmethod
    def build_vpn_packet(packet: bytes, version: int = 1) -> bytes:
        # Pack the version as a single byte
        version_byte = struct.pack('B', version)  # 'B' stands for unsigned char (1 byte)
        return version_byte + packet

    @staticmethod
    def extract_payload(packet: bytes) -> bytes | None:
        if vpn_protocol.verify_vpn_packet(packet):
            return packet[1:]
        return None

    @staticmethod
    def verify_vpn_packet(packet: bytes, version: int = 1) -> bool:
        return version == packet[0]

    #error packets
    #Build error or something

import os
def main():
    print("test starts here\n\n")
    # Test data for the packet
    data = b"Hello, World!"  # Data (13 bytes)
    
    # Generate a random authentication token (16 bytes)
    auth_token = os.urandom(16)
    
    # Test the VPN Protocol Build & Packet Creation
    vpn = vpn_protocol()
    
    # Build the VPN packet with the data
    vpn_packet = vpn.build_vpn_packet(data)
    print(f"Built VPN Packet: {vpn_packet}")

    aes_key = os.urandom(32)
    encrypted_data = aes_encrypt(aes_key, vpn_packet)  # Using a random AES key for encryption

    # Build UDP packet with HMAC and length field
    udp_packet = vpn.build_udp_packet(encrypted_data, auth_token)
    print(f"Built UDP Packet with HMAC and Length Field: {udp_packet}")


    # Extract the VPN packet and verify HMAC
    extracted_vpn_packet = vpn.extract_vpn_packet(udp_packet, auth_token)
    if extracted_vpn_packet:
        print(f"Extracted VPN Packet: {extracted_vpn_packet}")
        print(vpn.extract_payload(aes_decrypt(aes_key, extracted_vpn_packet)))
    else:
        print("HMAC verification failed!")

if __name__ == "__main__":
    main()