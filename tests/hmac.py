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


import hashlib
import hmac

# Function to generate HMAC using the auth token
def generate_hmac(data: bytes, auth_token: bytes):
    return hmac.new(auth_token, data, hashlib.sha256).digest()

# Function to verify HMAC
def verify_hmac(data: bytes, received_hmac: bytes, auth_token: bytes) -> bool:
    expected_hmac = generate_hmac(data, auth_token)
    return hmac.compare_digest(expected_hmac, received_hmac)



#Main unecessary things
from vpn.utils.encryption_methods import *  # Assume aes_encrypt and aes_decrypt are defined here    
import os
def main ():
    # Simulate key exchange - both client and server share this secret AES key
    AES_KEY = os.urandom(32)  # Shared AES key for encrypting the packet
    
    # Generate a random auth token (16 bytes) to authenticate the packet
    AUTH_TOKEN = os.urandom(16)  # Shared auth token for HMAC generation


    # Header information
    version = 1
    payload = "This is the encrypted message!"
    payload_length = len(payload)

    # Build header (non-encrypted) - includes the auth token
    header = f"version={version},payload_len={payload_length}"

    # Encrypt the entire packet (header + payload)
    packet = header.encode() + payload.encode()
    encrypted_packet = aes_encrypt(AES_KEY, packet)

    # Generate HMAC for the entire encrypted packet using the auth token
    header_and_payload_hmac = generate_hmac(encrypted_packet, AUTH_TOKEN)

    # Combine everything: encrypted packet + HMAC
    final_packet = encrypted_packet + header_and_payload_hmac
    print(f"Packet sent: {final_packet}")

    # Step 2: Server-side packet handling

    # Separate the packet components
    received_encrypted_packet = final_packet[:-32]  # Remove the last 32 bytes for HMAC
    received_hmac = final_packet[-32:]  # Last 32 bytes for SHA256 HMAC

    # Verify the HMAC (to ensure packet integrity)
    if not verify_hmac(received_encrypted_packet, received_hmac, AUTH_TOKEN):
        raise ValueError("HMAC verification failed! Packet integrity compromised.")

    # Decrypt the entire packet (header + payload)
    decrypted_packet = aes_decrypt(AES_KEY, received_encrypted_packet)

    # Separate the decrypted header and payload
    header_end = len(header.encode())  # Find the length of the header
    decrypted_header = decrypted_packet[:header_end]
    decrypted_payload = decrypted_packet[header_end:].decode()

    # Output the results
    print(f"Decrypted Header: {decrypted_header.decode()}")
    print(f"Decrypted Payload: {decrypted_payload}")

if __name__ == "__main__":
    main()