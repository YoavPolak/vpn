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
def generate_hmac(data: bytes, auth_token: bytes) -> bytes:
    return hmac.new(auth_token, data, hashlib.sha256).digest()

# Function to verify HMAC
def verify_hmac(data: bytes, received_hmac: bytes, auth_token: bytes) -> bool:
    expected_hmac = generate_hmac(data, auth_token)
    return hmac.compare_digest(expected_hmac, received_hmac)