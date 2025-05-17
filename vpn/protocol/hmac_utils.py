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
    """
    Generate a Hash-based Message Authentication Code (HMAC) using SHA-256.

    Args:
    - data: The data to be authenticated (usually the payload).
    - auth_token: The secret key used for generating the HMAC.
    
    Returns:
    - The HMAC value (a byte string).
    """
    # Use HMAC with SHA-256 to generate the HMAC for the provided data and auth_token
    return hmac.new(auth_token, data, hashlib.sha256).digest()

# Function to verify HMAC
def verify_hmac(data: bytes, received_hmac: bytes, auth_token: bytes) -> bool:
    """
    Verify if the received HMAC matches the expected HMAC for the given data.

    Args:
    - data: The data whose authenticity needs to be verified.
    - received_hmac: The HMAC received with the data, which needs to be validated.
    - auth_token: The secret key used to generate the expected HMAC.

    Returns:
    - True if the received HMAC matches the expected HMAC, False otherwise.
    """
    # Generate the expected HMAC for the provided data and auth_token
    expected_hmac = generate_hmac(data, auth_token)
    # Use hmac.compare_digest to securely compare the expected and received HMACs
    return hmac.compare_digest(expected_hmac, received_hmac)
