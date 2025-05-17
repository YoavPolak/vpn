from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

BLOCK_SIZE = 16  # AES block size (AES operates in fixed 128-bit blocks)
AES_KEY_SIZE = 32  # AES-256 (AES key size of 256 bits)

# RSA Key Generation
def generate_rsa_keys():
    """
    Generates a pair of RSA keys (private and public keys).
    
    Returns:
    - private_key: The generated RSA private key.
    - public_key: The generated RSA public key.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # Public exponent commonly used in RSA
        key_size=2048,  # Key size of 2048 bits
    )
    public_key = private_key.public_key()  # Extract the corresponding public key
    return private_key, public_key

# Encrypt AES key with RSA Public Key
def encrypt_with_rsa(public_key, aes_key):
    """
    Encrypts an AES key using RSA public key encryption with OAEP padding.
    
    Args:
    - public_key: RSA public key used for encryption.
    - aes_key: AES key to be encrypted.

    Returns:
    - encrypted_key: The encrypted AES key.
    """
    encrypted_key = public_key.encrypt(
        aes_key,  # AES key to be encrypted
        padding.OAEP(  # OAEP padding scheme for RSA encryption
            mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Mask Generation Function using SHA256
            algorithm=hashes.SHA256(),  # Hashing algorithm used
            label=None,  # No label for encryption
        ),
    )
    return encrypted_key

# Decrypt AES key with RSA Private Key
def decrypt_with_rsa(private_key, encrypted_key):
    """
    Decrypts the AES key using RSA private key decryption with OAEP padding.
    
    Args:
    - private_key: RSA private key used for decryption.
    - encrypted_key: The encrypted AES key.

    Returns:
    - decrypted_key: The decrypted AES key.
    """
    decrypted_key = private_key.decrypt(
        encrypted_key,  # The encrypted AES key to be decrypted
        padding.OAEP(  # OAEP padding scheme for RSA decryption
            mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Mask Generation Function using SHA256
            algorithm=hashes.SHA256(),  # Hashing algorithm used
            label=None,  # No label for decryption
        ),
    )
    return decrypted_key

# AES Encryption
def aes_encrypt(key, plaintext: bytes) -> bytes:
    """
    Encrypts a message using AES encryption with the given AES key.
    
    Args:
    - key: AES key used for encryption.
    - plaintext: The message to be encrypted.

    Returns:
    - ciphertext: The encrypted message (including initialization vector).
    """
    iv = os.urandom(BLOCK_SIZE)  # Generate a random initialization vector (IV)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))  # Use AES in CFB mode
    encryptor = cipher.encryptor()  # Create an encryptor object
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()  # Encrypt the plaintext
    return iv + ciphertext  # Return the IV concatenated with the ciphertext

# AES Decryption
def aes_decrypt(key, ciphertext: bytes) -> bytes:
    """
    Decrypts an AES-encrypted message using the given AES key.
    
    Args:
    - key: AES key used for decryption.
    - ciphertext: The encrypted message (including initialization vector).

    Returns:
    - plaintext: The decrypted message.
    """
    iv = ciphertext[:BLOCK_SIZE]  # Extract the initialization vector from the ciphertext
    actual_ciphertext = ciphertext[BLOCK_SIZE:]  # Extract the actual encrypted message
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))  # Use AES in CFB mode with the extracted IV
    decryptor = cipher.decryptor()  # Create a decryptor object
    plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()  # Decrypt the ciphertext
    return plaintext  # Return the decrypted message

# Example Communication
def main():
    """
    Simulates an example communication between two parties (Alice and Bob) using RSA and AES.
    """
    # Step 1: Generate RSA keys for two parties (Alice and Bob)
    alice_private_key, alice_public_key = generate_rsa_keys()
    bob_private_key, bob_public_key = generate_rsa_keys()
    
    # Serialize Bob's public key to send to Alice (convert to PEM format)
    serialized_bob_public_key = bob_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,  # PEM format for public key
        format=serialization.PublicFormat.SubjectPublicKeyInfo,  # Standard format for public keys
    )
    
    # Alice receives Bob's public key (this is a simulation, typically done via secure transmission)
    bob_public_key = serialization.load_pem_public_key(serialized_bob_public_key)
    
    # Step 2: Alice generates an AES key (randomly generated 256-bit AES key)
    aes_key = os.urandom(32)  # AES-256 key size is 32 bytes (256 bits)
    
    # Step 3: Alice encrypts the AES key using Bob's public key (RSA encryption)
    encrypted_aes_key = encrypt_with_rsa(bob_public_key, aes_key)
    
    # Step 4: Bob decrypts the AES key using his private key (RSA decryption)
    decrypted_aes_key = decrypt_with_rsa(bob_private_key, encrypted_aes_key)
    
    # Step 5: Verify the AES key matches the original key Alice generated
    assert aes_key == decrypted_aes_key, "AES key mismatch!"  # Ensure the AES key is the same
    
    # Step 6: Use the shared AES key for encryption/decryption of a message
    plaintext = b"Hello, secure world!"  # Message to be encrypted
    encrypted_message = aes_encrypt(aes_key, plaintext)  # Encrypt the message with AES
    decrypted_message = aes_decrypt(aes_key, encrypted_message)  # Decrypt the message with AES
    
    # Output the results
    print(f"Original Message: {plaintext}")
    print(f"Encrypted Message: {encrypted_message}")
    print(f"Decrypted Message: {decrypted_message}")

if __name__ == "__main__":
    main()
