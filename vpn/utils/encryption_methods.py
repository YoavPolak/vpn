from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# RSA Key Generation
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Encrypt AES key with RSA Public Key
def encrypt_with_rsa(public_key, aes_key):
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return encrypted_key

# Decrypt AES key with RSA Private Key
def decrypt_with_rsa(private_key, encrypted_key):
    decrypted_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return decrypted_key

# AES Encryption
def aes_encrypt(key, plaintext: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + ciphertext

# AES Decryption
def aes_decrypt(key, ciphertext: bytes) -> bytes:
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
    return plaintext

# Example Communication
def main():
    # Step 1: Generate RSA keys for two parties (Alice and Bob)
    alice_private_key, alice_public_key = generate_rsa_keys()
    bob_private_key, bob_public_key = generate_rsa_keys()
    
    # Serialize Bob's public key to send to Alice
    serialized_bob_public_key = bob_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    
    # Alice receives Bob's public key
    bob_public_key = serialization.load_pem_public_key(serialized_bob_public_key)
    
    # Step 2: Alice generates an AES key
    aes_key = os.urandom(32)  # AES-256
    
    # Step 3: Alice encrypts the AES key using Bob's public key
    encrypted_aes_key = encrypt_with_rsa(bob_public_key, aes_key)
    
    # Step 4: Bob decrypts the AES key using his private key
    decrypted_aes_key = decrypt_with_rsa(bob_private_key, encrypted_aes_key)
    
    # Step 5: Verify the AES key matches
    assert aes_key == decrypted_aes_key, "AES key mismatch!"
    
    # Step 6: Use the shared AES key for encryption/decryption
    plaintext = b"Hello, secure world!"
    encrypted_message = aes_encrypt(aes_key, plaintext)
    decrypted_message = aes_decrypt(aes_key, encrypted_message)
    
    print(f"Original Message: {plaintext}")
    print(f"Encrypted Message: {encrypted_message}")
    print(f"Decrypted Message: {decrypted_message}")

if __name__ == "__main__":
    main()
    #example for gal and guy :)
