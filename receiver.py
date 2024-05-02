from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pss
import os

def read_private_key(filename):
    """Reads and imports the private RSA key from a file."""
    with open(filename, 'rb') as f:
        key_data = f.read()
# Extract the private key
    private_key_data = key_data.split(b'-----END RSA PRIVATE KEY-----')[0] + b'-----END RSA PRIVATE KEY-----\n'
    return RSA.import_key(private_key_data)

def decrypt_aes_key_with_rsa(encrypted_key, private_key):
    """Decrypts the AES key using RSA private key."""
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_key)
    return aes_key

def decrypt_message_aes(nonce, ciphertext, tag, aes_key):
    """Decrypts the AES encrypted message."""
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    return data.decode('utf-8')

def verify_mac(ciphertext, mac, public_key):
    """Verifies the MAC of the ciphertext using the sender's public RSA key."""
    h = SHA256.new(ciphertext)
    verifier = pss.new(public_key)
    try:
        verifier.verify(h, mac)
        return True
    except (ValueError, TypeError):
        return False

# Read the private RSA key of the receiver
receiver_private_key = read_private_key('receiver_keys.pem')

# Read the transmitted data
with open('Transmitted_Data.txt', 'rb') as f:
    encrypted_aes_key = f.read(256)  # RSA key size / 8
    nonce = f.read(16)  # AES block size
    #ciphertext = f.read(len(f.read()) - 256 - 32)  # Subtract MAC and tag size
    ciphertext = f.read(-1)[:-272]  # Read all except for the last 256 bytes (MAC tag)
    f.seek(-272, os.SEEK_END)  # Go to 16 bytes before the end of the file
    tag = f.read(16)  # AES tag is fixed size
    mac = f.read(256)  # Signature size


# Decrypt the AES key
aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, receiver_private_key)

# Decrypt the message
#message = decrypt_message_aes(nonce, ciphertext, tag, aes_key)
try:
    message = decrypt_message_aes(nonce, ciphertext, tag, aes_key)
    print("Decrypted message:", message)
except ValueError as e:
    print("Decryption failed:", e)
# Read sender's public key to verify MAC
sender_public_key = RSA.import_key(open('sender_keys.pem', 'rb').read().split(b'\n-----END RSA PRIVATE KEY-----\n')[1])

# Verify MAC
if verify_mac(ciphertext, mac, sender_public_key):
    print("MAC verified successfully. Message integrity confirmed.")
else:
    print("MAC verification failed. The message may have been tampered with.")
