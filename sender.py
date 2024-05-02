from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pss
from Crypto.Random import get_random_bytes
import os

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def write_keys_to_file(private_key, public_key, filename):
    with open(filename, 'wb') as f:
        f.write(private_key)
        f.write(b'\n')#-----END RSA PRIVATE KEY-----\n')
        f.write(public_key)

def read_public_key(filename):
    """Reads and imports the public RSA key from a file."""
    with open(filename, 'rb') as f:
        key_data = f.read()
# Extract the public key
    public_key_data = b'-----BEGIN PUBLIC KEY-----' + key_data.split(b'-----BEGIN PUBLIC KEY-----')[1]
    return RSA.import_key(public_key_data)

def encrypt_message_aes(message, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return nonce, ciphertext, tag

def encrypt_aes_key_with_rsa(aes_key, public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_key = cipher_rsa.encrypt(aes_key)
    return enc_key

def create_mac(ciphertext, key):
    h = SHA256.new(ciphertext)
    signer = pss.new(key)
    signature = signer.sign(h)
    return signature

# Generate RSA keys for both parties
sender_private, sender_public = generate_rsa_keys()
receiver_private, receiver_public = generate_rsa_keys()

# Save keys to files (normally you would only have access to your own private key and the other's public key)
write_keys_to_file(sender_private, sender_public, 'sender_keys.pem')
write_keys_to_file(receiver_private, receiver_public, 'receiver_keys.pem')

# Read the public key of the receiver (simulating key distribution)
receiver_pub_key = read_public_key('receiver_keys.pem')

# Define a message to encrypt
message = "Hello, this is a secure message."

# Generate a random AES key
aes_key = get_random_bytes(16)

# Encrypt the message with AES
nonce, ciphertext, tag = encrypt_message_aes(message, aes_key)

# Encrypt the AES key with the receiver's RSA public key
encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, receiver_pub_key)

# Create MAC for the ciphertext
mac = create_mac(ciphertext, RSA.import_key(sender_private))

# Save transmitted data to a file
with open('Transmitted_Data.txt', 'wb') as f:
    f.write(encrypted_aes_key)
    f.write(nonce)
    f.write(ciphertext)
    f.write(tag)
    f.write(mac)

print("Data encrypted and written to 'Transmitted_Data.txt'")
