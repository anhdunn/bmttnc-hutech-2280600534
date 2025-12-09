from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import socket
import threading

# Connect to server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 12346))

# Generate RSA key for client
client_key = RSA.generate(2048)

# Receive server's public key
server_public_key = RSA.import_key(client_socket.recv(2048))

# Send client's public key
client_socket.send(client_key.publickey().export_key(format='PEM'))

# Receive AES key encrypted with client's public key
encrypted_aes_key = client_socket.recv(2048)

cipher_rsa = PKCS1_OAEP.new(client_key)
aes_key = cipher_rsa.decrypt(encrypted_aes_key)

# AES functions
def encrypt_message(key, message):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return cipher.iv + ciphertext

def decrypt_message(key, encrypted_message):
    if len(encrypted_message) < AES.block_size:
        return ""
    iv = encrypted_message[:AES.block_size]
    ciphertext = encrypted_message[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_message.decode()

# Thread to receive messages
def receive_message():
    while True:
        encrypted_message = client_socket.recv(1024)
        if not encrypted_message:
            break
        decrypted_message = decrypt_message(aes_key, encrypted_message)
        print("Received:", decrypted_message)

# Start thread
receive_thread = threading.Thread(target=receive_message, daemon=True)
receive_thread.start()

# Main loop to send messages
while True:
    message = input("Enter message ('exit' to quit): ")
    encrypted_message = encrypt_message(aes_key, message)
    client_socket.send(encrypted_message)
    if message == "exit":
        break

client_socket.close()
