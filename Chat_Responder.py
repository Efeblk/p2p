import socket
import json
import random
import datetime
import pyPesLib
import base64

def generate_key(p, g):
    private_key = random.randint(1, p - 1)  # Ensure private_key is within [1, p-1]
    shared_key = pow(g, private_key, p)
    return private_key, shared_key, g, p

def decrypt_message(encrypted_message_base64, shared_key):
    shared_key = shared_key.to_bytes(8, 'big')
    cipher = des(shared_key, padmode=PAD_PKCS5)

    encrypted_message = base64.b64decode(encrypted_message_base64)
    decrypted_message = cipher.decrypt(encrypted_message)

    return decrypted_message

def log_message(timestamp, sender, message, direction):
    log_entry = f"{timestamp} - {sender} ({direction}): {message}"
    with open('chat_log.txt', 'a') as log_file:
        log_file.write(log_entry + '\n')

def get_ip_address():
    # Create a socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        # This doesn't actually connect, but it does cause the system to
        # select an interface that would be used for a real connection
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except socket.error:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def chat_responder():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ip_address = get_ip_address()
    server_socket.bind((ip_address, 6001))
    server_socket.listen(1)

    try:
        while True:
            client_socket, address = server_socket.accept()
            handle_client_connection(client_socket)
    finally:
        server_socket.close()

def handle_client_connection(client_socket):
    try:
        while True:
            message = client_socket.recv(1024)
            if not message:
                break
            
            payload = json.loads(message.decode())
            username = payload.get('username')
            message_content = payload.get('message')
            shared_key = payload.get('shared_key')  # Extract the shared key from the payload

            if shared_key:
                # Secure chat
                decrypted_message = decrypt_message(message_content, shared_key)
                decrypted_message_str = decrypted_message.decode()

                print(f"Received secure message from {username}: {decrypted_message_str}")
                timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                log_message(timestamp, username, decrypted_message_str, 'RECEIVED')
            else:
                # Unsecured chat
                print(f"Received unsecured message from {username}: {message_content}")
                timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                log_message(timestamp, username, message_content, 'RECEIVED')

    except Exception as e:
        print(f"Error handling client connection: {e}")
    finally:
        client_socket.close()

if __name__ == '__main__':
    chat_responder()
