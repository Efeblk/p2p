import socket
import json
import time

users = {}

def listen_for_broadcasts():
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Set socket options to allow broadcasting
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # Bind the socket to a specific address and port
    sock.bind(('', 6000))

    while True:
        # Receive data from the socket
        data, address = sock.recvfrom(1024)
        try:
            # Parse the received data as JSON
            message = json.loads(data.decode())
            # Extract the username and IP address from the message
            username = message['username']
            ip_address = message['ip_address']
            # Update the last seen time and IP address for the user
            users[username] = {'last_seen': time.time(), 'ip_address': ip_address}
            # Print the received message to the terminal
            print(f"Received broadcast from {username} at {ip_address}")
            # Write the user data to a file
            with open('users.txt', 'w') as f:
                json.dump(users, f)
        except json.JSONDecodeError:
            pass

# Start listening for broadcasts
listen_for_broadcasts()