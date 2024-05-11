import socket
import json
import time

# Function to send broadcast UDP messages
def send_broadcast(username, ip_address, interval=8):
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # Create the JSON payload
    payload = json.dumps({"username": username, "ip_address": ip_address})

    while True:
        try:
            # Send the broadcast message
            sock.sendto(payload.encode(), ('255.255.255.255', 6000)) #'<broadcast>'
        except Exception as e:
            pass

        # Wait for the specified interval before sending the next broadcast
        time.sleep(interval)

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

def main():
    # Ask the user to specify their username
    username = input("Please enter your username: ")

    # Get the IP address
    ip_address = get_ip_address()

    # Start sending broadcast messages
    send_broadcast(username, ip_address)

if __name__ == "__main__":
    main()