import random
import json
import threading
import time
import socket


def genarate_private_key(): 
    # Always generate a new private key
    private_key = random.randint(1, 23)
    with open("private_key.json", "w") as json_file:
        json.dump({"private_key": private_key, "public_key": -1}, json_file)
    return private_key

def generate_public_key(private_key):
    with open("p_and_g.json", "r") as json_file:
        data = json.load(json_file)
    p = data["p"]
    g = data["g"]
    public_key = pow(g, private_key, p)
    with open("public_key.json", "w") and open("public_key.json", "r") as json_file:
        data = json.load(json_file)

    return public_key


def display_online_users(users):
    current_time = time.time()
    for username, user_info in users.items():
        last_seen = user_info['last_seen']
        time_difference = current_time - last_seen
        if time_difference <= 10:
            status = 'Online'
        else:
            status = 'Away'
        print(f"{username} ({status})")

def list_users():
    print(users)
    display_online_users(users)

def initiate_chat():
     # Prompt the user for the username to chat with
            users = read_user_data('users.txt')
            while True:
                username = input("Enter the username to chat with (or 'back' to go back): ")
                username = username.lower()
                if username == 'back':
                    break
                if username in users:
                    # Prompt the user for secure or unsecure chat
                    secure_chat = input("Do you want to chat securely? (yes/no): ")
                    secure_chat = secure_chat.lower()
                    if secure_chat == 'yes':
                        initiate_secure_chat(username)
                    else:
                        initiate_unsecure_chat(username)
                    break
                print("Invalid username. Please try again.")

def print_history():
    # Display the chat history
    with open('chat_log.txt', 'r') as log_file:
        print(log_file.read())

def ask_for_username():
    # Prompt the user for their username
    username = input("Please enter your username: ")
    return username

def send_broadcast(username, ip_address, interval=8):
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # Create the JSON payload
    payload = json.dumps({"username": username, "ip_address": ip_address})

    while True:
        if announce_thread_stop:
            return
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

def live_self_announce(username):
    # Get the IP address
    global ip_address_self
    ip_address_self = get_ip_address()

    # Start sending broadcast messages
    send_broadcast(username, ip_address_self)

def listen_for_broadcasts():
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Set socket options to allow broadcasting
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # Bind the socket to a specific address and port
    sock.bind(('', 6000))

    while True:
        if listen_thread_stop:
            return
        data, address = sock.recvfrom(1024)
        try:
            # Parse the received data as JSON
            message = json.loads(data.decode())
            # Extract the username and IP address from the message
            username = message['username']
            ip_address = message['ip_address']
            if ip_address == ip_address_self:
                continue
            # Update the last seen time and IP address for the user
            users[username] = {'last_seen': time.time(), 'ip_address': ip_address}
            # Print the received message to the terminal
            print(f"Received broadcast from {username} at {ip_address}")
            # Write the user data to a file
            with open('users.txt', 'w') as f:
                json.dump(users, f)
        except json.JSONDecodeError:
            pass


def main():
    global announce_thread_stop
    global listen_thread_stop
    global users

    users = {}

    listen_thread_stop = False
    announce_thread_stop = False
    
    username = ask_for_username()

    announce_thread = threading.Thread(target=live_self_announce, args=(username,))
    listen_thread = threading.Thread(target=listen_for_broadcasts)
    listen_thread.start()
    announce_thread.start()

    #private_key = genarate_private_key()
    #print(private_key)
    #public_key = generate_public_key(private_key)
    #print(public_key)
    while True:
        option = input("Specify 'Users', 'Chat', 'History' or 'Exit': ")
        option = option.lower()
        
        if option == 'users':
            list_users()
        elif option == 'chat':
            initiate_chat()
        elif option == 'history':
            print_history()
        elif option == 'exit':
            break
        else:
            print("Invalid option. Please try again.")
    print("Exiting...")
    listen_thread_stop = True
    listen_thread.join()
    announce_thread_stop = True
    announce_thread.join()
    
if __name__ == '__main__':
    main()