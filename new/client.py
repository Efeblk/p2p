import random
import json
import threading
import time
import socket
import base64
import datetime

def genarate_private_key(): 
    # Always generate a new private key
    private_key = random.randint(1, 23)
    return private_key

def generate_public_key(private_key):
    with open("p_and_g.json", "r") as json_file:
        data = json.load(json_file)
    p = data["p"]
    g = data["g"]
    public_key = pow(g, private_key, p)

    return public_key

def generate_shared_key(public_key, private_key):
    with open("p_and_g.json", "r") as json_file:
        data = json.load(json_file)
    p = data["p"]
    shared_key = pow(public_key, private_key, p)
    return shared_key

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
    display_online_users(users)
    print(users)

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

def listen_connection():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ip_address = ip_address_self
    server_socket.bind((ip_address, 6001))
    server_socket.listen(1)
    server_socket.settimeout(1)  # Set a timeout of 1 second

    try:
        while True:
            if message_thread_stop:
                return
            try:
                client_socket, address = server_socket.accept()
            except socket.timeout:
                continue  # If accept() times out, skip to the next iteration of the loop
            handle_client_connection(client_socket)
    finally:
        server_socket.close()

def handle_client_connection(client_socket):
    try:
        while True:
            if message_thread_stop:
                return
            message = client_socket.recv(1024)
            if not message:
                break
            payload = json.loads(message.decode())
            rcv_username = payload.get('username')
            rcv_public_key = payload.get('public_key')
            is_response = payload.get('is_response')
            print("is response")
            print(is_response)
            print(type(is_response))
            if is_response == False:
                #im not the one who initiated the chat
                print(f"IM NOT THE SENDER")
                private_key = genarate_private_key() #this is for server
                public_key = generate_public_key(private_key) #this is for server
                shared_key = generate_shared_key(rcv_public_key, private_key)
                send_public_key(rcv_username, public_key, True) #send my public key to the other user

                found = False
                with open('key_cache.json', 'r') as file:
                    data = json.load(file)
                    print(data)
                    for key in data:
                        if key["username"] == rcv_username:
                            found = True
                            key["private_key"] = private_key
                            key["public_key"] = public_key
                            key["shared_key"] = shared_key
                            break
                with open('key_cache.json', 'w') as file:
                    json.dump(data, file)
                if found == False:
                    add_key(rcv_username, private_key, public_key, shared_key)
            elif is_response == True:
                #im the one who initiated the chat
                print(f"IM THE SENDER")
                with open('key_cache.json', 'r') as file:
                    data = json.load(file)
                    print(data)
                    for key in data:
                        if key["username"] == rcv_username:
                            shared_key = generate_shared_key(rcv_public_key, key["private_key"])
                            key["shared_key"] = shared_key
                            break
                with open('key_cache.json', 'w') as file:
                    json.dump(data, file)
    except Exception as e:
        print(f"Error handling client connection: {e}")
    finally:
        client_socket.close()

def send_public_key(username, public_key, is_response):
    # Create a TCP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    user_ip_address = users[username]['ip_address']
    sock.connect((user_ip_address, 6001))
    payload = json.dumps({"username": self_username, "public_key": public_key, "ip_address": ip_address_self, "is_response": is_response})
    sock.sendall(payload.encode())

def initiate_secure_chat(username):
    private_key = genarate_private_key()
    public_key = generate_public_key(private_key)
    add_key(username, private_key, public_key, -1)
    send_public_key(username, public_key, False)

def initiate_chat():
    # Prompt the user for the username to chat with
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
            # Write the user data to a file
            with open('users.txt', 'w') as f:
                json.dump(users, f)
        except json.JSONDecodeError:
            pass

def add_key(username, private_key, public_key, shared_key):
    # Load the existing keys
    keys = []
    try:
        with open("key_cache.json", 'r') as json_file:
            keys = json.load(json_file)
    except:
        print("no data")

    keys.append({"username": username, "private_key": private_key, "public_key": public_key, "shared_key": shared_key})
    # Write the updated keys back to the file
    with open("key_cache.json", "w") as json_file:
        json.dump(keys, json_file)

def main():
    global announce_thread_stop
    global listen_thread_stop
    global message_thread_stop
    global users

    users = {}

    message_thread_stop = False
    listen_thread_stop = False
    announce_thread_stop = False
    
    global self_username
    global ip_address_self

    ip_address_self = get_ip_address()
    self_username = ask_for_username()

    with open('key_cache.json', 'w'):
        pass

    announce_thread = threading.Thread(target=live_self_announce, args=(self_username,))
    listen_thread = threading.Thread(target=listen_for_broadcasts)
    message_listener_thread = threading.Thread(target=listen_connection)
    listen_thread.start()
    announce_thread.start()
    message_listener_thread.start()

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
    listen_thread.join() # Wait for the thread to finish
    announce_thread_stop = True
    announce_thread.join() # Wait for the thread to finish
    message_thread_stop = True
    message_listener_thread.join() # Wait for the thread to finish
    
    
if __name__ == '__main__':
    main()