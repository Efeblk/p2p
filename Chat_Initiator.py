import json
import time
import socket
import random
import pyDesLib
import datetime
import base64

# Function to display the list of online users
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

def generate_key(p, g):
    private_key = random.randint(1, p - 1)  # Ensure private_key is within [1, p-1]
    shared_key = pow(g, private_key, p)
    return private_key, shared_key, g, p

def read_shared_key_from_json(file_path, p):
    with open(file_path, "r") as json_file:
        public_key_data = json.load(json_file)
    
    public_key = public_key_data["public_value"]
    final_key = pow(public_key, private_key, p)  # private_key needs to be provided
    return final_key


# Function to initiate a secure chat
def initiate_secure_chat(username):
    # Generate private key, shared key, and other necessary parameters
    private_key, shared_key, g, p = generate_key(23, 5)

    # Save the shared key and parameters to a JSON file
    shared_key_data = {
        "public_value": shared_key,
        "p": p,
        "g": g
    }
    
    with open("sent_public_key.json", "w") as json_file:
        json.dump(shared_key_data, json_file)

    message = input("Enter your secure message: ")
    send_message(username, message, shared_key, final_key=None)


# Function to initiate an unsecure chat
def initiate_unsecure_chat(username):
    # Allow the user to type their message
    message = input("Enter your message: ")
    # Send the message to the user 
    send_message(username, message, 0, 0)

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

def send_message(username, message, shared_key, final_key):
    # Create a TCP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with open('users.txt', 'r') as file:
       users = json.load(file)
    users = read_user_data('users.txt')
    ip_address = users[username]['ip_address']
    # Connect to the server
    sock.connect((ip_address, 6001))
    
    # Check if the message is secure
    if shared_key and final_key:
        # Encrypt the message
        encrypted_message = encrypt_message(message, shared_key)
        # Encode the encrypted message as a base64 string
        message = base64.b64encode(encrypted_message).decode()

    # Create the JSON payload
    payload = json.dumps({
        'username': username,
        'message': message,
        'shared_key': shared_key if shared_key and final_key else None,  # Add the shared key to the payload only if the message is secure
        'final_key': final_key if shared_key and final_key else None  # Include the public key in the payload only if the message is secure
    })
    # Send the message
    sock.sendall(payload.encode())
    
    # Close the socket
    sock.close()

    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_message(timestamp, username, message, 'SENT')

# Function to log a message
def log_message(timestamp, username, message, direction):
    
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    log_entry = f"{timestamp} - {username}: {message}"
    with open('chat_log.txt', 'a') as log_file:
        log_file.write(log_entry + '\n')

# Function to encrypt a message
def encrypt_message(message, final_key):
    # Create a new DES cipher object
    final_key = final_key.to_bytes(8, 'big')
    cipher = des(final_key, padmode=PAD_PKCS5)

    # Convert the message to bytes, if necessary
    if isinstance(message, str):
        message = message.encode()

    # Encrypt the message
    encrypted_message = cipher.encrypt(message)

    # Return the encrypted message
    return encrypted_message

# Function to read user data from a file
def read_user_data(filename):
    with open(filename, 'r') as f:
        return json.load(f)

# Main function
def main():
    while True:
        option = input("Specify 'Users', 'Chat', 'History' or 'Exit': ")
        if option.lower() == 'users':
            # Display the list of online users
            users = read_user_data('users.txt')
            # Display the online users
            display_online_users(users)
        elif option.lower() == 'chat':
            # Prompt the user for the username to chat with
            users = read_user_data('users.txt')
            while True:
                username = input("Enter the username to chat with (or 'back' to go back): ")
                if username.lower() == 'back':
                    break
                if username in users:
                    # Prompt the user for secure or unsecure chat
                    secure_chat = input("Do you want to chat securely? (yes/no): ")
                    if secure_chat.lower() == 'yes':
                        initiate_secure_chat(username)
                    else:
                        initiate_unsecure_chat(username)
                    break
                print("Invalid username. Please try again.")
        elif option.lower() == 'history':
            # Display the chat history
            with open('chat_log.txt', 'r') as log_file:
                print(log_file.read())
        elif option.lower() == 'exit':
            break
        else:
            print("Invalid option. Please try again.")

if __name__ == '__main__':
    main()