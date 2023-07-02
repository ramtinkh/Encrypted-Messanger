import socket
import ssl
import json
import threading

import bcrypt
import os
from cryptography.hazmat.primitives.serialization import load_pem_public_key


from Cert import generate_server_cert
from messcrypt import *

# User database (insecure for demonstration purposes)
json_users = []
logged_in_users = []
session_keys = []

def load_users():
    try:
        with open('./users.json') as file:
            jsonify = json.load(file)
            global json_users
            json_users = jsonify
    except json.JSONDecodeError as e:
        print(f"Invalid JSON format: {e}")

def save_users():
    encrypted_users = json_users
    with open('./users.json', 'w') as f:
        json.dump(encrypted_users, f)

def set_session_key():
    pass


def start_server(host, port, certfile, keyfile):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile, keyfile)
    os.remove(keyfile)

    while True:
        print("Waiting for client connection...")

        client_socket, client_address = server_socket.accept()
        print(f"New connection from {client_address}")

        ssl_socket = context.wrap_socket(client_socket, server_side=True)
        # Spawn a new thread to handle the client connection
        thread = threading.Thread(target=handle_client, args=(ssl_socket,))
        thread.start()

def handle_client(ssl_socket):
    authenticated = False
    username = ""

    while True:
        data = ssl_socket.recv(1024)
        if not data:
            break

        message = decrypt_message(data, private_key).decode().strip()

        print("logged in users :", logged_in_users)
        if not authenticated:
            if message.startswith("REGISTER"):
                _, username, password = message.split()
                register_user(username, password)
                response = "Registration successful. Please login."
                ssl_socket.sendall(response.encode())
            elif message.startswith("LOGIN"):
                _, username, password = message.split()
                if authenticate_user(username, password):
                    authenticated = True
                    logged_in_users.append(username)
                    ssl_socket.sendall(b"Login successful.")
                else:
                    ssl_socket.sendall(b"Invalid username or password. Please try again.")
            else:
                ssl_socket.sendall(b"Invalid command. Please register or login.")
        else:
            if message.startswith("ONLINES"):
                onlines = ""
                for i in logged_in_users:
                    onlines += i + " "
                response = "onlines: " + onlines
                ssl_socket.sendall(response.encode())
            if message.startswith("CONNECT"):
                _, my_user, target_user = message.split()
                target_file = "../Client/" + target_user + "public.pem"
                target_pub = ""
                with open(target_file, 'rb') as file_in:
                    target_pub = file_in.read()
                    target_pub = target_pub.decode()
                    target_pub = target_pub[26:-25]
                print(target_pub)
                plain = target_user + " " + target_pub + " " + my_user
                signature = sign_message(plain.encode(), private_key)
                sent = plain + "||" + signature.decode("latin1")
                ssl_socket.sendall(sent.encode("latin1"))
            if message.startswith("LOGOUT"):
                _, username = message.split()
                logged_in_users.remove(username)
                ssl_socket.sendall(b"logout successful.")
                break
            # Process authenticated client commands here
            # ssl_socket.sendall(b"Authenticated command received.")

    ssl_socket.close()


def register_user(username, password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    user_dict = {
        "username": username,
        "hashed_password": hashed_password.decode(),
        "salt": salt.decode()
    }
    json_users.append(user_dict)
    save_users()


def authenticate_user(username, password):
    for i in range(len(json_users)):
        if username == json_users[i]['username']:
            salt = json_users[i]['salt'].encode()
            hashed_pass = bcrypt.hashpw(password.encode('utf-8'), salt)
            if json_users[i]['hashed_password'] == hashed_pass.decode():
                return True
    return False

    # if username in json_users and json_users[username] == password:
    #     return True
    # return False

# Start the server
host = 'localhost'
port = 8888
private_key = generate_server_cert()
certfile = 'server.crt'  # Path to server's SSL certificate
keyfile = 'plain_server.key'   # Path to server's SSL private key
load_users()
start_server(host, port, certfile, keyfile)


