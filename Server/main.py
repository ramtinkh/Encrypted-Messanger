import os
import socket
import ssl

from Cert import *

# User database (insecure for demonstration purposes)
users = {
    "user1": "password1",
    "user2": "password2",
}

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
        print("Client connected:", client_address)

        ssl_socket = context.wrap_socket(client_socket, server_side=True)
        handle_client(ssl_socket)

def handle_client(ssl_socket):
    authenticated = False
    username = ""

    while True:
        data = ssl_socket.recv(1024)
        if not data:
            break

        message = data.decode().strip()

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
                    print(authenticated)
                    ssl_socket.sendall(b"Login successful.")
                else:
                    ssl_socket.sendall(b"Invalid username or password. Please try again.")
            else:
                ssl_socket.sendall(b"Invalid command. Please register or login.")
        else:
            # Process authenticated client commands here
            ssl_socket.sendall(b"Authenticated command received.")

    ssl_socket.close()

def register_user(username, password):
    users[username] = password

def authenticate_user(username, password):
    if username in users and users[username] == password:
        return True
    return False

# Start the server
host = 'localhost'
port = 8888
generate_server_cert()
certfile = 'server.crt'  # Path to server's SSL certificate
keyfile = 'plain_server.key'   # Path to server's SSL private key
start_server(host, port, certfile, keyfile)


