import os
import socket
import ssl

from keygen import *
from messcrypt import *


def connect_to_server(host, port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_socket = ssl.wrap_socket(client_socket)

    ssl_socket.connect((host, port))
    print("Connected to server:", (host, port))

    with open('../Server/server_public_key.pem', 'rb') as key_file:
        server_pub = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    while True:
        command = input("Enter command (REGISTER or LOGIN): ")
        # print(encrypt_message(command.encode(), server_pub))
        ssl_socket.sendall(encrypt_message(command.encode(), server_pub))
        _, username, password = command.split()
        response = receive_data(ssl_socket)
        print("Server response:", response.decode())

        if response.decode() == "Login successful.":
            break

    key_gen(username, password)
    # Authenticated commands
    while True:
        command = input("Enter authenticated command (e.g., CONNECT, SEND, RECEIVE, FORWARD.): ")
        ssl_socket.sendall(encrypt_message(command.encode(), server_pub))
        response = receive_data(ssl_socket)
        print("Server response:", response.decode("latin1"))
        if command.startswith("CONNECT"):
            _, my_user, target_user = command.split()
            res = response.decode("latin1").split("||")
            signature = res[1].encode("latin1")
            # verified = verify_message()
            # dec = encrypt_message(response, server_pub).decode().strip()
            # print(dec)
            # splitted = dec.split()
            # if dec[0] == target_user and dec[2] == my_user:
            #     target_public = dec[1]
            #     nonce = os.urandom(16)
            #     plain = nonce.decode() + " " + my_user
            #     encrypted = encrypt_message(plain, target_public)
            #     command = "FORWARD " + encrypted + " " + target_user
            #     print(command)
            #     encrypted = encrypt_message(command.encode(), target_public)
            #     print(encrypted)
            #     ssl_socket.sendall(encrypted)
            #     response = receive_data(ssl_socket)
            #     print("Server response:", response.decode())
        if response.decode("latin1") == "logout successful.":
            break

    ssl_socket.close()


def receive_data(ssl_socket):
    received_data = b""
    data = ssl_socket.recv(1024)
    received_data += data
    return received_data
    # while True:
    #     print("inja")
    #     data = ssl_socket.recv(1024)
    #     print(data)
    #     if not data:
    #         print("omad biron")
    #         break
    #     received_data += data
    # print(received_data)
    # return received_data

# Connect to the server
host = 'localhost'
port = 8888
connect_to_server(host, port)
