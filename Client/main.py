import socket
import ssl


def connect_to_server(host, port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_socket = ssl.wrap_socket(client_socket)

    ssl_socket.connect((host, port))
    print("Connected to server:", (host, port))

    while True:
        command = input("Enter command (REGISTER or LOGIN): ")
        ssl_socket.sendall(command.encode())

        response = receive_data(ssl_socket)
        print("Server response:", response.decode())

        if response.decode() == b"Login successful.":
            break

    # Authenticated commands
    while True:
        command = input("Enter authenticated command (e.g., SEND, RECEIVE, etc.): ")
        ssl_socket.sendall(command.encode())

        response = receive_data(ssl_socket)
        print("Server response:", response.decode())

    ssl_socket.close()


def receive_data(ssl_socket):
    received_data = b""
    while True:
        data = ssl_socket.recv(1024)
        if not data:
            break
        received_data += data
    return received_data


# Connect to the server
host = 'localhost'
port = 8888
connect_to_server(host, port)
