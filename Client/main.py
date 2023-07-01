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
        _, username, _ = command.split()
        response = receive_data(ssl_socket)
        print("Server response:", response.decode())

        if response.decode() == "Login successful.":
            break

    # Authenticated commands
    while True:
        command = input("Enter authenticated command (e.g., SEND, RECEIVE, FORWARD.): ")
        ssl_socket.sendall(command.encode())
        response = receive_data(ssl_socket)
        print("Server response:", response.decode())
        if response.decode() == "logout successful.":
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
