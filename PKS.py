import socket
import threading

# Define IP and Ports for both peers
CLIENT_IP = "192.168.1.106"  # Client IP (Peer 1)
CLIENT_PORT = 50602  # Client port

SERVER_IP = "192.168.1.108"  # Server IP (Peer 2)
SERVER_PORT = 50601  # Server port


class Client:
    def __init__(self, ip, port, server_ip, server_port):
        # Create a UDP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((ip, port))  # Bind to client's own IP and port

        self.server_ip = server_ip
        self.server_port = server_port

    def send_message(self, message):
        """Send a message to the server (or peer)."""
        self.sock.sendto(message.encode("utf-8"), (self.server_ip, self.server_port))

    def receive_message(self):
        """Receive messages from the server (or peer)."""
        while True:
            data, _ = self.sock.recvfrom(1024)  # Buffer size is 1024 bytes
            print("Received from server:", data.decode("utf-8"))

    def quit(self):
        """Close the client socket."""
        self.sock.close()
        print("Client closed.")


class Server:
    def __init__(self, ip, port):
        # Create a UDP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((ip, port))  # Bind to server's IP and port

    def receive_message(self):
        """Receive messages from the client (or peer)."""
        while True:
            data, self.client = self.sock.recvfrom(1024)  # Buffer size is 1024 bytes
            print("Received from client:", data.decode("utf-8"))

    def send_response(self, message):
        """Send a message back to the client (or peer)."""
        self.sock.sendto(message.encode("utf-8"), self.client)

    def quit(self):
        """Close the server socket."""
        self.sock.close()
        print("Server closed.")


def run_client():
    client = Client(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT)

    # Start a thread for receiving messages from the server (peer)
    receive_thread = threading.Thread(target=client.receive_message)
    receive_thread.daemon = True  # Daemon thread exits when the main program exits
    receive_thread.start()

    # Send messages in the main thread
    while True:
        message = input("Input your message (type 'exit' to quit): ")
        if message.lower() == "exit":
            client.quit()
            break
        client.send_message(message)


def run_server():
    server = Server(SERVER_IP, SERVER_PORT)

    # Start a thread for receiving messages from the client (peer)
    receive_thread = threading.Thread(target=server.receive_message)
    receive_thread.daemon = True  # Daemon thread exits when the main program exits
    receive_thread.start()

    # Send responses in the main thread
    while True:
        message = input("Input response (type 'exit' to quit): ")
        if message.lower() == "exit":
            server.quit()
            break
        server.send_response(message)


def main():
    role_choice = input("Are you Client or Server? (c/s): ").lower()

    if role_choice == 'c':
        run_client()
    elif role_choice == 's':
        run_server()
    else:
        print("Invalid input. Choose 'c' for Client or 's' for Server.")


if __name__ == "__main__":
    main()