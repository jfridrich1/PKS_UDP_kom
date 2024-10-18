import socket
import threading

CLIENT_IP = "192.168.1.106"  # Client host IP
CLIENT_PORT = 50602  # Client port for receiving communication
SERVER_IP = "192.168.1.108"  # Server host IP
SERVER_PORT = 50601  # Server port for receiving communication


class Client:
    def __init__(self, ip, port, server_ip, server_port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP socket creation
        self.sock.bind((ip, port))  # Bind the client to its IP and port
        self.server_ip = server_ip
        self.server_port = server_port

    def send_message(self, message):
        """Send a message to the server."""
        self.sock.sendto(message.encode("utf-8"), (self.server_ip, self.server_port))

    def receive(self):
        """Receive messages from the server."""
        while True:
            data, _ = self.sock.recvfrom(1024)  # Buffer size is 1024 bytes
            print("Server says: %s" % data.decode("utf-8"))

    def quit(self):
        """Close the client socket."""
        self.sock.close()
        print("Client closed..")


class Server:
    def __init__(self, ip, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP socket creation
        self.sock.bind((ip, port))  # Bind the server to its IP and port

    def receive(self):
        """Receive messages from the client."""
        while True:
            data, self.client = self.sock.recvfrom(1024)  # Buffer size is 1024 bytes
            print("Client says: %s" % data.decode("utf-8"))

    def send_response(self, message):
        """Send a message back to the client."""
        self.sock.sendto(message.encode("utf-8"), self.client)

    def quit(self):
        """Close the server socket."""
        self.sock.close()
        print("Server closed..")


def run_client():
    client = Client(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT)

    # Start a thread to receive messages from the server
    receive_thread = threading.Thread(target=client.receive)
    receive_thread.daemon = True  # This ensures the thread will exit when the main program exits
    receive_thread.start()

    # Sending messages in the main thread
    while True:
        message = input("You: ")
        if message.lower() == "exit":
            client.quit()
            break
        client.send_message(message)


def run_server():
    server = Server(SERVER_IP, SERVER_PORT)

    # Start a thread to receive messages from the client
    receive_thread = threading.Thread(target=server.receive)
    receive_thread.daemon = True  # This ensures the thread will exit when the main program exits
    receive_thread.start()

    # Sending responses in the main thread
    while True:
        message = input("You: ")
        if message.lower() == "exit":
            server.quit()
            break
        server.send_response(message)


def main():
    main_choice = input("Server/Client? (s/c): ").lower()
    if main_choice == 'c':
        run_client()
    elif main_choice == 's':
        run_server()
    else:
        print("Invalid choice.")


if __name__ == "__main__":
    main()
