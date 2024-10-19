import socket
import threading

CLIENT_IP = "192.168.1.107"  # client host IP A.B.C.D
CLIENT_PORT = 50602  # client port for receiving communication
SERVER_IP = "192.168.1.108"  # server host IP (public IP) A.B.C.D
SERVER_PORT = 50601

class Header:
    def __init__(self, seq_number, flags, mess_type, checksum, payload_size, payload) -> None:
        pass
    def build_packet(self):
        pass
    def parse_packet(self, packet):#bez self
        pass

class Client:
    def __init__(self, ip, port, server_ip, server_port) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP socket creation
        self.server_ip = server_ip
        self.server_port = server_port
        self.sock.bind((ip, port))  # Bind to the client IP and port
        self.running = True  # Control flag to stop threads

    def receive(self):
        while self.running:
            try:
                data, _ = self.sock.recvfrom(1024)  # Buffer size is 1024 bytes
                #parsenut data
                print(f"\nServer: {data.decode('utf-8')}")
            except:
                break

    def send(self):
        while self.running:
            message = input("You (Client): ")
            self.send_message(message)
            if message.lower() == "quit":
                self.running = False
                break

    def three_way_handshake(self):
        # Step 1: Send SYN to the server
        print("Sending SYN to the server...")
        self.send_message("SYN")
        
        # Step 2: Receive SYN-ACK from the server
        response, _ = self.sock.recvfrom(1024)
        response = response.decode('utf-8')
        if response == "SYN-ACK":
            print("Received SYN-ACK from the server...")
            
            # Step 3: Send ACK to the server
            print("Sending ACK to the server...")
            self.send_message("ACK")
            return True
        return False

    def send_message(self, message):
        self.sock.sendto(bytes(message, encoding="utf-8"), (self.server_ip, self.server_port))

    def quit(self):
        self.running = False
        self.sock.close()
        print("Client closed...")

class Server:
    def __init__(self, ip, port) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP socket creation
        self.sock.bind((ip, port))  # Needs to be tuple (string, int)
        self.client = None
        self.running = True  # Control flag to stop threads

    def receive(self):
        while self.running:
            try:
                data, self.client = self.sock.recvfrom(1024)  # Buffer size is 1024 bytes
                #parsenut data
                print(f"\nClient: {data.decode('utf-8')}")
            except:
                break

    def send(self):
        while self.running:
            message = input("You (Server): ")
            self.send_response(message)
            if message.lower() == "quit":
                self.running = False
                break

    def three_way_handshake(self):
        # Step 1: Receive SYN from the client
        print("Waiting for SYN from client...")
        message, self.client = self.sock.recvfrom(1024)
        message = message.decode('utf-8')
        if message == "SYN":
            print("Received SYN from client...")

            # Step 2: Send SYN-ACK to the client
            print("Sending SYN-ACK to the client...")
            self.send_response("SYN-ACK")

            # Step 3: Receive ACK from the client
            ack, _ = self.sock.recvfrom(1024)
            if ack.decode('utf-8') == "ACK":
                print("Received ACK from client... Connection established!")
                return True
        return False

    def send_response(self, message):
        if self.client:
            self.sock.sendto(message.encode('utf-8'), self.client)

    def quit(self):
        self.running = False
        self.sock.close()
        print("Server closed...")

def run_client():
    client = Client(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT)

    # Perform 3-way handshake
    if client.three_way_handshake():
        print("Handshake successful. Ready to chat...")

        # Start threads for sending and receiving messages
        recv_thread = threading.Thread(target=client.receive)
        send_thread = threading.Thread(target=client.send)

        recv_thread.start()
        send_thread.start()

        send_thread.join()  # Wait for send_thread to finish
        client.quit()  # Clean up and close the connection
    else:
        print("Handshake failed.")
        client.quit()

def run_server():
    server = Server(SERVER_IP, SERVER_PORT)

    # Perform 3-way handshake
    if server.three_way_handshake():
        print("Handshake successful. Ready to chat...")

        # Start threads for sending and receiving messages
        recv_thread = threading.Thread(target=server.receive)
        send_thread = threading.Thread(target=server.send)

        recv_thread.start()
        send_thread.start()

        send_thread.join()  # Wait for send_thread to finish
        server.quit()  # Clean up and close the connection
    else:
        print("Handshake failed.")
        server.quit()

def main():
    main_choice = input("Server/Client? (c/s): ")
    if main_choice == 'c':
        run_client()
    elif main_choice == 's':
        run_server()
    else:
        print("Invalid id")

if __name__ == "__main__":
    main()
