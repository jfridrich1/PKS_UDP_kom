import socket
import threading
import struct

CLIENT_IP = "127.0.0.1"  # Use localhost for testing on the same machine
CLIENT_PORT = 50602
SERVER_IP = "127.0.0.1"  # Use localhost for testing on the same machine
SERVER_PORT = 50601


class Header:
    def __init__(self, mess_type, flags, payload_size, total_frag, frag_offset, checksum, payload) -> None:
        #8B header
        self.mess_type=mess_type
        self.flags=flags
        self.payload_size=payload_size
        self.total_frag=total_frag
        self.frag_offset=frag_offset
        self.checksum=checksum
        self.payload=payload;

    def buildp(self):#Network, 1B(8 flags), 2B(0-2^16),       1B(0-255),        2B(0-2^16),         2B([%]0-2^16)
        head=struct.pack('!B H B H H', self.flags, self.payload_size, self.total_frag, self.frag_offset, self.checksum)
        head=head+self.payload
        return head
    
    def parsep(packet):
        head=packet[:8]
        flags,payload_size,total_frag,frag_offset,checksum=struct.unpack('!B H B H H', head)
        payload=packet[10:10+payload_size]
        return {'flags': flags,'payload_size':payload_size, 'total_frag': total_frag, 'frag_offset': frag_offset, 'checksum': checksum,'payload': payload}

class Client:
    def __init__(self, ip, port, server_ip, server_port) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP socket creation
        self.server_ip = server_ip
        self.server_port = server_port
        self.sock.bind((ip, port))  # Bind to the client IP and port
        self.running_th = True  # Control flag to stop threads

    def receive(self):
        while self.running_th:
            try:
                data, _ = self.sock.recvfrom(1024)  # Buffer size is 1024 bytes
                #parsenut data
                print(f"\nServer: {data.decode('utf-8')}")
            except:
                break

    def send(self):
        while self.running_th:
            message = input("You (Client): ")
            self.send_message(message)
            if message.lower() == "quit":
                self.running_th = False
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
        self.running_th = False
        self.sock.close()
        print("Client closed...")

class Server:
    def __init__(self, ip, port) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP socket creation
        self.sock.bind((ip, port))  # Needs to be tuple (string, int)
        self.client = None
        self.running_th = True  # Control flag to stop threads

    def receive(self):
        while self.running_th:
            try:
                data, self.client = self.sock.recvfrom(1024)  # Buffer size is 1024 bytes
                #parsenut data
                print(f"\nClient: {data.decode('utf-8')}")
            except:
                break

    def send(self):
        while self.running_th:
            message = input("You (Server): ")
            self.send_response(message)
            if message.lower() == "quit":
                self.running_th = False
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
        self.running_th = False
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
