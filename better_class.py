import socket
import threading
import struct

class Header:
    def __init__(self, flags, payload_size, total_frag, frag_offset, checksum, payload) -> None:
        #8B header
        self.flags = flags
        self.payload_size = payload_size
        self.total_frag = total_frag
        self.frag_offset = frag_offset
        self.checksum = checksum
        self.payload = payload

    def build_packet(self):
        if isinstance(self.payload, str):
            self.payload = self.payload.encode('utf-8')
        head = struct.pack('!B H B H H', self.flags, self.payload_size, self.total_frag, self.frag_offset, self.checksum)
        return head + self.payload

    @staticmethod
    def parse_packet(packet):
        head = packet[:8]
        flags, payload_size, total_frag, frag_offset, checksum = struct.unpack('!B H B H H', head)
        payload = packet[8:8+payload_size]
        return {'flags': flags, 'payload_size': payload_size, 'total_frag': total_frag, 'frag_offset': frag_offset, 'checksum': checksum, 'payload': payload}

# Common base class for both Client and Server
class Peer:
    def __init__(self, ip, port) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP socket
        self.sock.bind((ip, port))
        self.client = None
        self.running_th = True

    def send_message(self, message, target=None):
        if isinstance(message, str):
            message = message.encode('utf-8')
        if target is None and self.client:
            target = self.client
        if target:
            self.sock.sendto(message, target)

    def receive(self):
        while self.running_th:
            try:
                data, self.client = self.sock.recvfrom(1024)
                packet = Header.parse_packet(data)
                print(f"\nReceived packet: {packet}")
            except Exception as e:
                print(f"Error in receiving: {e}")
                break

    def send(self):
        while self.running_th:
            message = input(f"You ({self.__class__.__name__}): ")
            flags = 1
            payload_size = len(message)
            total_frag = 2
            frag_offset = 3
            checksum = 1234
            packet = Header(flags, payload_size, total_frag, frag_offset, checksum, message)
            self.send_message(packet.build_packet())

            if message.lower() == "quit":
                self.running_th = False
                break

    def start(self):
        recv_thread = threading.Thread(target=self.receive)
        send_thread = threading.Thread(target=self.send)
        recv_thread.start()
        send_thread.start()
        send_thread.join()

    def quit(self):
        self.running_th = False
        self.sock.close()
        print(f"{self.__class__.__name__} closed...")

# Client class inheriting from Peer
class Client(Peer):
    def __init__(self, ip, port, server_ip, server_port) -> None:
        super().__init__(ip, port)
        self.server_ip = server_ip
        self.server_port = server_port

    def three_way_handshake(self):
        print("Sending SYN to the server...")
        self.send_message("SYN", (self.server_ip, self.server_port))
        response, _ = self.sock.recvfrom(1024)
        response = response.decode('utf-8')
        if response == "SYN-ACK":
            print("Received SYN-ACK from the server...")
            print("Sending ACK to the server...")
            self.send_message("ACK", (self.server_ip, self.server_port))
            return True
        return False

# Server class inheriting from Peer
class Server(Peer):
    def __init__(self, ip, port) -> None:
        super().__init__(ip, port)

    def three_way_handshake(self):
        print("Waiting for SYN from client...")
        message, self.client = self.sock.recvfrom(1024)
        message = message.decode('utf-8')
        if message == "SYN":
            print("Received SYN from client...")
            print("Sending SYN-ACK to the client...")
            self.send_message("SYN-ACK")
            ack, _ = self.sock.recvfrom(1024)
            if ack.decode('utf-8') == "ACK":
                print("Received ACK from client... Connection established!")
                return True
        return False

# Running the client
def run_client():
    client = Client(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT)
    if client.three_way_handshake():
        print("Handshake successful. Ready to chat...")
        client.start()
    else:
        print("Handshake failed.")
    client.quit()

# Running the server
def run_server():
    server = Server(SERVER_IP, SERVER_PORT)
    if server.three_way_handshake():
        print("Handshake successful. Ready to chat...")
        server.start()
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
        print("Invalid choice")

if __name__ == "__main__":
    CLIENT_IP = "127.0.0.1"
    CLIENT_PORT = 50602
    SERVER_IP = "127.0.0.1"
    SERVER_PORT = 50601
    main()
