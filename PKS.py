import socket
CLIENT_IP = "192.168.1.106" # client host ip A.B.C.D
CLIENT_PORT = 50602 # client port for recieving communication
SERVER_IP = "192.168.1.108" # Server host ip (public IP) A.B.C.D
SERVER_PORT = 50601

class Client:
    def __init__(self, ip, port, server_ip, server_port) ->None:
        self.sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM); # UDP socket creation
        self.server_ip = server_ip;
        self.server_port = server_port;

    def receive(self):
        data = None;
        data, self.server = self.sock.recvfrom(1024); # buffer   size is 1024 bytes
        return data; #1

    def send_message(self, message):
        self.sock.sendto(bytes(message,encoding="utf-8"),(self.server_ip,self.server_port));

    def quit(self):
        self.sock.close(); # correctly closing socket
        print("Client closed..");

class Server:
    def __init__(self, ip, port) -> None:
        self.sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM); # UDP socket creation
        self.sock.bind((ip, port)); #needs to be tuple (string,int)

<<<<<<< Updated upstream
    def receive_message(self):
        """Receive messages from the client (or peer)."""
        while True:
            data, self.client = self.sock.recvfrom(1024)  # Buffer size is 1024 bytes
            print("Received from client:", data.decode("utf-8"))
=======
    def receive(self):
        data = None;
        while data == None:
            data, self.client= self.sock.recvfrom(1024); #buffer size is 1024 bytes
        print("Received message: %s" % data);
        #return data # 1
        return str(data,encoding="utf-8")
    
    def three_way_handshake(self):
        # Step 1: Receive SYN from the client
        print("Waiting for SYN from client...")
        message = self.receive()
        if message == "SYN":
            print("Received SYN from client...")

            # Step 2: Send SYN-ACK to the client
            print("Sending SYN-ACK to the client...")
            self.send_response("SYN-ACK")

            # Step 3: Receive ACK from the client
            ack = self.receive()
            if ack == "ACK":
                print("Received ACK from client... Connection established!")
                return True
        return False
>>>>>>> Stashed changes

    #def send_response(self):
    #    self.sock.sendto(b"Message received... closing connection",self.client);
    def send_response(self, message):
        self.sock.sendto(message.encode('utf-8'), self.client)

    def quit(self):
        self.sock.close(); # correctly closing socket
        print("Server closed..");

def run_client():
<<<<<<< Updated upstream
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

=======
    client=Client(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT);
    """message=input("Input your message:");
    client.send_message(message);
    response=client.receive();
    if response:
        print(response.decode());
    else:
        print("Message not received!");"""
    # Perform 3-way handshake
    if client.three_way_handshake():
        print("Handshake successful. Ready to send data...")
        message = input("Input your message: ")
        client.send_message(message)
    else:
        print("Handshake failed.")
    client.quit();

def run_server():
    server=Server(SERVER_IP, SERVER_PORT);
    """data=server.receive();
    if data:
        server.send_response();
    else:
        print("Message not received!");"""
    # Perform 3-way handshake
    if server.three_way_handshake():
        print("Handshake successful. Ready to receive data...")
        data = server.receive()
        if data:
            print(f"Received message: {data}")
            server.send_response("Message received")
        else:
            print("Message not received.")
    else:
        print("Handshake failed.")
    server.quit();
>>>>>>> Stashed changes

def main():
    main_choice=input("Server/Client? (c/s):");
    if main_choice=='c':
        run_client();   
    elif main_choice=='s':
        run_server();
    else:
        print("Error id");

if __name__=="__main__":
    main();