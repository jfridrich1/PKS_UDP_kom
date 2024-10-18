import socket
CLIENT_IP = "192.168.1.107" # client host ip A.B.C.D
CLIENT_PORT = 50602 # client port for recieving communication
SERVER_IP = "192.168.1.108" # Server host ip (public IP) A.B.C.D
SERVER_PORT = 50601

class Client:
    def __init__(self, ip, port, server_ip, server_port) ->None:
        self.sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM); # UDP socket creation
        self.server_ip = server_ip;
        self.server_port = server_port;
        self.sock.bind((ip, port))  # Bind to the client IP and port

    def receive(self):
        data = None;
        data, self.server = self.sock.recvfrom(1024); # buffer   size is 1024 bytes
        return data; #1

    def three_way_handshake(self):
        # Step 1: Send SYN to the server
        print("Sending SYN to the server...")
        self.send_message("SYN")
        
        # Step 2: Receive SYN-ACK from the server
        response = self.receive()
        response=response.decode('utf-8')
        if response == "SYN-ACK":
            print("Received SYN-ACK from the server...")
            
            # Step 3: Send ACK to the server
            print("Sending ACK to the server...")
            self.send_message("ACK")
            return True
        return False
    
    def chat(self):
        while True:
            message = input("You (Client): ")
            self.send_message(message)
            if message.lower() == "quit":
                print("Ending chat from client side...")
                break
            response = self.receive()
            print(f"Server: {response}")
            if response.lower() == "quit":
                print("Server ended the chat.")
                break

    def send_message(self, message):
        self.sock.sendto(bytes(message,encoding="utf-8"),(self.server_ip,self.server_port));

    def quit(self):
        self.sock.close(); # correctly closing socket
        print("Client closed..");

class Server:
    def __init__(self, ip, port) -> None:
        self.sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM); # UDP socket creation
        self.sock.bind((ip, port)); #needs to be tuple (string,int)
        self.client = None

    def receive(self):
        data = None;
        while data == None:
            data, self.client= self.sock.recvfrom(1024); #buffer size is 1024 bytes
        #print("Received message: %s" % data);
        #return data # 1
        return str(data,encoding="utf-8")
    
    def three_way_handshake(self):
        # Step 1: Receive SYN from the client
        print("Waiting for SYN from client...")
        message = self.receive()
        print(f"Server received: {message}")
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

    def chat(self):
        while True:
            message = self.receive()
            print(f"Client: {message}")
            if message.lower() == "quit":
                print("Client ended the chat.")
                break
            response = input("You (Server): ")
            self.send_response(response)
            if response.lower() == "quit":
                print("Ending chat from server side...")
                break

    def send_response(self, message):
        self.sock.sendto(message.encode('utf-8'), self.client)

    def quit(self):
        self.sock.close(); # correctly closing socket
        print("Server closed..");

def run_client():
    client=Client(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT);

    # Perform 3-way handshake
    if client.three_way_handshake():
        print("Handshake successful. Ready to send data...")
        client.chat();
    else:
        print("Handshake failed.")
    client.quit();

def run_server():
    server=Server(SERVER_IP, SERVER_PORT);

    # Perform 3-way handshake
    if server.three_way_handshake():
        print("Handshake successful. Ready to receive data...")
        server.chat()
    else:
        print("Handshake failed.")
    server.quit();

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