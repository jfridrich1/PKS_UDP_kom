import socket
CLIENT_IP = "192.168.1.106" # client host ip A.B.C.D
CLIENT_PORT = 50602 # client port for recieving communication
SERVER_IP = "192.168.1.106" # Server host ip (public IP) A.B.C.D
SERVER_PORT = 50601

class Client:
    def __init__(self, ip, port, server_ip, server_port) ->None:
        self.sock = socket.socket(socket.AF_INET,
        socket.SOCK_DGRAM) # UDP socket creation
        self.server_ip = server_ip
        self.server_port = server_port

    def receive(self):
        data = None
        data, self.server = self.sock.recvfrom(1024) # buffer   size is 1024 bytes
        return data #1

    def send_message(self, message):
        self.sock.sendto(bytes(message,encoding="utf8"),(self.server_ip,self.server_port))

    def quit(self):
        self.sock.close() # correctly closing socket
        print("Client closed..")

class Server:
    def __init__(self, ip, port) -> None:
        self.sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM) # UDP socket creation
        self.sock.bind((ip, port)) #needs to be tuple (string,int)

    def receive(self):
        data = None
        while data == None:
            data, self.client= self.sock.recvfrom(1024) #buffer size is 1024 bytes
        print("Received message: %s" % data)
        #return data # 1
        return str(data,encoding="utf-8")

    def send_response(self):
        self.sock.sendto(b"Message received... closing connection",self.client)

    def quit(self):
        self.sock.close() # correctly closing socket
        print("Server closed..")

if __name__=="__main__":
    server = Server(SERVER_IP, SERVER_PORT)
    data = "empty"
    data = server.receive() # 1
    if data != None: # 1
        server.send_response() # 1
    else: # 1
        print("Message has not been received") #1
    server.quit()

if __name__=="__main__":
    client = Client(CLIENT_IP, CLIENT_PORT, SERVER_IP,SERVER_PORT)
    data = "empty"
    print("Input your message: ") #1
    client.send_message(input()) # 1
    data = client.receive() # 1
    if data != None: # 1
        print(data.decode()) # 1
    else: # 1
        print("Message has not been received") #1
    client.quit() 