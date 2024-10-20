import socket
import threading
import struct


class Header:
    def __init__(self, flags, payload_size, total_frag, frag_offset, checksum, payload) -> None:
        self.flags=flags
        self.payload_size=payload_size
        self.total_frag=total_frag
        self.frag_offset=frag_offset
        self.checksum=checksum
        self.payload=payload

    #toto bude metoda ktora vola vsetky ostatne funkcne metody (fragment, ...)
    def build_packet(self):
        if isinstance(self.payload, str):
            self.payload=self.payload.encode('utf-8')
        head=struct.pack('!B H B H H', self.flags, self.payload_size, self.total_frag, self.frag_offset, self.checksum)
        return head+self.payload

    @staticmethod #nepotrebuje Header instance
    #spracuj packet
    def parse_packet(packet):
        head=packet[:8]   #8 je velkost headeru
        flags, payload_size, total_frag, frag_offset, checksum=struct.unpack('!B H B H H', head)#1B,2B,1B,2B,2B
        payload=packet[8:8+payload_size] #data/sprava
        return {'flags':flags, 'payload_size':payload_size, 'total_frag':total_frag, 'frag_offset':frag_offset, 'checksum':checksum, 'payload':payload}

#zaklad pre Klienta a Server
class Peer:
    def __init__(self, ip, port) -> None:
        self.sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((ip,port))   #bind k Peer-ovi (client/server)
        self.running_th=True        #threading flag
        self.peer_address=None      #priprava na ulozenie adresy (klienta ak je server, servera ak je klient)

    #odosielanie sprav - pre SYN, SYN ACK, ACK
    def send_message(self, message, receiver=None):
        if isinstance(message, str):
            message=message.encode('utf-8')
        if receiver is None: #errir handle
            receiver=self.peer_address
        if receiver:
            self.sock.sendto(message, receiver)

    #metoda prijatia packetu
    def receive_packet(self):
        while self.running_th:  #threadovanie 
            data, self.peer_address=self.sock.recvfrom(1024) #zmenit velkost neskor
            #rozober packet
            packet=Header.parse_packet(data)

            #debug
            print(f"\nReceived packet: {packet}")
            print(f"Received message: {packet['payload']}")

    #metoda odoslania packetu
    def send_packet(self):
        while self.running_th:  #threadovanie
            #debug, neskor prec
            data=input(f"You ({self.__class__.__name__}): ")

            #default hodnoty na debug
            flags=1
            payload_size=len(data)
            total_frag=2
            frag_offset=3
            checksum=1234

            #volanie funkcii spracovania poli (fragmetnt, MT, flagy,...) TU

            #skladanie packetu,inc 
            packet=Header(flags, payload_size, total_frag, frag_offset, checksum, data)
            self.send_message(packet.build_packet(),self.peer_address)

            #pokus o ukoncenie spojenia
            """print(f"toto je data: {data}")
            if data.lower() == "quit":
                self.running_th = False
                break"""

    #metoda na vymienanie sprav
    def chatting(self):
        recv_thread=threading.Thread(target=self.receive_packet)
        send_thread=threading.Thread(target=self.send_packet)
        recv_thread.start()
        send_thread.start()
        send_thread.join()

    #metoda na ukoncenie spojenia - zatial iba jednostranne
    def quit(self):
        self.running_th=False   #koniec threadovania
        self.sock.close()       #uzavri socket

        #debug, neskor prec
        print(f"{self.__class__.__name__} closed...")

class Client(Peer):
    def __init__(self) -> None:
        super().__init__("127.0.0.1", 50601)
        self.server_ip=None
        self.server_port=None
        #servers address na posielanie

    #klientova verzia 3w shaku
    def three_way_hs_c(self, server_ip, server_port):
        #start 3wHS, debug
        self.server_ip=server_ip
        self.server_port=server_port

        print("Sending SYN to the server...")
        self.send_message("SYN", (self.server_ip, self.server_port))  #serverova adresa

        #odpoved na SYN
        response, self.peer_address = self.sock.recvfrom(1024)
        response=response.decode('utf-8')
        if response=="SYN-ACK":

            #debug
            print("Received SYN-ACK from the server...")
            print("Sending ACK to the server...")
            self.send_message("ACK", self.peer_address)  #posli ACK serveru
            return True
        return False

    def send_packet(self):
        self.peer_address=(self.server_ip,self.server_port)
        super().send_packet()

class Server(Peer):
    def __init__(self, ip, port) -> None:
        super().__init__(ip, port)

    #serverova verzia 3w shaku
    def three_way_hs_s(self):
        #vypis po zvoleni servera
        print("Waiting for SYN from client...")

        #prichod SYN
        message, self.peer_address=self.sock.recvfrom(1024) #klientova adresa
        message=message.decode('utf-8')
        if message=="SYN":
            print("Received SYN from client...")

            #posli odpoved na SYN -> SYN-ACK, debug
            print("Sending SYN-ACK to the client...")
            self.send_message("SYN-ACK", self.peer_address)

            #odpoved na SYN-ACK -> ACK
            ack, _=self.sock.recvfrom(1024)
            if ack.decode('utf-8')=="ACK":

                #prijaty ACk, debug
                print("Received ACK from client, connection complete!")
                return True
        return False

#klient main
def run_client():
    server_ip=input("Server IP:")
    server_port=int(input("Server port:"))
    client=Client()
    if client.three_way_hs_c(server_ip,server_port)==True:
        print("Handshake successful. Chat ready!")
        client.chatting()
    else:
        print("Handshake error.")
    client.quit()

#server main
def run_server():
    server = Server("127.0.0.1", 50602)
    if server.three_way_hs_s()==True:
        print("Handshake successful. Chat ready!")
        server.chatting()
    else:
        print("Handshake error.")
    server.quit()

def main():
    main_choice=input("Server/Client? (c/s): ")
    if main_choice=='c':
        run_client()
    elif main_choice=='s':
        run_server()
    else:
        print("Invalid command.")

if __name__=="__main__":
    main()


#upravit velkost bufferu - 1024
#doriesit printy ako You (trieda) - odstranit / fixnut
#ako seknut komunikaciu
#spravit nech klient ip nie je local ale hocijaka