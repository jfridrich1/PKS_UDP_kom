import socket
import threading
import struct


class Header:
    def __init__(self, flags, payload_size, frag_offset, crc_field, payload) -> None:
        self.flags=flags
        self.payload_size=payload_size
        self.frag_offset=frag_offset
        self.crc_field=crc_field
        self.payload=payload
    
    # Metóda na kódovanie flagov
    @staticmethod
    def encode_flags(msg=False, file=False, signal=False, heartbeat=False,
                     nack=False, syn=False, ack=False, start_frag=False):
        flags = 0
        if msg:
            flags |= (1 << 0)  # Bit 0
        if file:
            flags |= (1 << 1)  # Bit 1
        if signal:
            flags |= (1 << 2)  # Bit 2
        if heartbeat:
            flags |= (1 << 3)  # Bit 3
        if nack:
            flags |= (1 << 4)  # Bit 4
        if syn:
            flags |= (1 << 5)  # Bit 5
        if ack:
            flags |= (1 << 6)  # Bit 6
        if start_frag:
            flags |= (1 << 7)  # Bit 7
        return flags

    # Metóda na dekódovanie flagov
    @staticmethod
    def decode_flags(flags_byte):
        return {
            "msg": bool(flags_byte & (1 << 0)),
            "file": bool(flags_byte & (1 << 1)),
            "signal": bool(flags_byte & (1 << 2)),
            "heartbeat": bool(flags_byte & (1 << 3)),
            "nack": bool(flags_byte & (1 << 4)),
            "syn": bool(flags_byte & (1 << 5)),
            "ack": bool(flags_byte & (1 << 6)),
            "start_frag": bool(flags_byte & (1 << 7)),
        }

    #toto bude metoda ktora vola vsetky ostatne funkcne metody (fragment, ...)
    def build_packet(self):
        if isinstance(self.payload, str):
            self.payload=self.payload.encode('utf-8')
        head=struct.pack('!B H H H', self.flags, self.payload_size, self.frag_offset, self.crc_field)
        return head+self.payload

    @staticmethod #nepotrebuje Header instance
    #spracuj packet
    def parse_packet(packet):
        head=packet[:7]   #7 je velkost headeru
        flags, payload_size, frag_offset, crc_field=struct.unpack('!B H H H', head)#1B,2B,2B,2B
        payload=packet[7:7+payload_size] #data/sprava
        decoded_flags = Header.decode_flags(flags)  # Rozloženie flagov
        return {
            'flags':decoded_flags, 
            'payload_size':payload_size, 
            'frag_offset':frag_offset, 
            'crc_field':crc_field, 
            'payload':payload
        }

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

            # Dekóduj obsah podľa flagov
            #print(f"\nReceived packet: {packet}")
            if packet['flags']['msg']:
                print(f"Received message: {packet['payload'].decode('utf-8')}\n")
            elif packet['flags']['file']:
                print(f"\nReceived file {packet['payload']}")

    #metoda odoslania packetu
    def send_packet(self):
        while self.running_th:  #threadovanie
            #debug, neskor prec
            #data=input(f"You ({self.__class__.__name__}): ")

            packet_type = input("Type of message? (m for message / f for file): ").strip().lower()
            if packet_type == 'f':
                # Súbor
                file_path = input("Enter the file path: ").strip()
                payload=file_path
                flags = Header.encode_flags(file=True)
            else:
                # Správa
                payload = input("Enter your message: ").strip().encode('utf-8')
                flags = Header.encode_flags(msg=True)

            #default hodnoty na debug
            payload_size=len(payload)
            frag_offset=1
            crc_field=2

            #volanie funkcii spracovania poli (fragmetnt, MT, flagy,...) TU

            #skladanie packetu,inc 
            packet=Header(flags, payload_size, frag_offset, crc_field, payload)
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
    def __init__(self, ip ,port) -> None:
        super().__init__(ip, port)
        self.server_ip=None
        self.server_port=None
        #servers address na posielanie

    #klientova verzia 3w shaku
    def three_way_hs_c(self, server_ip, server_port):
        #start 3wHS, debug
        self.server_ip=server_ip
        self.server_port=server_port

        print("Send SYN...")
        syn_flags = Header.encode_flags(signal=True, syn=True)
        syn_packet = Header(syn_flags, payload_size=0, frag_offset=0, crc_field=0, payload="").build_packet()
        self.send_message(syn_packet, (self.server_ip, self.server_port))
        #self.send_message("SYN", (self.server_ip, self.server_port))  #serverova adresa

        #odpoved na SYN
        data, self.peer_address = self.sock.recvfrom(1024)
        response = Header.parse_packet(data)
        #response=response.decode('utf-8')


        # Skontroluj, či je SYN-ACK správny
        if response['flags']['signal'] and response['flags']['syn'] and response['flags']['ack']:
            print("Received SYN-ACK...")

            # Send ACK správa
            print("Send ACK...")
            ack_flags = Header.encode_flags(signal=True, ack=True)
            ack_packet = Header(ack_flags, payload_size=0, frag_offset=0, crc_field=0, payload="").build_packet()
            self.send_message(ack_packet, self.peer_address)
            return True
        return False


        """if response=="SYN-ACK":

            #debug
            print("Received SYN-ACK...")
            print("Send ACK...")
            self.send_message("ACK", self.peer_address)  #posli ACK serveru
            return True
        return False"""

    def send_packet(self):
        self.peer_address=(self.server_ip,self.server_port)
        super().send_packet()

class Server(Peer):
    def __init__(self, ip, port) -> None:
        super().__init__(ip, port)

    #serverova verzia 3w shaku
    def three_way_hs_s(self):
        #vypis po zvoleni servera
        print("Wait for SYN...")

        #prichod SYN
        data, self.peer_address=self.sock.recvfrom(1024) #klientova adresa
        request = Header.parse_packet(data)
        #message=message.decode('utf-8')

        if request['flags']['signal'] and request['flags']['syn']:
            print("Received SYN...")

            #posli odpoved na SYN -> SYN-ACK, debug
            print("Send SYN-ACK...")
            syn_ack_flags = Header.encode_flags(signal=True, syn=True, ack=True)
            syn_ack_packet = Header(syn_ack_flags, payload_size=0, frag_offset=0, crc_field=0, payload="").build_packet()
            self.send_message(syn_ack_packet, self.peer_address)
            #self.send_message("SYN-ACK", self.peer_address)

            #odpoved na SYN-ACK -> ACK
            ack, _=self.sock.recvfrom(1024)
            response = Header.parse_packet(ack)

            if request['flags']['signal'] and response['flags']['ack']:
                print("Received ACK, connection complete!")
                return True
            
            """if ack.decode('utf-8')=="ACK":
                #prijaty ACk, debug
                print("Received ACK, connection complete!")
                return True"""
        return False

class Main:
    def __init__(self):
        self.client = None
        self.server = None

    def run_client(self):
        # Získanie IP a portov pre klienta a server
        client_ip = input("Client IP (default 127.0.0.1): ") or "127.0.0.1"
        client_port = int(input("Client port (default 50601): ") or "50601")
        server_ip = input("Server IP (default 127.0.0.1): ") or "127.0.0.1"
        server_port = int(input("Server port (default 50602): ") or "50602")

        # Vytvorenie klienta s dynamickými parametrami
        self.client = Client(client_ip, client_port)

        # Pokus o nadviazanie spojenia pomocou 3W handshake
        if self.client.three_way_hs_c(server_ip, server_port):
            print("Handshake successful, ready for chat!")
            self.client.chatting()
        else:
            print("Handshake error.")
        self.client.quit()

    def run_server(self):
        # Získanie IP a portov pre server
        server_ip = input("Server IP (default 127.0.0.1): ") or "127.0.0.1"
        server_port = int(input("Server port (default 50602): ") or "50602")

        # Vytvorenie servera s dynamickými parametrami
        self.server = Server(server_ip, server_port)

        # Pokus o nadviazanie spojenia pomocou 3W handshake
        if self.server.three_way_hs_s():
            print("Handshake successful, ready for chat!")
            self.server.chatting()
        else:
            print("Handshake error.")
        self.server.quit()

    def start(self):
        # Voľba režimu (Server alebo Client)
        main_choice = input("Server/Client? (c/s): ")
        if main_choice == 'c':
            self.run_client()
        elif main_choice == 's':
            self.run_server()
        else:
            print("Invalid command.")


if __name__ == "__main__":
    p2p_chat = Main()
    p2p_chat.start()




#upravit velkost bufferu - 1024
#doriesit printy ako You (trieda) - odstranit / fixnut
#ako seknut komunikaciu
#spravit nech klient ip nie je local ale hocijaka



#zmenit hlavicku a implementaciu, asi ta varianta bez signal bitu
    #upravit class Header cely -
        #init, build_packet, parse_packet
#fagmentacia - nastudovat este lebo nevien abslitne co robit este
    #metoda fragmentation() a kopu dalsich
#poskodenie a strata dat - Selective Repeat SR, mozno tu vylepsienu metodu
    #metoda Selective Repeat
#Keep Alive - heartbeat mozno este dneska