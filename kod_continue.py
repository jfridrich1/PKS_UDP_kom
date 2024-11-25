import socket
import threading
import struct
import binascii
import time


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

    # CRC16 pomocou binascii
    def calculate_crc(self, data: bytes) -> int:
        return binascii.crc_hqx(data, 0xFFFF)

    #toto bude metoda ktora vola vsetky ostatne funkcne metody (fragment, ...)
    def build_packet(self):
        if isinstance(self.payload, str):
            self.payload=self.payload.encode('utf-8')

        #CRC16 volanie
        self.crc_field = self.calculate_crc(self.payload)
        head=struct.pack('!B H H H', self.flags, self.payload_size, self.frag_offset, self.crc_field)
        return head+self.payload

    @staticmethod #nepotrebuje Header instance
    #spracuj packet
    def parse_packet(packet):
        head=packet[:7]   #7 je velkost headeru
        flags, payload_size, frag_offset, crc_field=struct.unpack('!B H H H', head)#1B,2B,2B,2B
        payload=packet[7:7+payload_size] #data/sprava
        decoded_flags = Header.decode_flags(flags)  # Rozloženie flagov

        # Kontrola
        calculated_crc = binascii.crc_hqx(payload, 0xFFFF)
        #print(f"\nExpected CRC: {crc_field}, Calculated CRC: {calculated_crc}")

        # CRC kontrola
        if calculated_crc != crc_field:
            raise ValueError(f"CRC check failed: expected {crc_field}, got {calculated_crc}")

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

        self.reassembly_buf = {}  # Buffer pre fragmenty
        self.expected_fragments = None  # Očakávaný počet fragmentov
        
        self.acknowledged_fragments = set()  # Sada ACK fragmentov
        self.window_size = 4  # Sliding window veľkosť
        self.unacked_fragments = {}  # Neodpovedané fragmenty: {frag_offset: (time_sent, built_packet)}

        self.is_active = False


    #odosielanie sprav - pre SYN, SYN ACK, ACK, asi mozem odstranit
    def send_message(self, message, receiver=None):
        if isinstance(message, str):
            message=message.encode('utf-8')
        if receiver is None: #errir handle
            receiver=self.peer_address
        if receiver:
            self.sock.sendto(message, receiver)


    def receive_packet(self):
        while self.running_th:
            data, self.peer_address = self.sock.recvfrom(2048)
            try:
                packet = Header.parse_packet(data)
                if packet['flags']['ack']:
                    self.handle_ack(packet['frag_offset'])
                elif packet['flags']['nack']:
                    self.handle_nack(packet['frag_offset'])
                elif packet['flags']['msg'] or packet['flags']['file']:
                    self.is_active = True
                    self.handle_fragment(packet)
                    self.is_active = False
            except ValueError as e:
                print(f"Error parsing packet: {e}")


    # Spracovanie ACK správ
    def handle_ack(self, frag_offset):
        print(f"+++ Received ACK for fragment {frag_offset+1} +++")
        if frag_offset in self.unacked_fragments:
            del self.unacked_fragments[frag_offset]
            self.acknowledged_fragments.add(frag_offset)

    # Spracovanie NACK správ.
    def handle_nack(self, frag_offset):
        print(f"--- Received NACK for fragment {frag_offset+1}. ---")
        if frag_offset in self.unacked_fragments:
            _, built_packet = self.unacked_fragments[frag_offset]
            self.send_message(built_packet, self.peer_address)
            print(f"--- Retransmitted fragment {frag_offset+1} due to NACK. ---")

    # Spracovanie prijatých fragmentov
    def handle_fragment(self, packet):
        frag_offset = packet['frag_offset']

        if packet['flags']['start_frag']:
            # Štartovací paket
            self.expected_fragments = packet['payload_size']
            self.reassembly_buf = {}  # Inicializácia bufferu pre nový prenos
            print(f"\n+++ Start packet received. Expecting {self.expected_fragments} fragments. +++")
            return

        if frag_offset in self.reassembly_buf:
            return  # Fragment už prijatý

        try:
            # Validácia CRC a ukladanie
            self.reassembly_buf[frag_offset] = packet['payload']
            print(f"+++ Fragment {frag_offset+1} received and stored. +++")

            # Poslať ACK
            ack_flags = Header.encode_flags(ack=True)
            ack_packet = Header(ack_flags, payload_size=0, frag_offset=frag_offset, crc_field=0, payload=b'')
            self.send_message(ack_packet.build_packet(), self.peer_address)

            # Skontrolovať, či sme prijali všetky fragmenty
            if len(self.reassembly_buf) == self.expected_fragments:
                print(f"------------- All fragments received ({len(self.reassembly_buf)}). -------------\nReassembling data...")
                reassembled_data = b''.join(
                    self.reassembly_buf[i] for i in range(self.expected_fragments)
                )
                print(f"+++ Reassembled data (size: {len(reassembled_data)} bytes). +++")
                
                # Spracovanie dát na základe flagov
                if packet['flags']['msg']:
                    # Ak ide o správu, vypíš ju ako text
                    print("+++ Received message: +++")
                    print(reassembled_data.decode('utf-8', errors='replace'))
                    print("\n")
                elif packet['flags']['file']:
                    # Ak ide o súbor, vypýtaj si cestu na uloženie
                    save_dir = input("Enter the directory to save the file (default: current directory): ").strip() or "."
                    save_name = input("Enter the file name (default: received_file): ").strip() or "received_file"

                    full_path = f"{save_dir.rstrip('/')}/{save_name}"
                    try:
                        with open(full_path, "wb") as file:
                            file.write(reassembled_data)
                        print(f"+++ File successfully saved at: {full_path} +++")
                    except FileNotFoundError:
                        print("!!! Invalid directory. File not saved. !!!")
                    except Exception as e:
                        print(f"!!! Error saving file: {e} !!!")

        except ValueError as e:
            print(f"Fragment {frag_offset} failed CRC check: {e}")
            # Poslať NACK pre poškodený fragment
            nack_flags = Header.encode_flags(nack=True)
            nack_packet = Header(nack_flags, payload_size=0, frag_offset=frag_offset, crc_field=0, payload=b'')
            self.send_message(nack_packet.build_packet(), self.peer_address)
            print(f"--- Sent NACK for fragment {frag_offset}. ---")




    # Metoda odoslania packetu
    def send_packet(self):
        while self.running_th:

            if self.is_active:
                time.sleep(0.1)
                continue

            # Typ správy
            packet_type = input("Type of message? (m for message / f for file): ").strip().lower()

            # Subor 
            if packet_type == 'f':
                # Súbor
                file_path = input("Enter the file path: ").strip()
                try:
                    with open(file_path, "rb") as file:
                        payload = file.read()  # Načítaj obsah súboru
                except FileNotFoundError:
                    print("File not found")
                    continue
                flags = Header.encode_flags(file=True)

            # Sprava
            elif packet_type == 'm':
                # Správa
                message = input("Enter your message: ").strip().encode('utf-8')
                payload = message
                flags = Header.encode_flags(msg=True)

            else:
                print("Invalid option. Type 'm' for message or 'f' for file.")
                continue

            # Spoločné spracovanie fragmentov a odosielanie
            self.is_active = True
            self._send_payload_in_fragments(payload, flags)
            self.is_active = False



    def _send_payload_in_fragments(self, payload, flags):
        payload_size = len(payload)
        max_payload_size = int(input("Enter MAX_PAYLOAD_SIZE (default 1024): ") or "1024")
        num_fragments = (payload_size + max_payload_size - 1) // max_payload_size

        # Odoslanie štartovacieho paketu
        start_frag_flags = flags | (1 << 7)  # Nastav bit start_frag
        start_packet = Header(start_frag_flags, payload_size=num_fragments, frag_offset=0, crc_field=0, payload=b'')
        self.send_message(start_packet.build_packet(), self.peer_address)
        print(f"+++ Start fragment sent with total fragments: {num_fragments}. +++")

        base = 0  # Sliding window začiatok

        while base < num_fragments:
            # Posielanie fragmentov v rámci sliding window
            for i in range(base, min(base + self.window_size, num_fragments)):
                if i not in self.unacked_fragments:
                    start = i * max_payload_size
                    end = min(start + max_payload_size, payload_size)
                    fragment = payload[start:end]
                    packet = Header(flags, len(fragment), i, crc_field=0, payload=fragment)
                    built_packet = packet.build_packet()
                    self.send_message(built_packet, self.peer_address)
                    self.unacked_fragments[i] = (time.time(), built_packet)
                    print(f"--- Sent fragment {i+1}/{num_fragments} ({len(fragment)} bytes). ---")

            # Spracovanie timeoutov a retransmisie
            current_time = time.time()
            for frag_offset, (time_sent, built_packet) in list(self.unacked_fragments.items()):
                if current_time - time_sent > 5:  # Timeout 2 sekundy
                    self.send_message(built_packet, self.peer_address)
                    self.unacked_fragments[frag_offset] = (current_time, built_packet)
                    print(f"Retransmitted fragment {frag_offset}.")

            # Posun sliding window
            while base in self.acknowledged_fragments:
                base += 1

            # Kontrola ukončenia
            if len(self.acknowledged_fragments) == num_fragments:
                print(f"------------- All fragments acknowledged ({len(self.acknowledged_fragments)}). -------------")
                break



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




#fagmentacia - nastudovat este lebo nevien abslitne co robit este
    #metoda fragmentation() a kopu dalsich
#poskodenie a strata dat - Selective Repeat SR, mozno tu vylepsienu metodu
    #metoda Selective Repeat
#Keep Alive - heartbeat mozno este dneska