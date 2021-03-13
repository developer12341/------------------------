import threading, struct, datetime
from ganeral_dependencies.global_values import *
from server_dependencies import email_send
class request_heandler(threading.Thread):
    def __init__(self, client,addr,client_e,client_d, client_N, db_obj, addr_name,addr_chatId,chatId_addr):
        self.queue_requests = []
        self.client = client
        self.addr = addr
        self.client_d = client_d
        self.client_e = client_e
        self.client_N = client_N
        self.db_obj = db_obj
        self.is_logged_in = False
        self.username = None
        self.current_details = []
        #{address: username, ...}
        self.addr_name = addr_name
        #{address: chatId, ...}
        self.addr_chatId = addr_chatId
        #{chatId: [address,address...], ...}
        self.chatId_addr = chatId_addr

        self.keep_runing = True
        threading.Thread.__init__(self)
        return
    

    def run(self):
        while self.keep_runing:
            #recive packets from client
            packet = self.client.recv(PACKET_SIZE)
            if packet == b'':
                print(f"{self.addr} closed")
                self.close_conn()
                return
            request, request_id, packet_amount, packet_number, flag = self.buffer_extractor(packet[:HEADER_SIZE])
            self.queue_requests.append(packet)
            if packet_amount > 1:
                for _ in range(packet_amount-1):
                    packet = self.client.recv(PACKET_SIZE)
                    self.queue_requests.insert(packet)

            #need to chack packet validity

            #sort by request
            if request == SEND_IMG or request == SEND_FILE or request == SEND_MSG:
                self.brodcast_packets(self.addr)
            elif request == LOGIN:
                self.login()
            elif request == REGISTER:
                self.register()
            elif request == CONN_CHAT:
                self.connect_to_chat()
            elif request == CREATE_CHAT:
                self.create_chat()
            elif request == GET_USERS:
                self.get_users()
            elif request == REPLACE_KEYS:
                self.replace_keys()
            elif request == LEAVE_CHAT:
                self.leave_chat()
            elif request == CLOSE_CONN:
                self.close_conn()
                return

            self.queue_requests = []
        self.client.close()
        
        
    
    def decrypt(self, cipher):
        cipher = cipher.strip(b'\x00')
        parts = cipher.split()
        #convert to int
        new_parts = []
        for part in parts:
            if part:
                new_parts.append( int(part))
        msg = map(lambda number: pow(number,self.client_d,self.client_N),new_parts)
        msg = bytes(msg)

        return msg

    
    def brodcast_packets(self,addr):
        pass
    
    def login(self):
        #chack if the username and password is in the database
        login_details = b''
        for packet in self.queue_requests:
            login_details += self.decrypt(packet[HEADER_SIZE:])
        username, password = struct.unpack(f"{USERNAME_MAX_LEN}s {PASSWORD_MAX_LEN}s",login_details)
        username = username.strip(b'\x00').decode("ascii")
        password = password.strip(b'\x00').decode("ascii")
        if self.db_obj.password_chack(username,password):
            packets = Packet_Maker(AUTHENTICAT_EMAIL,(self.client_e,self.client_N))
        else:
            packets = Packet_Maker(REG_LOGIN_FAIL,(self.client_e,self.client_N))

        
        self.client.send(packets.general_packets)

    
    def register(self):
        #chack if the username and password is in the database
        #if true then get them into the database and if false then
        register_details = bytes(0)
        for packet in queue_requests:
            register_details += self.decrypt(packet[HEADER_SIZE:])
        username, password, Byear, Bmonth, Bday = struct.unpack("30s 100s 2s 1s 1s",register_details[:134])
        birthday= datetime.date(int.from_bytes(Byear,"big"), Bmonth[0], Bday[0])
        username = username.strip(b'\x00')
        password = password.strip(b'\x00')
        email = register_details[134:].strip(b'\x00')

        if self.db_obj.does_user_exist(username):
            packets = Packet_Maker(REG_LOGIN_FAIL,(self.client_e,self.client_N))
        else:
            id_chacker = email_send.send_authentication_email(email.decode("ascii"))
            if not id_chacker:
                packets = Packet_Maker(EMAIL_DOSENT_EXIST,(self.client_e,self.client_N))
            else:
                packets = Packet_Maker(AUTHENTICAT_EMAIL,(self.client_e,self.client_N))
                self.current_details = [username,password,birthday,email]

        self.client.send(next(packets))

    
    def authenticat_email(self):
        pass
        # packet = self.client.recv(PACKET_SIZE)
        # request, request_id, packet_amount, packet_number, flag = self.buffer_extractor(packet[:HEADER_SIZE])
        # if packet_amoun
        # self.db_obj.insert_user(username,password,birthday,email)


    def connect_to_chat(self):
        #chack if logged in
        data = bytes(0)
        for packet in queue_requests:
            data += self.decrypt(packet[HEADER_SIZE:])
        username_len = data[0]
        username = data[1:username_len].decode("ascii")
        # self.addr_name[self.addr] = username


    def create_chat(self):
        #chack if logged in
        pass

    def get_users(self):
        #chack if logged in
        pass
    
    def replace_keys(self):
        pass
    
    def leave_chat(self):
        #chack if logged in
        pass

    def close_conn(self):

        self.is_logged_in = False
        self.keep_runing = False

    def bytes_to_int(self,byte):
        number = 0
        for i in range(1,len(byte)+1):
            number += byte[-i]*i
        return number
            
    def buffer_extractor(self, buffer):
        request, request_id, packet_amount, packet_number, flag = struct.unpack("1s 8s 3s 3s 1s", buffer)
        return request, request_id, self.bytes_to_int(packet_amount) , self.bytes_to_int(packet_number) , flag
