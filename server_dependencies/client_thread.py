import threading, struct, datetime
from ganeral_dependencies.global_values import *
from server_dependencies import email_send
from ganeral_dependencies.packets_maker import Packet_Maker
import uuid
class request_heandler(threading.Thread):
    def __init__(self, client,addr,client_e,client_d, client_N,notification_Server, db_obj,chatId_cli,clientid_client):
        self.queue_requests = []
        self.client = client
        self.notification_server = notification_Server
        self.addr = addr
        self.client_d = client_d
        self.client_e = client_e
        self.client_N = client_N
        self.db_obj = db_obj
        self.is_logged_in = False
        self.username = None
        self.current_details = []
        #{client_id: notification_client_obj}
        self.clientid_client  = clientid_client
        #{chatId: [client_id,client_id...], ...}
        self.chatId_cli = chatId_cli

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
                    self.queue_requests.append(packet)

            #need to chack packet validity

            #sort by request
            if request == SEND_IMG or request == SEND_FILE or request == SEND_MSG:
                self.brodcast_packets(self.addr)
            elif request == LOGIN:
                self.login()
            elif request == REGISTER:
                self.register()
            elif request == JOIN_CHAT:
                self.connect_to_chat()
            # elif request == CREATE_CHAT:
            #     self.create_chat()
            elif request == SEND_FRIEND_REQ:
                self.send_friend_req()
            elif request == GET_USERS:
                self.get_users()
            # elif request == REPLACE_KEYS:
            #     self.replace_keys()
            elif request == LEAVE_CHAT:
                self.leave_chat()
            elif request == SEND_PINCODE:
                self.authenticat_email()
            elif request == NOTIFICATION_SETUP:
                self.notification_setup()
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
    def notification_setup(self):
        client_notification, addr = self.notification_server.accept()
        
    def send_friend_req(self):
        pass
    def create_chat(self):
        #chack if logged in
        chat_id = uuid.uuid4().bytes[:4]
        chat_id = chat_id.hex()
        self.cli_chatId[self.client] = chat_id
        self.chatId_cli[chat_id] = [self.client]
        packets = Packet_Maker(JOIN_CHAT,self.public_key,content=chat_id)
        self.client.send(next(packets))


    
    def brodcast_packets(self,addr):
        pass
    
    def login(self):
        #chack if the username and password is in the database
        login_details = b''
        for packet in self.queue_requests:
            login_details += self.decrypt(packet[HEADER_SIZE:])
        print(login_details)
        username, password = login_details[:USERNAME_MAX_LEN], login_details[USERNAME_MAX_LEN:]
        username = username.strip(b'\x00').decode("ascii")
        password = password.strip(b'\x00').decode("ascii")
        print(username)
        print(password)
        client_id = self.db_obj.password_chack(username,password)
        if client_id:
            packets = Packet_Maker(REG_LOGIN_SUC,(self.client_e,self.client_N))
            self.clientid_client[]
        else:
            packets = Packet_Maker(REG_LOGIN_FAIL,(self.client_e,self.client_N))

        
        self.client.send(next(packets))

    
    def register(self):
        #chack if the username and password is in the database
        #if true then get them into the database and if false then
        register_details = b''
        for packet in self.queue_requests:
            register_details += self.decrypt(packet[HEADER_SIZE:])
        username, password, Byear, Bmonth, Bday = struct.unpack("30s 100s 2s 1s 1s",register_details[:134])
        birthday= datetime.date(int.from_bytes(Byear,"big"), Bmonth[0], Bday[0])
        username = username.strip(b'\x00').decode("ascii")
        password = password.strip(b'\x00').decode("ascii")
        email = register_details[134:].strip(b'\x00').decode("ascii")

        if self.db_obj.does_user_exist(username,email):
            packets = Packet_Maker(USERNAME_TAKEN,(self.client_e,self.client_N))
        else:
            print(email)
            id_chacker = email_send.send_authentication_email(email)
            print(id_chacker)
            if not id_chacker:
                packets = Packet_Maker(EMAIL_DOSENT_EXIST,(self.client_e,self.client_N))
            else:
                packets = Packet_Maker(AUTHENTICAT_EMAIL,(self.client_e,self.client_N))
                self.id_chacker = id_chacker
                self.current_details = [username,password,birthday,email]

        self.client.send(next(packets))

    
    def authenticat_email(self):
        pincode = b''
        for packet in self.queue_requests:
            pincode += packet[HEADER_SIZE:]
        pincode = pincode.strip(b'\x00')
        pincode = self.decrypt(pincode).decode("ascii")
        print(pincode)
        if self.id_chacker != pincode:
            packets = Packet_Maker(AUTHENTICAT_EMAIL,(self.client_e,self.client_N))
        else:
            packets = Packet_Maker(REG_LOGIN_SUC,(self.client_e,self.client_N))
            self.db_obj.insert_user(*self.current_details)
            self.cli_name[addr] = username
        self.client.send(next(packets))



    def connect_to_chat(self):
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
