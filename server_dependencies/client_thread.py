import threading, struct, datetime, hashlib,json,uuid, time
from ganeral_dependencies.global_values import *
from server_dependencies import email_send
from ganeral_dependencies.protocols import Packet_Maker
from server_dependencies import key_distrebution
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode

class request_heandler(threading.Thread):
    def __init__(self, client, addr, shared_secret, db_obj, chatId_cli, client_chatid, chatid_pubkey,user_list):
        self.queue_requests = []
        self.client = client
        self.addr = addr
        self.key = hashlib.sha256(self.int_to_bytes(shared_secret)).hexdigest().encode("utf-8")
        # print(self.key)
        self.db_obj = db_obj
        self.username = None
        self.user_list = user_list
        self.current_details = []
        #{client: chat_id}
        self.client_chatid  = client_chatid
        #{chatId: [client,client...], ...}
        self.chatId_cli = chatId_cli
        #{chatId:none or {client:group_pub_key,...}...} 
        #for the group_dh_key_excange
        self.chatid_pubkey = chatid_pubkey

        self.keep_runing = True
        threading.Thread.__init__(self)
        return
    
    def int_to_bytes(self, x: int) -> bytes:
        return x.to_bytes((x.bit_length() + 7) // 8, 'big')


    def decrypt(self,json_input):
        if json_input:
            json_input = json_input.strip(b'\x00')
            b64 = json.loads(json_input)
            json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
            jv = {k:b64decode(b64[k]) for k in json_k}
            cipher = AES.new(self.key, AES.MODE_SIV, nonce=jv['nonce'])
            cipher.update(jv['header'])
            plaintext = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])
            return plaintext
        else:
            return plaintext

    def run(self):
        while self.keep_runing:
            #recive packets from client
            packet = self.client.recv(PACKET_SIZE)
            if packet == b'':
                #print(f"{self.addr} closed")
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
                self.brodcast_packets()
            elif request == LOGIN:
                self.login()
            elif request == REGISTER:
                self.register()
            elif request == JOIN_CHAT:
                self.join_chat()
            elif request == CREATE_CHAT:
                self.create_chat()
            elif request == GET_USERS:
                self.get_users()
            elif request == GET_GROUP_KEY:
                self.get_group_key()
            # elif request == REPLACE_KEYS:
            #     self.replace_keys()
            elif request == LEAVE_CHAT:
                self.leave_chat()
            elif request == SEND_PINCODE:
                self.authenticat_email()
            elif request == SEND_GROUP_KEYS:
                self.send_group_keys()
            elif request == SEND_FIRST_KEY:
                self.send_first_key()
            elif request == CLOSE_CONN:
                self.close_conn()
                return

            self.queue_requests = []
        self.client.close()
        
    def send_first_key(self):
        public_key = b''
        for packet in self.queue_requests:
            public_key += packet[HEADER_SIZE:]
        self.chatid_pubkey[self.chat_id][self.client] = public_key



    def send_group_keys(self):
        for packet in self.queue_requests:
            # print("user get packets: " + str(packet))
            self.chatId_cli[self.chat_id][-1].send(packet)
        

    def notification_setup(self):
        client_notification, addr = self.notification_server.accept()
        

    def get_group_key(self):
        cli_group_pub_key = b''
        for packet in self.queue_requests:
            cli_group_pub_key += packet[HEADER_SIZE:]
        key_index, cli_group_pub_key = self.decrypt(cli_group_pub_key).split(b'index_code_end')
        key_index = pin_code.decode("utf-8")
        for key_index_value, key in self.chatid_pubkey[self.chat_id].items():
            if key_index_value == key_index:
                self.chatid_pubkey[key_index_value] = cli_group_pub_key
                break

    def create_chat(self):
        chat_id = uuid.uuid4().bytes[:3]
        chat_id = chat_id.hex()
        chat_id = chat_id.encode("utf-8")
        print(chat_id)
        self.chatId_cli[chat_id] = [self.client]
        self.client_chatid[self.client] = chat_id
        self.chat_id = chat_id
        packets = Packet_Maker(JOIN_CHAT,self.key,content=chat_id)
        for packet in packets:
            self.client.send(packet)
        

    def join_chat(self):
        #chack if logged in
        cli_public_key = b''
        for packet in self.queue_requests:
            cli_public_key += packet[HEADER_SIZE:]
        pin_code, cli_public_key = self.decrypt(cli_public_key.strip(b'\x00')).split(b'pin_code_end')
        if pin_code in self.chatId_cli:
            #key_exchange
            packets = Packet_Maker(GET_GROUP_KEY,content=cli_public_key)
            self.chatId_cli[pin_code].append(self.client)
            for packet in packets:
                self.chatId_cli[pin_code][0].send(packet)
            self.chat_id = pin_code
            # packet = Packet_Maker(JOIN_CHAT,content=)
            # self.client.send(next(packet))
            # self.chatid_pubkey[pin_code] = {}
            # self.chatid_pubkey[pin_code][self.client] = cli_group_pub_key
            # self.chat_id = pin_code
            # packet = Packet_Maker(SEND_FIRST_KEY).__next__()
            # for client in self.chatId_cli[pin_code]:
            #     client.send(packet)
            # self.chatId_cli[pin_code].append(self.client)
            # time.sleep(2)
            # key_thread = key_distrebution.key_distribution(self.chatId_cli[self.chat_id],self.chatid_pubkey,self.chat_id)
            # key_thread.start()
        else:
            packet = Packet_Maker(CANT_JOIN_CHAT)
            self.client.send(next(packet))
            
                    
    def brodcast_packets(self):
        for client in self.chatId_cli[self.chat_id]:
            if client is not self.client:
                for packet in self.queue_requests:
                    client.send(packet)
        
    def login(self):
        #chack if the username and password is in the database
        login_details = b''
        for packet in self.queue_requests:
            login_details += packet[HEADER_SIZE:]
        login_details = self.decrypt(login_details.strip(b'\x00'))
        username, password = login_details[:USERNAME_MAX_LEN], login_details[USERNAME_MAX_LEN:]
        username = username.strip(b'\x00').decode("utf-8")
        password = password.strip(b'\x00').decode("utf-8")
        client_id = self.db_obj.password_chack(username,password)
        if client_id:
            if username in self.user_list:
                packets = Packet_Maker(USER_LOGGED_IN,self.key)
            else:
                # print(self.user_list)
                self.user_list.append(username)
                packets = Packet_Maker(REG_LOGIN_SUC,self.key)
        else:
            packets = Packet_Maker(REG_LOGIN_FAIL,self.key)

        
        self.client.send(next(packets))

    
    def register(self):
        #chack if the username and password is in the database
        #if true then get them into the database and if false then
        register_details = b''
        for packet in self.queue_requests:
            register_details += packet[HEADER_SIZE:]
        
        register_details = self.decrypt(register_details)
        username, password, Byear, Bmonth, Bday = struct.unpack(f"{USERNAME_MAX_LEN}s {PASSWORD_MAX_LEN}s 2s 1s 1s",register_details[:134])
        birthday= datetime.date(int.from_bytes(Byear,"big"), Bmonth[0], Bday[0])
        username = username.strip(b'\x00').decode("utf-8")
        password = password.strip(b'\x00').decode("utf-8")
        email = register_details[134:].strip(b'\x00').decode("utf-8")

        if self.db_obj.does_user_exist(username):
            packets = Packet_Maker(USERNAME_TAKEN,self.key)
        elif self.db_obj.does_email_exist(email):
            packets = Packet_Maker(EMAIL_TAKEN,self.key)
        else:
            #print(email)
            id_chacker = email_send.send_authentication_email(email)
            #print(id_chacker)
            if not id_chacker:
                packets = Packet_Maker(EMAIL_DOSENT_EXIST,self.key)
            else:
                packets = Packet_Maker(AUTHENTICAT_EMAIL,self.key)
                self.id_chacker = id_chacker
                self.current_details = [username,password,birthday,email]

        self.client.send(next(packets))

    
    def authenticat_email(self):
        pincode = b''
        for packet in self.queue_requests:
            pincode += packet[HEADER_SIZE:]
        pincode = pincode.strip(b'\x00')
        pincode = self.decrypt(pincode).decode("utf-8")
        #print(pincode)
        if self.id_chacker != pincode:
            packets = Packet_Maker(AUTHENTICAT_EMAIL,self.key)
        else:
            self.user_list.append(self.current_details[0])
            packets = Packet_Maker(REG_LOGIN_SUC,self.key)
            self.db_obj.insert_user(*self.current_details)
        self.client.send(next(packets))




    def get_users(self):
        #chack if logged in
        pass
    
    def replace_keys(self):
        pass
    
    def leave_chat(self):
        #chack if logged in
        pass

    def close_conn(self):
        if self.username:
            del self.user_list[self.user_list.index(self.username)]
        
        self.keep_runing = False

    def bytes_to_int(self,byte):
        number = 0
        for i in range(1,len(byte)+1):
            number += byte[-i]*i
        return number

    def buffer_extractor(self, buffer):
        request, request_id, packet_amount, packet_number, flag = struct.unpack("1s 8s 3s 3s 1s", buffer)
        return request, request_id, self.bytes_to_int(packet_amount) , self.bytes_to_int(packet_number) , flag
