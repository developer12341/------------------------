import datetime
import hashlib
import json
import struct
import threading
import uuid
from base64 import b64decode

from Crypto.Cipher import AES

from ganeral_dependencies.global_functions import int_to_bytes, buffer_extractor, bytes_to_int
from ganeral_dependencies.global_values import *
from ganeral_dependencies.protocols import PacketMaker
from server_dependencies import email_send


class RequestHandler(threading.Thread):
    def __init__(self, client, addr, shared_secret, db_obj, chat_id_cli, user_list):
        self.client = client
        self.addr = addr
        self.key = hashlib.sha256(int_to_bytes(shared_secret)).hexdigest().encode("utf-8")
        self.db_obj = db_obj
        self.queue_requests = []
        self.user_list = user_list
        self.current_details = []
        self.chat_id_cli = chat_id_cli  # {chatId: [client,client...], ...}
        self.chat_id = None
        self.username = None
        self.keep_running = True
        self.id_check = None
        threading.Thread.__init__(self)

    def decrypt(self, json_input):
        if json_input:
            json_input = json_input.strip(b'\x00')
            b64 = json.loads(json_input)
            json_k = ['nonce', 'header', 'ciphertext', 'tag']
            jv = {k: b64decode(b64[k]) for k in json_k}
            cipher = AES.new(self.key, AES.MODE_SIV, nonce=jv['nonce'])
            cipher.update(jv['header'])
            plaintext = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])
            return plaintext
        else:
            return json_input

    def run(self):
        while self.keep_running:
            # receive packets from client
            packet = self.client.recv(PACKET_SIZE)
            if packet == b'':
                self.close_conn()
                return
            request, request_id, packet_amount, packet_number, flag = buffer_extractor(packet[:HEADER_SIZE])
            self.queue_requests.append(packet)
            if packet_amount > 1:
                for _ in range(packet_amount - 1):
                    packet = self.client.recv(PACKET_SIZE)
                    self.queue_requests.append(packet)

            # need to check packet validity

            # sort by request
            if request == SEND_IMG or request == SEND_FILE or request == SEND_MSG:
                self.broadcast_packets()
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
            # elif request == GET_GROUP_KEY:
            #     self.get_group_key()
            # elif request == REPLACE_KEYS:
            #     self.replace_keys()
            elif request == LEAVE_CHAT:
                self.leave_chat()
            elif request == SEND_PIN_CODE:
                self.authenticate_email()
            elif request == SEND_GROUP_KEYS:
                self.send_group_keys()
            elif request == CLOSE_CONN:
                self.close_conn()
                return

            self.queue_requests = []
        self.client.close()

    def send_group_keys(self):
        for packet in self.queue_requests:
            self.chat_id_cli[self.chat_id][-1].send(packet)

    # def get_group_key(self):
    #     cli_group_pub_key = b''
    #     for packet in self.queue_requests:
    #         cli_group_pub_key += packet[HEADER_SIZE:]
    #     key_index, cli_group_pub_key = self.decrypt(cli_group_pub_key).split(b"index_code_end")
    #     key_index = pin_code.decode("utf-8")
    #     for key_index_value, key in self.chat_id_pubkey[self.chat_id].items():
    #         if key_index_value == key_index:
    #             self.chat_id_pubkey[key_index_value] = cli_group_pub_key
    #             break

    def create_chat(self):
        chat_id = uuid.uuid4().bytes[:3]
        chat_id = chat_id.hex()
        chat_id = chat_id.encode("utf-8")
        print(chat_id)
        self.chat_id_cli[chat_id] = [self.client]
        self.chat_id = chat_id
        packets = PacketMaker(JOIN_CHAT, self.key, content=chat_id)
        for packet in packets:
            self.client.send(packet)

    def join_chat(self):
        # check if logged in
        cli_public_key = b''
        for packet in self.queue_requests:
            cli_public_key += packet[HEADER_SIZE:]
        pin_code, cli_public_key = self.decrypt(cli_public_key.strip(b'\x00')).split(b'pin_code_end')
        if pin_code in self.chat_id_cli:
            # key_exchange
            packets = PacketMaker(GET_GROUP_KEY, content=cli_public_key)
            self.chat_id_cli[pin_code].append(self.client)
            for packet in packets:
                self.chat_id_cli[pin_code][0].send(packet)
            self.chat_id = pin_code
        else:
            packet = PacketMaker(CANT_JOIN_CHAT)
            self.client.send(next(packet))

    def broadcast_packets(self):
        for client in self.chat_id_cli[self.chat_id]:
            if client is not self.client:
                for packet in self.queue_requests:
                    client.send(packet)

    def login(self):
        # check if the username and password is in the database
        login_details = b''
        for packet in self.queue_requests:
            login_details += packet[HEADER_SIZE:]
        login_details = self.decrypt(login_details.strip(b'\x00'))
        username, password = login_details[:USERNAME_MAX_LEN], login_details[USERNAME_MAX_LEN:]
        username = username.strip(b'\x00').decode("utf-8")
        password = password.strip(b'\x00').decode("utf-8")
        client_id = self.db_obj.password_check(username, password)
        if client_id:
            if username in self.user_list:
                packets = PacketMaker(USER_LOGGED_IN, self.key)
            else:
                self.user_list.append(username)
                self.username = username
                packets = PacketMaker(REG_LOGIN_SUC, self.key)
        else:
            packets = PacketMaker(REG_LOGIN_FAIL, self.key)

        self.client.send(next(packets))

    def register(self):
        # check if the username and password is in the database
        # if true then get them into the database and if false then
        register_details = b''
        for packet in self.queue_requests:
            register_details += packet[HEADER_SIZE:]

        register_details = self.decrypt(register_details)
        username, password, year, month, day = struct.unpack(f"{USERNAME_MAX_LEN}s {PASSWORD_MAX_LEN}s 2s 1s 1s",
                                                             register_details[:134])
        birthday = datetime.date(bytes_to_int(year), month[0], day[0])
        username = username.strip(b'\x00').decode("utf-8")
        password = password.strip(b'\x00').decode("utf-8")
        email = register_details[134:].strip(b'\x00').decode("utf-8")

        if self.db_obj.does_user_exist(username):
            packets = PacketMaker(USERNAME_TAKEN, self.key)
        elif self.db_obj.does_email_exist(email):
            packets = PacketMaker(EMAIL_TAKEN, self.key)
        else:
            id_check = email_send.send_authentication_email(email)
            if not id_check:
                packets = PacketMaker(EMAIL_DOESNT_EXIST, self.key)
            else:
                packets = PacketMaker(AUTHENTICATE_EMAIL, self.key)
                self.id_check = id_check
                self.current_details = [username, password, birthday, email]

        self.client.send(next(packets))

    def authenticate_email(self):
        pin_code = b''
        for packet in self.queue_requests:
            pin_code += packet[HEADER_SIZE:]
        pin_code = pin_code.strip(b'\x00')
        pin_code = self.decrypt(pin_code).decode("utf-8")
        if self.id_check != pin_code:
            packets = PacketMaker(AUTHENTICATE_EMAIL, self.key)
        else:
            self.user_list.append(self.current_details[0])
            self.username = self.current_details[0]
            packets = PacketMaker(REG_LOGIN_SUC, self.key)
            self.db_obj.insert_user(*self.current_details)
        self.client.send(next(packets))

    def get_users(self):
        # check if logged in
        pass

    def replace_keys(self):
        pass

    def leave_chat(self):
        # check if logged in
        pass

    def close_conn(self):
        if self.username:
            del self.user_list[self.user_list.index(self.username)]
        self.keep_running = False
