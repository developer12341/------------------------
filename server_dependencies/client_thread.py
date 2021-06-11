import datetime
import hashlib
import json
import threading
import uuid
from base64 import b64decode

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

from ganeral_dependencies import AES_crypto
from Crypto.Cipher import AES

from ganeral_dependencies.global_functions import int_to_bytes, buffer_extractor, from_json, bytes_to_int, \
    reset_password_from_json, merge_int_lists
from ganeral_dependencies.global_values import *
from ganeral_dependencies.protocol import PacketMaker
from server_dependencies import email_send


class RequestHandler(threading.Thread):
    def __init__(self, client, addr, shared_secret, db_obj, chat_id_cli, chat_id_name, user_list,
                 chat_name_chat_id: dict, server_values, public_chat_key):
        self.chat_name = None
        self.server_values = server_values
        self.password = ""
        self.auth_for_change_password = False
        self.client = client
        self.addr = addr
        self.key = hashlib.sha256(int_to_bytes(shared_secret)).hexdigest().encode("utf-8")
        self.db_obj = db_obj
        self.queue_requests = []
        self.user_list = user_list
        self.current_details = []
        self.chat_name_chat_id = chat_name_chat_id  # {chat_name: chat_id e.g. chat_password}
        self.public_chat_key = public_chat_key  # {chat_name: key} only for public chats
        self.chat_id_cli = chat_id_cli  # {chatId: [client,client...], ...}
        self.chat_id_name = chat_id_name  # {chatId: [username,username...], ...}
        self.chat_id = None
        self.username = None
        self.keep_running = True
        self.id_check = None
        threading.Thread.__init__(self)

    def decrypt(self, json_input):
        try:
            if json_input:
                json_input = json_input.strip(b'\x00')
                b64 = json.loads(json_input)
                json_k = ['nonce', 'header', 'ciphertext', 'tag']
                jv = {k: b64decode(b64[k]) for k in json_k}
                cipher = AES.new(self.key, AES.MODE_SIV, nonce=jv['nonce'])
                cipher.update(jv['header'])
                plaintext = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])
                return plaintext
            return json_input
        except json.decoder.JSONDecodeError as e:
            print("json_input: " + str(json_input))
            print("json_input len: " + str(len(json_input)))
            print("error")
            raise e

    def run(self):
        while self.keep_running:
            # receive packets from client
            packet = self.client.recv(PACKET_SIZE)
            if packet == b'':
                self.close_conn()
                return
            request, request_id, packet_amount, packet_number, flag = buffer_extractor(packet[:HEADER_SIZE])
            self.queue_requests.append(packet)
            bad_packets_list = []
            if len(packet) != 1024:
                request, request_id, packet_amount, packet_number, flag = buffer_extractor(packet[:HEADER_SIZE])
                bad_packets_list.append(packet_number)
            if packet_amount > 1:
                for _ in range(packet_amount - packet_number - 1):
                    packet = self.client.recv(PACKET_SIZE)
                    if len(packet) != 1024:
                        request, request_id, packet_amount, packet_number, flag = buffer_extractor(packet[:HEADER_SIZE])
                        bad_packets_list.append(packet_number)
                    self.queue_requests.append(packet)

            # need to check packet validity

            if packet_amount - len(self.queue_requests):
                print("fuck, something went wrong")
                # not every packet was sent for some reason
                packets_not_arrived = list(range(packet_amount))
                print(packets_not_arrived)
                for packet in self.queue_requests:
                    request, request_id, packet_amount, packet_number, flag = buffer_extractor(packet[:HEADER_SIZE])
                    packets_not_arrived.remove(packet_number)
                    print(str(packet_number) + " has arrived safely")
                bad_packets_list = merge_int_lists(bad_packets_list, packets_not_arrived)

            print(packets_not_arrived)

            if bad_packets_list:
                bad_packets_list = list(map(lambda number: str(number), bad_packets_list))
                content = request_id + b"," + " ".join(bad_packets_list).encode("utf-8")
                packets = PacketMaker(RESEND_PACKETS, content=content, shared_secret=self.key)
                for packet in packets:
                    print(packet)
                    self.client.send(packet)

                packet = self.client.recv(PACKET_SIZE)
                if packet == b'':
                    self.close_conn()
                    return
                request, request_id, packet_amount, packet_number, flag = buffer_extractor(packet[:HEADER_SIZE])
                self.queue_requests.insert(packet_number, packet)
                if packet_amount > 1:
                    for _ in range(packet_amount - packet_number - 1):
                        packet = self.client.recv(PACKET_SIZE)
                        self.queue_requests.insert(packet_number, packet)

            # sort by request
            if request == SEND_IMG or request == SEND_FILE or request == SEND_MSG:
                print(packet_amount - len(self.queue_requests))
                if request == SEND_FILE or request == SEND_IMG:
                    print("sending file/img " + str(packet_amount - len(self.queue_requests)))
                    packets = PacketMaker(SENDING_COMPLITED, content=request_id, shared_secret=self.key)
                    for packet in packets:
                        self.client.send(packet)
                    # s = b''.join(self.queue_requests)
                self.broadcast_packets()
            elif request == LOGIN:
                self.login()
            elif request == REGISTER:
                self.register()
            elif request == JOIN_CHAT:
                self.join_chat()
            elif request == CREATE_CHAT:
                self.create_chat()
            # elif request == GET_USERS:
            #     self.get_users()
            elif request == GET_GROUP_INFO:
                self.get_group_info()
            elif request == RESET_PASSWORD:
                self.reset_password()
            elif request == LEAVE_CHAT:
                self.leave_chat()
            elif request == SEND_PIN_CODE:
                self.authenticate_email()
            elif request == SEND_GROUP_KEYS:
                self.send_group_keys()
            elif request == GET_CHATS:
                self.get_chats()
            elif request == JOIN_PASSWORD_LESS_CHAT:
                self.join_password_less_chat()
            elif request == CREATE_PUBLIC_CHAT:
                self.create_public_chat()
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
        full_msg = self.queue_requests.pop()[HEADER_SIZE:]
        is_password_protected = full_msg[0]
        is_password_protected = bool(is_password_protected)
        chat_id = uuid.uuid4().bytes[:3]
        chat_id = chat_id.hex()
        chat_name = self.username + "'s private chat"
        if is_password_protected:
            chat_name += " (safe chat)"
        print(chat_id)
        self.chat_name_chat_id[chat_name] = chat_id
        self.chat_id_cli[chat_id] = [self.client]
        self.chat_id_name[chat_id] = [self.username]
        self.chat_id = chat_id
        content = chat_name.encode("utf-8") + b"~~~" + chat_id.encode("utf-8")
        packets = PacketMaker(JOIN_CHAT, shared_secret=self.key, content=content)
        for packet in packets:
            self.client.send(packet)

    def create_public_chat(self):
        full_msg = b''
        for packet in self.queue_requests:
            full_msg += packet[HEADER_SIZE:]
        full_msg = self.decrypt(full_msg)
        rsa_key, swear_protection = full_msg[:-1], full_msg[-1]
        chat_name = self.username + "'s public chat"
        if bool(swear_protection):
            chat_name += " (safe chat)"

        self.chat_name_chat_id[chat_name] = None
        self.chat_id_cli[chat_name] = [self.client]
        self.chat_id_name[chat_name] = [self.username]
        secret_key = get_random_bytes(32)
        self.public_chat_key[chat_name] = secret_key
        self.chat_id = chat_name
        client_public_key = RSA.import_key(rsa_key.decode("utf-8"))
        content = AES_crypto.rsa_encrypt(self.public_chat_key[chat_name], client_public_key)
        packets = PacketMaker(GET_GROUP_KEY, content=content)
        for packet in packets:
            self.client.send(packet)
        self.chat_id = chat_name

    def join_password_less_chat(self):
        full_msg = b''
        for packet in self.queue_requests:
            full_msg += packet[HEADER_SIZE:]

        content = self.decrypt(full_msg)
        content = json.loads(content.decode("utf-8"))
        chat_name, rsa_key = content.values()
        if chat_name in self.public_chat_key:
            # key_exchange
            client_public_key = RSA.import_key(rsa_key.encode("utf-8"))
            content = AES_crypto.rsa_encrypt(self.public_chat_key[chat_name], client_public_key)
            packets = PacketMaker(GET_GROUP_KEY, content=content)
            self.chat_id_cli[chat_name].append(self.client)
            self.chat_id_name[chat_name].append(self.username)
            for packet in packets:
                self.client.send(packet)
            self.chat_id = chat_name
            self.chat_name = chat_name
        else:
            packet = PacketMaker(CANT_JOIN_CHAT)
            self.client.send(next(packet))

    def join_chat(self):
        # check if logged in
        full_msg = b''
        for packet in self.queue_requests:
            full_msg += packet[HEADER_SIZE:]
        full_msg = self.decrypt(full_msg)
        content = json.loads(full_msg)
        chat_name, pin_code, rsa_key = content.values()
        if self.chat_name_chat_id[chat_name] == pin_code:
            # key_exchange
            packets = PacketMaker(GET_GROUP_KEY, content=rsa_key.encode("utf-8"))
            self.chat_id_cli[pin_code].append(self.client)
            self.chat_id_name[pin_code].append(self.username)
            for packet in packets:
                self.chat_id_cli[pin_code][0].send(packet)
            self.chat_id = pin_code
            self.chat_name = chat_name
        else:
            packet = PacketMaker(CANT_JOIN_CHAT)
            self.client.send(next(packet))

    def broadcast_packets(self):
        print()
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
        username, password, email, day, month, year = from_json(register_details)
        birthday = datetime.date(bytes_to_int(year), month[0], day[0])
        username = username.decode("utf-8")
        password = password.decode("utf-8")
        email = email.decode("utf-8")

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
            packets = PacketMaker(REG_LOGIN_SUC)
            self.db_obj.insert_user(*self.current_details)
        self.client.send(next(packets))

    def get_users(self):
        # check if logged in
        pass

    def reset_password(self):

        # check if the username and password is in the database
        # if true then get them into the database and if false then
        rename_details = b''
        for packet in self.queue_requests:
            rename_details += packet[HEADER_SIZE:]

        rename_details = self.decrypt(rename_details)
        username, password, email = reset_password_from_json(rename_details)
        username = username.decode("utf-8")
        password = password.decode("utf-8")
        email = email.decode("utf-8")
        if username in self.user_list:
            packets = PacketMaker(USER_LOGGED_IN)
            self.client.send(next(packets))
        elif self.db_obj.does_user_email_exist(username, email):
            self.password = password
            self.username = username
            self.auth_for_change_password = True
            email_send.send_authentication_email(email)
            packets = PacketMaker(AUTHENTICATE_EMAIL)
            self.client.send(next(packets))
        else:
            packets = PacketMaker(REG_LOGIN_FAIL)
            self.client.send(next(packets))

    def leave_chat(self):
        print(self.username + " left chat " + str(self.chat_name))
        del self.chat_id_cli[self.chat_id][self.chat_id_cli[self.chat_id].index(self.client)]
        del self.chat_id_name[self.chat_id][self.chat_id_name[self.chat_id].index(self.username)]
        if self.chat_id not in self.public_chat_key:
            if not self.chat_id_cli[self.chat_id]:
                del self.chat_id_cli[self.chat_id]
                for item in self.chat_name_chat_id:
                    if self.chat_name_chat_id[item] == self.chat_id:
                        del self.chat_name_chat_id[item]
                        break
            if not self.chat_id_name[self.chat_id]:
                del self.chat_id_name[self.chat_id]
        self.chat_id = None
        self.chat_name = None

    def close_conn(self):
        if self.chat_id or self.chat_name:
            self.leave_chat()
        if self.username:
            self.user_list.remove(self.username)
        self.keep_running = False

    def get_group_info(self):
        content = "\n".join(self.chat_id_name[self.chat_id])
        packets = PacketMaker(GET_GROUP_INFO, shared_secret=self.key, content=content.encode("utf-8"))
        for packet in packets:
            self.client.send(packet)

    def get_chats(self):
        chat_list = {}
        for key, value in self.chat_name_chat_id.items():
            if not value:
                chat_list[key] = "public"
            else:
                chat_list[key] = "private"

        content = json.dumps(chat_list)
        packets = PacketMaker(GET_CHATS, content=content.encode("utf-8"), shared_secret=self.key)
        for packet in packets:
            self.client.send(packet)
