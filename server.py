import socket

import pyperclip as pc
from Crypto.Random import get_random_bytes

import pyDH
from ganeral_dependencies.global_functions import bytes_to_int, int_to_bytes
from ganeral_dependencies.global_values import *
from server_dependencies import client_thread, sql_manager, server_enc

hostname = socket.gethostname()
local_ip = socket.gethostbyname(hostname)

print("ip copied to clipboard")
print(local_ip)


class server_values:
    public_chat_numbers = 1


# copying ip to clipboard
pc.copy(local_ip)

# setting up the server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("0.0.0.0", PORT))
server.listen()

# setting up needed variables and objects

database = sql_manager.UsersDatabase("userdata")

server_key = server_enc.key_generator()

# {chatId: [client,client...], ...}
chat_id_cli = {}


# {chatId: [username,username...], ...}
chat_id_name = {}

# {chat_name: chat_id e.g. chat_password}
chat_name_chat_id = {}

# {chat_name: key}
public_chat_key = {}


def create_password_less_chat():
    chat_name = "public chat number " + str(server_values.public_chat_numbers)
    server_values.public_chat_numbers += 1
    chat_name_chat_id[chat_name] = None
    chat_id_cli[chat_name] = []
    chat_id_name[chat_name] = []
    key = get_random_bytes(32)
    public_chat_key[chat_name] = key


user_list = []

create_password_less_chat()
while True:
    client, addr = server.accept()

    DH_parameters = pyDH.DiffieHellman()
    DH_pub_key = DH_parameters.gen_public_key()
    s = int_to_bytes(DH_pub_key)  # sing the key with the rsa private key
    client.send(s)
    client_public_key = bytes_to_int(client.recv(8192))  # gets the other contributor to the DH key exchange

    shared_secrete = DH_parameters.gen_shared_key(client_public_key)

    thread = client_thread.RequestHandler(client, addr, shared_secrete, database, chat_id_cli, chat_id_name, user_list,
                                          chat_name_chat_id, server_values, public_chat_key)

    thread.start()
