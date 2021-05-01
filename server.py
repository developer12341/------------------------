import socket

import pyperclip as pc

import pyDH

from ganeral_dependencies.global_functions import bytes_to_int, int_to_bytes
from ganeral_dependencies.global_values import *
from server_dependencies import client_thread, sql_manager, server_enc
hostname = socket.gethostname()
local_ip = socket.gethostbyname(hostname)

print("ip copied to clipboard")
print(local_ip)

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

user_list = []
while True:
    client, addr = server.accept()

    DH_parameters = pyDH.DiffieHellman()
    DH_pub_key = DH_parameters.gen_public_key()
    s = int_to_bytes(DH_pub_key)  # sing the key with the rsa private key
    client.send(s)
    client_public_key = bytes_to_int(client.recv(8192))  # gets the other contributor to the DH key exchange

    shared_secrete = DH_parameters.gen_shared_key(client_public_key)

    thread = client_thread.RequestHandler(client, addr, shared_secrete, database, chat_id_cli, chat_id_name, user_list)

    thread.start()
