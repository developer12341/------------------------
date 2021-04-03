import socket
import pyDH,hashlib
from ganeral_dependencies.global_values import *
from server_dependencies import client_thread, sql_manager, server_enc
from ganeral_dependencies import pac_comp
#setting up the server
server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server.bind((IP,PORT))
server.listen()


#setting up needed varubles and objects

data_base = sql_manager.User_Db("userdata")

server_key = server_enc.key_ganerator()

#{client_id: notification_client_obj}
clientid_client = {}
#{chatId: [client,client...], ...}
chatId_cli = {}
#{chatId:none or [pub_key1, pub_key2]...} 
#for the group_dh_key_excange
chatid_pubkey = {}

while True:
    client, addr = server.accept()

    DH_parameters = pyDH.DiffieHellman()
    DH_pub_key = DH_parameters.gen_public_key()
    s = (pac_comp.int_to_bytes(server_enc.sing_key(server_key, DH_pub_key)))# sing the key with the rsa private key
    client.send(s)
    client_public_key = pac_comp.bytes_to_int(client.recv(8192)) # gets the other contributer to the DH key exchange

    shared_secrete = DH_parameters.gen_shared_key(client_public_key)
    # key = hashlib.sha256(pac_comp.int_to_bytes(shared_secrete)).hexdigest().encode("ascii")
    
    thread = client_thread.request_heandler(client,addr,shared_secrete,data_base, chatId_cli, chatId_cli, chatid_pubkey)

    thread.start()