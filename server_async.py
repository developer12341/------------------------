import socket
from ganeral_dependencies import RSA_crypt
from ganeral_dependencies.global_values import *
from server_dependencies import client_thread, sql_manager


#setting up the server
server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server.bind((IP,PORT))
server.listen()


#setting up the notification_port
notification_server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
notification_server.bind((IP,NOTIFICATION_PORT))
notification_server.listen()

#setting up needed varubles and objects
server_e, server_d, server_N = RSA_crypt.generateKeys(32)
public_key = f"{server_e} {server_N} "
data_base = sql_manager.User_Db("userdata")


#{client_id: notification_client_obj}
clientid_client = {}
#{chatId: [client,client...], ...}
chatId_cli = {}

while True:

    client, addr = server.accept()
    try:
        client.send(public_key.encode("ascii"))

        encrypted_msg = client.recv(2048)

        msg = RSA_crypt.decrypt(encrypted_msg, server_d,server_N).split()
        client_e, client_d, client_N = map(lambda string: int(string),msg)

        thread = client_thread.request_heandler(client,addr,client_e,client_d,client_N,notification_server,data_base, chatId_cli, chatId_cli,)

        thread.start()
    except:
        pass