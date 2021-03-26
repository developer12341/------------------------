import socket,time
from ganeral_dependencies import RSA_crypt,global_values
import client_dependencies.gui_manager as gui_manager

server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

server.connect((global_values.IP,global_values.PORT))


#key exchange

#getting server keys
server_e, server_N = server.recv(global_values.PACKET_SIZE).decode("ascii").split()
server_e, server_N = int(server_e), int(server_N)


#ganerating the client keys
keys = RSA_crypt.generateKeys(32)
massage = map(lambda num: str(num),keys)
massage = " ".join(massage)

encrypted_msg = RSA_crypt.encrypt(massage.encode("ascii"),server_e,server_N)
server.send(encrypted_msg)

gui_manager.main(server,keys)

