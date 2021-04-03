import hashlib
import pyDH
import socket

from client_dependencies import gui_manager
from ganeral_dependencies import global_values, protocol_digest
from ganeral_dependencies.global_functions import int_to_bytes, bytes_to_int

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server.connect((global_values.IP, global_values.PORT))

# key exchange
parameters = pyDH.DiffieHellman()
my_pub_key = parameters.gen_public_key()

# getting server keys
pub_DH_KEY = bytes_to_int(server.recv(8192))
server_pub_key = pub_DH_KEY
shared_secret = parameters.gen_shared_key(server_pub_key)
server.send(int_to_bytes(my_pub_key))
key = hashlib.sha256(int_to_bytes(shared_secret)).hexdigest().encode("utf-8")
print(key)
gui_manager.main(server, key)
