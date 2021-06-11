import hashlib
import re

import pyDH
import socket
import sys

from client_dependencies import gui_manager
from ganeral_dependencies import global_values, protocol_digest
from ganeral_dependencies.global_functions import int_to_bytes, bytes_to_int

# Make a regular expression
# for validating an Ip-address
regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"


# Define a function for
# validate an Ip address
def check(Ip):
    # pass the regular expression
    # and the string in search() method
    if re.search(regex, Ip):
        return True

    else:
        return False


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
IP = input("please enter the server's IP (if the server is in this computer just hit enter): ")
if not check(IP):
    IP = "127.0.0.1"

server.connect((IP, global_values.PORT))

# key exchange
parameters = pyDH.DiffieHellman()
my_pub_key = parameters.gen_public_key()

# getting server keys
pub_DH_KEY = bytes_to_int(server.recv(8192))
server_pub_key = pub_DH_KEY
shared_secret = parameters.gen_shared_key(server_pub_key)
server.send(int_to_bytes(my_pub_key))
key = hashlib.sha256(int_to_bytes(shared_secret)).hexdigest().encode("utf-8")
gui_manager.main(server, key)
