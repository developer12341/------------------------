import socket
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import pyDH

def unsing_key(server_e, server_n, DH_public_key):
    return pow(DH_public_key, server_e, server_n)


def sing_key(RSA_key, DH_public_key):
    return pow(DH_public_key, RSA_key.d, RSA_key.n)

def key_ganerator():
    key_file = open("mykey.bin","rb")
    file_content = key_file.read()
    key_file.close()
    key = RSA.import_key(file_content)
    return key