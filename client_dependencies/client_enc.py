import socket
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import pyDH

def bytes_to_int(xbytes: bytes) -> int:
    return int.from_bytes(xbytes, 'big')
    
def unsing_key(DH_public_key):
    key = get_server_pub_key()
    return pow(bytes_to_int(DH_public_key), key.e, key.n)


def sing_key(RSA_key, DH_public_key):
    return pow(DH_public_key, RSA_key.d, RSA_key.n)

def get_server_pub_key():
    key = RSA.import_key(open(".\\client_dependencies\\pubkey.pem","rb").read())
    return key