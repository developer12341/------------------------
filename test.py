
from Crypto.PublicKey import RSA

def get_server_pub_key():
    key = RSA.import_key(open(".\\client_dependencies\\pubkey.bin","rb").read())
    return key
    
def PublicKey_to_file(key):
    key_file = open(".\\client_dependencies\\pubkey.bin","wb+")
    file_content = key.public_key().export_key()
    key_file.write(file_content)
    key_file.close()

def key_ganerator():
    key_file = open("mykey.bin","rb")
    file_content = key_file.read()
    key_file.close()
    key = None
    if file_content == b"":
        key_file = open("mykey.bin","wb")
        key = RSA.generate(2048)
        key_file.write(key.export_key("PEM"))
        key_file.close()
    else:
        key = RSA.import_key(file_content)
    return key


rsa_key = key_ganerator()
PublicKey_to_file(rsa_key)
public_key = get_server_pub_key()

def unsing_key(DH_public_key):
    key = get_server_pub_key()
    return pow(DH_public_key, key.e, key.n)


def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')
    
def bytes_to_int(xbytes: bytes) -> int:
    return int.from_bytes(xbytes, 'big')
    
def sing_key(RSA_key, DH_public_key):
    return pow(DH_public_key, RSA_key.d, RSA_key.n)
key = b"secreat"
singed_key = sing_key(rsa_key,bytes_to_int(key))
print(singed_key)
i = unsing_key(singed_key)
print(int_to_bytes(i))