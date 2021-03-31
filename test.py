
from Crypto.PublicKey import RSA
def key_ganerator():
    key_file = open("mykey.pem","wb+")
    file_content = key_file.read()
    key = None
    if file_content == b"":
        key = RSA.generate(2048)
        key_file.write(key.export_key("PEM"))
    else:
        key = RSA.import_key(file_content)
    key_file.close()
    return key

key = key_ganerator()
pub = key.public_key()
key_file = open("pubkey.pem","wb")
key_file.write(pub.export_key("PEM"))