from Crypto.PublicKey import RSA


def unsing_key(DH_public_key):
    key = get_server_pub_key()
    return pow(DH_public_key, key.e, key.n)


def sing_key(RSA_key, DH_public_key):
    return pow(DH_public_key, RSA_key.d, RSA_key.n)


def get_server_pub_key():
    key = RSA.import_key(open(".\\client_dependencies\\pubkey.bin", "rb").read())
    return key
