import hashlib
import json
from base64 import b64encode, b64decode

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

from ganeral_dependencies.global_functions import int_to_bytes


def encrypt(data, bytes_key):
    header = get_random_bytes(8)
    key = hashlib.sha256(int_to_bytes(bytes_key)).hexdigest().encode("utf-8")
    nonce = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_SIV, nonce=nonce)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    json_k = ['nonce', 'header', 'ciphertext', 'tag']
    json_v = [b64encode(x).decode('utf-8') for x in (nonce, header, ciphertext, tag)]
    result = json.dumps(dict(zip(json_k, json_v)))
    return result


def decrypt(json_input, bytes_key: bytes):
    if json_input:
        json_input = json_input.strip(b'\x00')
        b64 = json.loads(json_input)
        json_k = ['nonce', 'header', 'ciphertext', 'tag']
        jv = {k: b64decode(b64[k]) for k in json_k}
        cipher = AES.new(bytes_key, AES.MODE_SIV, nonce=jv['nonce'])
        cipher.update(jv['header'])
        plaintext = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])
        return plaintext
    return json_input


def rsa_encrypt(data, public_key):
    session_key = get_random_bytes(16)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    json_k = ['enc_session_key', 'nonce', 'ciphertext', 'tag']
    json_v = [b64encode(x).decode('utf-8') for x in [enc_session_key, cipher_aes.nonce, ciphertext, tag]]
    result = json.dumps(dict(zip(json_k, json_v)))
    return result.encode("utf-8")


def rsa_decrypt(json_input, private_key):
    b64 = json.loads(json_input)
    json_k = ['enc_session_key', 'nonce', 'ciphertext', 'tag']
    jv = {k: b64decode(b64[k]) for k in json_k}

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(jv["enc_session_key"])

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, jv["nonce"])
    data = cipher_aes.decrypt_and_verify(jv["ciphertext"], jv["tag"])
    return data
