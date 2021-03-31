from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib, json
from base64 import b64encode, b64decode

def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def encrypt(data, DH_shared_KEY):
    header = get_random_bytes(8)
    key = hashlib.sha256(int_to_bytes(DH_shared_KEY)).hexdigest().encode("ascii")
    nonce = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_SIV, nonce=nonce)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
    json_v = [ b64encode(x).decode('utf-8') for x in (nonce, header, ciphertext, tag) ]
    result = json.dumps(dict(zip(json_k, json_v)))
    return result

def decrypt(json_input, bytes_key: bytes):
    b64 = json.loads(json_input)
    json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
    jv = {k:b64decode(b64[k]) for k in json_k}
    cipher = AES.new(bytes_key, AES.MODE_SIV, nonce=jv['nonce'])
    cipher.update(jv['header'])
    plaintext = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])
    return plaintext
    
