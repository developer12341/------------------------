import hashlib
import json
import ntpath
import struct
from base64 import b64encode, b64decode


def from_json(json_input):
    if json_input:
        print(json_input)
        json_input = json_input.strip(b'\x00')
        b64 = json.loads(json_input)
        json_k = ['username', 'password', 'email', "day", "month", 'year']
        jv = {k: b64decode(b64[k]) for k in json_k}
        return jv.values()
    return json_input


def to_json(username, password, email, day, month, year):
    json_k = ['username', 'password', 'email', "day", "month", 'year']
    json_v = [b64encode(x).decode('utf-8') for x in (username, password, email, day, month, year)]

    result = json.dumps(dict(zip(json_k, json_v)))
    return result.encode("utf-8")


def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')


def bytes_to_int(bytes_obj: bytes) -> int:
    return int.from_bytes(bytes_obj, 'big')


def hash_key(key):
    return hashlib.sha256(int_to_bytes(key)).hexdigest().encode("utf-8")


def hash_password(password):
    hash_ = hashlib.sha256()
    hash_.update(password.encode("utf-8"))
    return hash_.hexdigest()


def extract_file_name(path):
    head, tail = ntpath.split(path)
    return tail or ntpath.basename(head)


def buffer_extractor(buffer):
    request, request_id, packet_amount, packet_number, flag = struct.unpack("1s 8s 3s 3s 1s", buffer)
    return request, request_id, bytes_to_int(packet_amount), bytes_to_int(packet_number), flag
