import hashlib
import ntpath
import struct


def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')


def hash_key(key):
    return hashlib.sha256(int_to_bytes(key)).hexdigest().encode("utf-8")


def bytes_to_int(bytes_obj: bytes) -> int:
    return int.from_bytes(bytes_obj, 'big')


def extract_file_name(path):
    head, tail = ntpath.split(path)
    return tail or ntpath.basename(head)


def buffer_extractor(buffer):
    request, request_id, packet_amount, packet_number, flag = struct.unpack("1s 8s 3s 3s 1s", buffer)
    return request, request_id, bytes_to_int(packet_amount), bytes_to_int(packet_number), flag
