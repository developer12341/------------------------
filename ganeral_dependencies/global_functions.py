import hashlib
import json
import ntpath
import struct
from base64 import b64encode, b64decode


def from_json(json_input):
    if json_input:
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


def reset_password_to_json(username, email, password):
    json_k = ['username', 'password', 'email']
    json_v = [b64encode(x).decode('utf-8') for x in (username, password, email)]

    result = json.dumps(dict(zip(json_k, json_v)))
    return result.encode("utf-8")


def reset_password_from_json(json_input):
    if json_input:
        json_input = json_input.strip(b'\x00')
        b64 = json.loads(json_input)
        json_k = ['username', 'password', 'email']
        jv = {k: b64decode(b64[k]) for k in json_k}
        return jv.values()
    return json_input


def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')


def bytes_to_int(bytes_obj: bytes) -> int:
    return int.from_bytes(bytes_obj, 'big')


# def binery_search_closest(list1:list, number:int):
#     list1
#

def merge_int_lists(list1: list, list2: list) -> list:
    list1.sort()
    for item in list2:
        if item not in list1:
            index = binary_search(list1, 0, len(arr) - 1, item)
            if index == len(list1):
                list1.append(item)
            else:
                list1[index] = item


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


# Python 3 program for recursive binary search.
# Modifications needed for the older Python 2 are found in comments.

# Returns index of x in arr if present, else -1
def binary_search(arr, low, high, x):
    # Check base case
    if high >= low:

        mid = (high + low) // 2

        # If element is present at the middle itself
        if arr[mid] == x:
            return mid

        # If element is smaller than mid, then it can only
        # be present in left subarray
        elif arr[mid] > x:
            return binary_search(arr, low, mid - 1, x)

        # Else the element can only be present in right subarray
        else:
            return binary_search(arr, mid + 1, high, x)

    else:
        # Element is not present in the array
        return low


if __name__ == "__main__":
    # Test array
    arr = [2, 3, 4, 10, 40]
    arr2 = [4, 5, 80]
    merge_int_lists(arr, arr2)
    print(arr)
