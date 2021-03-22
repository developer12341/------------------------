import struct
from ganeral_dependencies.global_values import *

def decrypt(cipher,private_key):
    cipher = cipher.strip(b'\x00')
    parts = cipher.split()
    d,N = private_key
    #convert to int
    new_parts = []
    for part in parts:
        if part:
            new_parts.append( int(part))
    msg = map(lambda number: pow(number,d,N),new_parts)
    msg = bytes(msg)

    return msg

def bytes_to_int(byte):
    number = 0
    for i in range(1,len(byte)+1):
        number += byte[-i]*i
    return number
        
def buffer_extractor(buffer):
    request, request_id, packet_amount, packet_number, flag = struct.unpack("1s 8s 3s 3s 1s", buffer)
    return request, request_id, bytes_to_int(packet_amount) , bytes_to_int(packet_number) , flag

def extract_chat_id(packet,private_key):
    request, request_id, packet_amount, packet_number, flag = buffer_extractor(packet[:HEADER_SIZE])
    chat_id = packet[HEADER_SIZE:].strip(b'\x00')
    chat_id = decrypt(chat_id,private_key)
    return chat_id


def is_logged_in(packet):
    request, request_id, packet_amount, packet_number, flag = buffer_extractor(packet[:HEADER_SIZE])
    
    #packet validity
    if packet_number >= packet_amount:
        raise Exception("this packets are invalid")
    

    if request == REG_LOGIN_SUC:
        if flag != SOMETHING_ELSE:
            #packet validity
            raise Exception("this packet's request doesn't match the flag \n request == REG_LOGIN_SUC\n flag != R_L_SUC")
        return True
    elif request in [REG_LOGIN_FAIL,AUTHENTICAT_EMAIL]:
        if flag != SOMETHING_ELSE:
            #packet validity
            raise Exception("this packet's request doesn't match the flag \n request == REG_LOGIN_FAIL\n flag != R_L_FAIL")
        return False
    else:
        #packet validity
        raise Exception("this packet isn't REG_LOGIN type, please chack the server side for bugs")

def can_auth_email(packet):
    request, request_id, packet_amount, packet_number, flag = buffer_extractor(packet[:HEADER_SIZE])
    
    #packet validity
    if packet_number >= packet_amount:
        raise Exception("this packets are invalid")
    

    if request in [REG_LOGIN_FAIL,USERNAME_TAKEN,REG_LOGIN_SUC,AUTHENTICAT_EMAIL,EMAIL_DOSENT_EXIST]:
        if flag != SOMETHING_ELSE:
            #packet validity
            raise Exception("this packet's request doesn't match the flag \n request == REG_LOGIN_SUC\n flag != R_L_SUC")
        return request == AUTHENTICAT_EMAIL, request
    else:
        #packet validity
        raise Exception("this packet isn't REG_LOGIN type, please chack the server side for bugs")
