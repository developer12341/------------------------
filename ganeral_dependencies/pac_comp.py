import struct
from ganeral_dependencies.global_values import *
from ganeral_dependencies.AES_crypto import decrypt
from ganeral_dependencies.protocols import Packet_Maker
def get_shared_secret(server, cur_shared_secrat,dh_parameters):
    request, request_id, packet_amount, packet_number, flag = buffer_extractor(server.recv(HEADER_SIZE))
    content = server.recv(CONTENT_SIZE)
    while packet_number + 1 < packet_amount:
        request, request_id, packet_amount, packet_number, flag = buffer_extractor(server.recv(HEADER_SIZE))
        content += server.recv(CONTENT_SIZE)
    
    while request != END_SETTION:
        key_index, public_key = content[0], bytes_to_int(content[1:])
        cur_shared_secrat = dh_parameters.gen_shared_key(public_key)
        content = key_index + int_to_bytes(cur_shared_secrat)
        packets = Packet_Maker(GET_GROUP_KEY, content=content)
        for packet in packets:
            server.send(packet)
        
        request, request_id, packet_amount, packet_number, flag = buffer_extractor(server.recv(HEADER_SIZE))
        content = server.recv(CONTENT_SIZE)
        while packet_number + 1 < packet_amount:
            request, request_id, packet_amount, packet_number, flag = buffer_extractor(server.recv(HEADER_SIZE))
            content += server.recv(CONTENT_SIZE)
    
    key_index, public_key = content[0], bytes_to_int(content[1:])
    cur_shared_secrat = dh_parameters.gen_shared_key(public_key)
        
    return cur_shared_secrat

    



def extract_group_key(server):
    request, request_id, packet_amount, packet_number, flag = buffer_extractor(server.recv(HEADER_SIZE))
    content = server.recv(CONTENT_SIZE)
    while packet_number + 1 < packet_amount:
        request, request_id, packet_amount, packet_number, flag = buffer_extractor(server.recv(HEADER_SIZE))
    return content[0], bytes_to_int(content[1:])
    
def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')
    
def bytes_to_int(xbytes: bytes) -> int:
    return int.from_bytes(xbytes, 'big')
    
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

def does_user_exist(packet):
    request, request_id, packet_amount, packet_number, flag = buffer_extractor(packet[:HEADER_SIZE])
    
    #packet validity
    if packet_number >= packet_amount:
        raise Exception("this packets are invalid")

    if request == USERNAME_DOESNT_EXIST:
        return False
    elif request == CLIENT_KEYS:
        return True
    else:
        raise Exception("this packet is not a valid type, please chack the server side for bugs")

def can_enter_chat(packet):
    request, request_id, packet_amount, packet_number, flag = buffer_extractor(packet[:HEADER_SIZE])
    
    #packet validity
    if packet_number >= packet_amount:
        raise Exception("this packets are invalid")

    if request == JOIN_CHAT:
        return False
    elif request == CANT_JOIN_CHAT:
        return True
    else:
        raise Exception("this packet is not a valid type, please chack the server side for bugs")
