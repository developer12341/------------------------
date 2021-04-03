import struct,hashlib
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

    
def hash_key(key):
    return hashlib.sha256(int_to_bytes(key)).hexdigest().encode("utf-8")

def get_server_response(server):
    packet = server.recv(PACKET_SIZE)
    content = b''
    request, request_id, packet_amount, packet_number, flag = buffer_extractor(packet[:HEADER_SIZE])
    content += packet[HEADER_SIZE:]
    if packet_amount > 1:
        for _ in range(packet_amount-1):
            packet = server.recv(PACKET_SIZE)
            content += packet[HEADER_SIZE:]
    return request, content.strip(b'\x00')
    
def key_exchange(server,parameters):
    request, public_key = recive_public_key(server)
    while request == GET_GROUP_KEY:
        print("public key: " + str(public_key))
        try:
            public_key_int = bytes_to_int(public_key[1:])
            content = int_to_bytes(public_key[0]) + int_to_bytes(parameters.gen_shared_key(public_key_int))
            packets = Packet_Maker(SEND_GROUP_KEYS,content=content)
            for packet in packets:
                server.send(packet)
            request, public_key = recive_public_key(server)
        except Exception as e:
            print("public key: " + str(public_key))
            raise e
        
    if request == END_SETTION:
        public_key = bytes_to_int(public_key.strip(b'\x00'))
        group_key = hash_key(parameters.gen_shared_key(public_key))
        print("group_key: " + str(group_key))
        return group_key

        


    


def extract_group_key(server):
    request, request_id, packet_amount, packet_number, flag = buffer_extractor(server.recv(HEADER_SIZE))
    while packet_number + 1 < packet_amount:
        print("hello")
        content = server.recv(CONTENT_SIZE)
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
        return request, True
    elif request in [REG_LOGIN_FAIL,USER_LOGGED_IN]:
        if flag != SOMETHING_ELSE:
            #packet validity
            raise Exception("this packet's request doesn't match the flag \n request == REG_LOGIN_FAIL\n flag != R_L_FAIL")
        return request, False
    else:
        #packet validity
        raise Exception("this packet isn't REG_LOGIN type, please chack the server side for bugs")

def can_auth_email(packet):
    request, request_id, packet_amount, packet_number, flag = buffer_extractor(packet[:HEADER_SIZE])
    
    #packet validity
    if packet_number >= packet_amount:
        raise Exception("this packets are invalid")
    

    if request in [REG_LOGIN_FAIL,USERNAME_TAKEN,REG_LOGIN_SUC,AUTHENTICAT_EMAIL,EMAIL_DOSENT_EXIST,EMAIL_TAKEN]:
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
        print("packet_number: " + str(packet_number))
        print("packet_amount: " + str(packet_amount))
        raise Exception("this packets are invalid")

    if request == SEND_GROUP_KEYS:
        return True
    elif request == CANT_JOIN_CHAT:
        return False
    else:
        raise Exception("this packet is not a valid type, please chack the server side for bugs")
