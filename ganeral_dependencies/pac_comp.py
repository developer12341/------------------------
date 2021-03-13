import struct
from ganeral_dependencies.global_values import *

def bytes_to_int(byte):
    number = 0
    for i in range(1,len(byte)+1):
        number += byte[-i]*i
    return number
        
def buffer_extractor(buffer):
    request, request_id, packet_amount, packet_number, flag = struct.unpack("1s 8s 3s 3s 1s", buffer)
    return request, request_id, bytes_to_int(packet_amount) , bytes_to_int(packet_number) , flag

def is_logged_in(packet):
    request, request_id, packet_amount, packet_number, flag = buffer_extractor(packet[:HEADER_SIZE])
    
    #packet validity
    if packet_number >= packet_amount:
        raise Exception("this packets are invalid")
    

    if request == REG_LOGIN_SUC:
        if flag != R_L_SUC:
            #packet validity
            raise Exception("this packet's request doesn't match the flag \n request == REG_LOGIN_SUC\n flag != R_L_SUC")
        return True
    elif request == REG_LOGIN_FAIL:
        if flag != R_L_FAIL:
            #packet validity
            raise Exception("this packet's request doesn't match the flag \n request == REG_LOGIN_FAIL\n flag != R_L_FAIL")
        return False
    else:
        #packet validity
        raise Exception("this packet isn't REG_LOGIN type, please chack the server side for bugs")
