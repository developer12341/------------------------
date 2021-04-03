from ganeral_dependencies.AES_crypto import decrypt
from ganeral_dependencies.global_functions import buffer_extractor
from ganeral_dependencies.global_values import *


def get_server_response(server):
    packet = server.recv(PACKET_SIZE)
    content = b''
    request, request_id, packet_amount, packet_number, flag = buffer_extractor(packet[:HEADER_SIZE])
    content += packet[HEADER_SIZE:]
    if packet_amount > 1:
        for _ in range(packet_amount - 1):
            packet = server.recv(PACKET_SIZE)
            content += packet[HEADER_SIZE:]
    return request, content.strip(b'\x00')


def extract_chat_id(packet, private_key):
    # request, request_id, packet_amount, packet_number, flag = buffer_extractor(packet[:HEADER_SIZE])
    chat_id = packet[HEADER_SIZE:].strip(b'\x00')
    chat_id = decrypt(chat_id, private_key)
    return chat_id


def is_logged_in(packet):
    request, request_id, packet_amount, packet_number, flag = buffer_extractor(packet[:HEADER_SIZE])

    # packet validity
    if packet_number >= packet_amount:
        raise Exception("this packets are invalid")

    if request == REG_LOGIN_SUC:
        if flag != SOMETHING_ELSE:
            # packet validity
            raise Exception(
                "this packet's request doesn't match the flag \n request == REG_LOGIN_SUC\n flag != R_L_SUC")
        return request, True
    elif request in [REG_LOGIN_FAIL, USER_LOGGED_IN]:
        if flag != SOMETHING_ELSE:
            # packet validity
            raise Exception(
                "this packet's request doesn't match the flag \n request == REG_LOGIN_FAIL\n flag != R_L_FAIL")
        return request, False
    else:
        # packet validity
        raise Exception("this packet isn't REG_LOGIN type, please check the server side for bugs")


def can_auth_email(packet):
    request, request_id, packet_amount, packet_number, flag = buffer_extractor(packet[:HEADER_SIZE])

    # packet validity
    if packet_number >= packet_amount:
        raise Exception("this packets are invalid")

    if request in [REG_LOGIN_FAIL, USERNAME_TAKEN, REG_LOGIN_SUC, AUTHENTICATE_EMAIL, EMAIL_DOESNT_EXIST, EMAIL_TAKEN]:
        if flag != SOMETHING_ELSE:
            # packet validity
            raise Exception(
                "this packet's request doesn't match the flag \n request == REG_LOGIN_SUC\n flag != R_L_SUC")
        return request == AUTHENTICATE_EMAIL, request
    else:
        # packet validity
        raise Exception("this packet isn't REG_LOGIN type, please check the server side for bugs")


def does_user_exist(packet):
    request, request_id, packet_amount, packet_number, flag = buffer_extractor(packet[:HEADER_SIZE])

    # packet validity
    if packet_number >= packet_amount:
        raise Exception("this packets are invalid")

    if request == USERNAME_DOESNT_EXIST:
        return False
    elif request == CLIENT_KEYS:
        return True
    else:
        raise Exception("this packet is not a valid type, please check the server side for bugs")


def can_enter_chat(packet):
    request, request_id, packet_amount, packet_number, flag = buffer_extractor(packet[:HEADER_SIZE])

    # packet validity
    if packet_number >= packet_amount:
        print("packet_number: " + str(packet_number))
        print("packet_amount: " + str(packet_amount))
        raise Exception("this packets are invalid")

    if request == SEND_GROUP_KEYS:
        return True
    elif request == CANT_JOIN_CHAT:
        return False
    else:
        raise Exception("this packet is not a valid type, please check the server side for bugs")
