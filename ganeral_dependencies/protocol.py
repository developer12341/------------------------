import json
import os
import uuid
from base64 import b64encode
from tkinter.filedialog import askopenfilename
from typing import Any, Union

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from ganeral_dependencies import protocol_digest
from ganeral_dependencies.AES_crypto import decrypt
from ganeral_dependencies.global_functions import extract_file_name
from ganeral_dependencies.global_values import *


class PacketMaker:
    amount_info_packets: int

    def __init__(self, request, shared_secret=b'', content=None, file_path=None, username=None):
        """
            preparing the packets for construction and the header
        """
        self.key = shared_secret
        self.amount_info_packets = 0
        self.amount_content_packets = 0
        self.content = content
        self.username = username
        self.file_path = file_path
        self.amount_username_packets = 0
        if request == SEND_FILE:
            # edge case - sending file without a name or a type
            if not file_path:
                raise Exception("you must have a file path to send a file!")

            # encrypt the file name and file itself
            self.e_file_name = self.encrypt(extract_file_name(file_path).encode("utf-8"))
            with open(file_path, "rb") as f:
                self.content = f.read()
            # self.content = self.encrypt(content)
            self.amount_info_packets += (len(self.e_file_name) // CONTENT_SIZE) + 1

        elif request == SEND_IMG:
            # #displaying a suggestion
            # if content:
            #     raise Warning("you don't need to enter content when sending an image")

            import PIL
            from PIL import Image
            import io

            # compressing a file
            img = Image.open(file_path)

            new_size = map(lambda x: int(IMG_SIZE_FAC * x), img.size)
            img = img.resize(new_size, PIL.Image.ANTIALIAS)
            buffer = io.BytesIO()
            file_name = extract_file_name(file_path)
            file_format = file_name.split('.')[-1]
            img.save(buffer, format=file_format)

            # encrypt the content of the image and the file name
            self.content = buffer.getvalue()

            # self.content = self.encrypt(self.content)
            self.e_file_name = self.encrypt(file_name.encode("utf-8"))

            self.amount_info_packets += (len(self.e_file_name) // CONTENT_SIZE) + 1

        elif request in [REG_LOGIN_FAIL, USERNAME_TAKEN, REG_LOGIN_SUC, AUTHENTICATE_EMAIL, EMAIL_DOESNT_EXIST,
                         CREATE_CHAT]:
            pass

        elif request in [SEND_MSG, LOGIN, REGISTER, SEND_PIN_CODE, JOIN_CHAT]:
            pass

        if self.content:
            self.content = self.encrypt(self.content)
            self.amount_content_packets = (len(self.content) // CONTENT_SIZE) + 1
        else:
            self.amount_info_packets += 1

        if self.username:
            self.username = self.encrypt(self.username)
            self.amount_info_packets += (len(self.username) // CONTENT_SIZE) + 1
            self.amount_username_packets = (len(self.username) // CONTENT_SIZE) + 1

        packet_id = uuid.uuid4().bytes[:8]

        self.amount_of_packets = self.amount_content_packets + self.amount_info_packets

        # this part is in every packet so i am making it hear
        self.packet_index = 0
        self.amount_of_packets += self.packet_index
        self.header = request + packet_id
        self.header += self.amount_of_packets.to_bytes(3, "big")

    def encrypt(self, data):
        if self.key:
            header = get_random_bytes(8)
            nonce = get_random_bytes(16)
            cipher = AES.new(self.key, AES.MODE_SIV, nonce=nonce)
            cipher.update(header)
            ciphertext, tag = cipher.encrypt_and_digest(data)

            json_k = ['nonce', 'header', 'ciphertext', 'tag']
            json_v = [b64encode(x).decode('utf-8') for x in (nonce, header, ciphertext, tag)]
            return json.dumps(dict(zip(json_k, json_v))).encode("utf-8")
        else:
            return data

    def __iter__(self):
        return self

    def __len__(self):
        return self.amount_of_packets - self.packet_index

    def __next__(self):
        if self.packet_index >= self.amount_of_packets:
            raise StopIteration

        container: Union[bytes, Any] = self.header
        container += self.packet_index.to_bytes(3, "big")
        if self.packet_index < self.amount_info_packets:
            if self.username:
                container += USERNAME_PACKET
                if len(self.username) > CONTENT_SIZE:
                    container += self.username[:CONTENT_SIZE]
                    self.username = self.username[CONTENT_SIZE:]
                else:
                    container += self.username
                    self.username = None
            elif self.file_path:
                container += FILE_NAME_PACKET

                if len(self.e_file_name) > CONTENT_SIZE:
                    container += self.e_file_name[(self.packet_index - self.amount_username_packets) * CONTENT_SIZE:((
                                                                                                                                 self.packet_index - self.amount_username_packets) + 1) * CONTENT_SIZE]
                else:
                    container += self.e_file_name[(self.packet_index - self.amount_username_packets) * CONTENT_SIZE:]
            else:
                container += SOMETHING_ELSE
        else:

            container += CONTENT_PACKET
            if self.content:
                container += self.content[(self.packet_index - self.amount_info_packets) * CONTENT_SIZE:((
                                                                                                                     self.packet_index - self.amount_info_packets) + 1) * CONTENT_SIZE]

        self.packet_index += 1

        return container + bytes(PACKET_SIZE - len(container))


if __name__ == "__main__":

    while True:
        group_key = get_random_bytes(32)
        username = "idodon".encode("utf-8")
        filepath = askopenfilename()
        if filepath:
            request = SEND_FILE
            file_format = extract_file_name(filepath).split(".")[-1]
            if file_format.upper() in image_file_formats:
                request = SEND_IMG
            packets = PacketMaker(request, shared_secret=group_key, username=username, file_path=filepath)
            print("starting to send file")
            msg_queue = []
            for packet in packets:
                msg_queue.append(packet)
            print("sending complete")

            username = b''
            file_name = b''
            file_content__ = b''
            for packet in msg_queue:
                request, request_id, packet_amount, packet_number, flag = protocol_digest.buffer_extractor(
                    packet[:HEADER_SIZE])

                if flag == FILE_NAME_PACKET:
                    file_name += packet[HEADER_SIZE:]
                if flag == CONTENT_PACKET:
                    file_content__ += packet[HEADER_SIZE:]
                if flag == USERNAME_PACKET:
                    username += packet[HEADER_SIZE:]
            print("file_content__: " + str(file_content__))
            print("file content len: " + str(len(file_content__)))
            username_ = decrypt(username, group_key)
            print(username_)

            # username_ = decrypt(file_name, group_key)
            # print(username_)
            #
            # username_ = decrypt(file_content__, group_key)
            # print(username_)
