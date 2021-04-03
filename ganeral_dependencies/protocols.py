import json
import uuid
from base64 import b64encode
from typing import Any, Union

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from ganeral_dependencies.global_functions import extract_file_name
from ganeral_dependencies.global_values import *


class PacketMaker:

    def __init__(self, request, shared_secrete=b'', content=None, file_path=None):
        """
            preparing the packets for construction and the header
        """
        self.key = shared_secrete
        self.amount_info_packets = 0
        self.amount_content_packets = 0
        self.content = content
        self.username = None
        self.file_path = file_path
        if request == SEND_FILE:
            # edge case - sending file without a name or a type
            if not file_path:
                raise Exception("you must have a file path to send a file!")

            # encrypt the file name and file itself
            self.username = self.encrypt(content)
            self.e_file_name = self.encrypt(extract_file_name(file_path))
            with open(file_path, "rb") as f:
                self.content = f.read()
            # self.content = self.encrypt(content)
            print("self.e_file_name: " + self.e_file_name)
            self.amount_info_packets += (len(self.e_file_name) // CONTENT_SIZE) + 1
            self.amount_info_packets += (len(self.username) // CONTENT_SIZE) + 1

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
            self.username = self.encrypt(content)
            self.content = buffer.getvalue()

            # self.content = self.encrypt(self.content)
            self.e_file_name = self.encrypt(file_name.encode("utf-8"))

            self.amount_info_packets += (len(self.e_file_name) // CONTENT_SIZE) + 1
            self.amount_info_packets += (len(self.username) // CONTENT_SIZE) + 1

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
        packet_id = uuid.uuid4().bytes[:8]

        self.amount_of_packets = self.amount_content_packets + self.amount_info_packets

        # edge case - there are too many packets
        if self.amount_of_packets > 16777216:
            raise Exception(f"the content is too big :( \namount of packets = {self.amount_of_packets}")

        # this part is in every packet so i am making it hear
        self.packet_index = 0
        self.amount_of_packets += self.packet_index
        self.header = request + packet_id
        self.header += self.amount_of_packets.to_bytes(3, "big")

    def encrypt(self, data):
        if self.key:
            header = get_random_bytes(8)
            nonce = get_random_bytes(16)
            # print(self.key)
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

        packet: Union[bytes, Any] = self.header
        packet += self.packet_index.to_bytes(3, "big")
        if self.packet_index < self.amount_info_packets:
            if self.username:
                packet += USERNAME_PACKET
                print("USERNAME_PACKET")
                if len(self.username) > CONTENT_SIZE:
                    packet += self.username[:CONTENT_SIZE]
                    self.username = self.username[CONTENT_SIZE:]
                else:
                    packet += self.username
                    self.username = None
            elif self.file_path:
                print("file_name packets")

                packet += FILE_NAME_PACKET

                if len(self.e_file_name) > CONTENT_SIZE:
                    packet += self.e_file_name[self.packet_index * CONTENT_SIZE:(self.packet_index + 1) * CONTENT_SIZE]
                else:
                    packet += self.e_file_name[self.packet_index * CONTENT_SIZE:]
            else:
                packet += SOMETHING_ELSE
        else:
            print("content_packets")

            packet += CONTENT_PACKET
            if self.content:
                packet += self.content[self.packet_index * CONTENT_SIZE:(self.packet_index + 1) * CONTENT_SIZE]

        self.packet_index += 1
        return packet + bytes(PACKET_SIZE - len(packet))
