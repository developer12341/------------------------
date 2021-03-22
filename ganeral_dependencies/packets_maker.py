import uuid, math, time
from ganeral_dependencies.global_values import *
# import RSA_crypt
import ntpath
def extract_file_name(path):
    head, tail = ntpath.split(path)
    return tail or ntpath.basename(head)

class Packet_Maker:

    def __init__(self, request, public_key, content = None, file_path = None):
        """
            prepering the packets for constraction and the header
        """
        self.e,self.N = public_key
        self.amount_info_packets = 0
        self.amount_content_packets = 0
        self.content = content
        self.file_path = file_path
        if request == SEND_FILE:
            #edge case - sending file without a name or a type
            if not file_path:
                raise Exception("you must have a file path to send a file!")
            

            #encrypt the file name and file itself
            self.file_name = self.encrypt(extract_file_name(file_path))
            with open(file_path,"rb") as f:
                self.content = f.read()
            # self.content = self.encrypt(content)

            self.amount_info_packets += (len(self.file_name)//CONTENT_SIZE) + 1


        elif request == SEND_IMG:
            #displaying a suggestion
            if content:
                raise Warning("you don't need to enter content when sending an image")
            
            import PIL
            from PIL import Image
            import io
            
            #commpressing a file
            img = Image.open(file_path)

            new_size = map(lambda x: int(IMG_SIZE_FAC*x), img.size)
            img = img.resize(new_size, PIL.Image.ANTIALIAS)
            buffer= io.BytesIO()
            file_name = extract_file_name(file_path)
            file_format = file_name.split('.')[-1]
            img.save(buffer, format=file_format)

            #encrypt the content of the image and the file name
            self.content = buffer.getvalue()
            # self.content = self.encrypt(self.content)
            self.file_name = self.encrypt(file_name.encode("Ascii"))

            self.amount_info_packets += (len(self.file_name)//CONTENT_SIZE) + 1

        elif request in [REG_LOGIN_FAIL,USERNAME_TAKEN,REG_LOGIN_SUC,AUTHENTICAT_EMAIL,EMAIL_DOSENT_EXIST,CREATE_CHAT]:
            self.amount_info_packets += 1
        
        elif request in [SEND_MSG, LOGIN, REGISTER, SEND_PINCODE]:
            pass

        if self.content:
            self.content = self.encrypt(content)
            self.amount_content_packets = (len(self.content)//CONTENT_SIZE) + 1

        packet_id = uuid.uuid4().bytes[:8]

        self.amount_of_packets = self.amount_content_packets + self.amount_info_packets

        

        #edge case - there are too many packets
        if self.amount_of_packets > 16777216:
            raise Exception(f"the content is too big :( \namount of packets = {self.amount_of_packets}")
        
        #this part is in every packet so i am making it hear
        self.packet_index = 0
        self.amount_of_packets += self.packet_index
        self.header = request + packet_id 
        self.header += self.amount_of_packets.to_bytes(3,"big")

    def encrypt(self,msg):
        """
            encrypt every massege with the following formula
            (msg)^e % N = c 
        """
        cipher = map(lambda num: pow(num, self.e, self.N).__str__(), msg)
        cipher = ' '.join(cipher).encode("ascii")
        return cipher

    def __iter__(self):
        return self

    def __len__(self):
        return self.amount_of_packets - self.packet_index

    def __next__(self):
        if self.packet_index >= self.amount_of_packets:
            raise StopIteration

        packet = self.header
        packet += self.packet_index.to_bytes(3,"big")
        if self.packet_index < self.amount_info_packets:
            if self.file_path:
                packet += FILE_NAME_PACKET
                
                if len(self.file_name) > CONTENT_SIZE:
                    packet += self.file_name[self.packet_index*CONTENT_SIZE:(self.packet_index + 1)*CONTENT_SIZE]
                else:
                    packet += self.file_name[self.packet_index*CONTENT_SIZE:]
            else:
                packet += SOMETHING_ELSE
        else:
            packet += CONTENT_PACKET
            if self.content:
                packet += self.content[self.packet_index*CONTENT_SIZE:(self.packet_index + 1)*CONTENT_SIZE]

        self.packet_index += 1
        return packet + bytes(PACKET_SIZE-len(packet))
            
