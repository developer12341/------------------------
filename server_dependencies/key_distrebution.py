import threading,time
from ganeral_dependencies.protocols import Packet_Maker
from ganeral_dependencies.global_values import *
class key_distribution(threading.Thread):
    def __init__(self,client_list,chatid_pubkey,chatId):
        #{chatId:none or {[1, client, client, client]:group_pub_key,...}...} 
        #for the group_dh_key_excange
        #the client on the list are the client that havent recived this key
        self.chatid_pubkey = chatid_pubkey
        self.client_list =client_list
        self.chat_id = chatId
        key_index = 1
        for client in chatid_pubkey[chatId]:
            currnt_list = client_list.copy()
            del currnt_list[currnt_list.index(client)]
            currnt_list.insert(key_index)
            chatid_pubkey[chatId][currnt_list]
            key_index += 1
    
    def int_to_bytes(self, x: int) -> bytes:
        return x.to_bytes((x.bit_length() + 7) // 8, 'big')

    def run(self):
        for _ in range(len(self.client_list)- 1 ):
            for clients, key in self.chatid_pubkey[self.chat_id].items():
                if len(clients) != 2:
                    content = bytes([clients[0]]) + self.int_to_bytes(key)
                    packets = Packet_Maker(GET_GROUP_KEY,content = content)
                    for packet in packets:
                        clients[1].send(packet)
                    del clients[1]
                    time.sleep(1)
                else:
                    content = bytes([clients[0]]) + self.int_to_bytes(key)
                    packets = Packet_Maker(END_SETTION,content=content)
                    for client in self.client_list:
                        for packet in packets:
                            client.send(packet)
        
                    
