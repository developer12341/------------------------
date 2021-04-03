import threading,time,socket
from ganeral_dependencies.protocols import Packet_Maker
from ganeral_dependencies.global_values import *
class key_distribution(threading.Thread):
    def __init__(self,client_list,chatid_pubkey,chat_id):
        self.client_list = client_list
        self.key_index = 1
        self.chat_id = chat_id
        self.chatid_pubkey = chatid_pubkey
        for client in client_list:
            send_to = self.normlize(client_list.index(client)+1)
            chatid_pubkey[chat_id][send_to] = chatid_pubkey[chat_id][client]
        
        for client in client_list:
            del chatid_pubkey[chat_id][client]
        time.sleep(0.5)





        # #{chat_id:none or {[1, client, client, client]:group_pub_key,...}...} 
        # #for the group_dh_key_excange
        # #the client on the list are the client that havent recived this key
        # self.chatid_pubkey = chatid_pubkey
        # self.client_list =client_list
        # self.chat_id = chat_id
        # self.key_index = 1
        # self.client_lists = []
        # for client in client_list:
        #     currnt_list = client_list.copy()
        #     del currnt_list[currnt_list.index(client)]
        #     currnt_list.insert(0,self.key_index)
        #     self.client_lists.append(currnt_list)
        #     chatid_pubkey[chat_id][self.key_index] = chatid_pubkey[chat_id][client]
        #     self.key_index += 1
        # for client in client_list:
        #     del chatid_pubkey[chat_id][client]
        # print(len(chatid_pubkey[chat_id]))
        # print(self.client_lists)
        threading.Thread.__init__(self)

    def normlize(self,number):
        return number%len(self.client_list)

    def int_to_bytes(self, x: int) -> bytes:
        return x.to_bytes((x.bit_length() + 7) // 8, 'big')

    def run(self):
        for number_of_runs in range(len(self.client_list)-1):
            for send_to in range(len(self.client_list)):
                print(f"number_of_runs{number_of_runs}       send_to{send_to}" + str(self.normlize(number_of_runs +2+ send_to)))
                offset_chack = self.normlize(number_of_runs + send_to+2)
                # send_to = self.normlize(number_of_runs + send_to)
                if send_to != offset_chack:
                    content = bytes([send_to]) + self.chatid_pubkey[self.chat_id][send_to]
                    packets = Packet_Maker(GET_GROUP_KEY,content = content)
                    for packet in packets:
                        self.client_list[send_to].send(packet)
                    time.sleep(1.5)
                else:
                    print(str(self.client_list[send_to]) + "has recived all packets")
                    content = self.chatid_pubkey[self.chat_id][send_to]
                    packets = Packet_Maker(END_SETTION,content = content)
                    for packet in packets:
                        self.client_list[send_to].send(packet)
                  
        del self.chatid_pubkey[self.chat_id]
        print("end key settion")  

        # for _ in range(len(self.client_list)- 1 ):
        #     for dict_key in range(1,self.key_index):
        #         print(self.client_lists)
        #         number_of_sendings_left = 0
        #         for client_list in self.client_lists:
        #             for client in client_list[1:]:
        #                 if client is self.client_lists[dict_key-1][1]:
        #                     number_of_sendings_left += 1
        #         if number_of_sendings_left > 1:
        #             content = bytes([dict_key]) + self.chatid_pubkey[self.chat_id][dict_key]
        #             packets = Packet_Maker(GET_GROUP_KEY,content = content)
        #             for packet in packets:
        #                 self.client_lists[dict_key-1][1].send(packet)
        #             del self.client_lists[dict_key-1][1]
        #             time.sleep(1.4)
        #         else:
        #             print(str(self.client_lists[dict_key-1][1]) + "has recived all packets")
        #             content = self.chatid_pubkey[self.chat_id][dict_key]
        #             packets = Packet_Maker(END_SETTION,content = content)
        #             for packet in packets:
        #                 self.client_lists[dict_key-1][1].send(packet)
        #             del self.client_lists[dict_key-1][1]
        #             # packets = Packet_Maker(END_SETTION,content=key)
        #             # for client in self.client_list:
        #             #     for packet in packets:
        #             #         client.send(packet)
        
        # del self.chatid_pubkey[self.chat_id]
        # print("end key settion")
        