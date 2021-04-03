import socket, tkinter, threading
from tkinter import ttk
from ganeral_dependencies import protocols, AES_crypto
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from ganeral_dependencies import pac_comp
import pyDH
from ganeral_dependencies.global_values import *
from tkinter import messagebox
from ganeral_dependencies.pac_comp import get_server_response
def create_frame(chat_picker_frame,chat_frame,user_values,server,key):
    
    def join_chat(*args):
        pincode = pin_entry.get()
        if not pincode:
            return
        rsa_key = RSA.generate(2048)
        content = pincode.encode("utf-8") + b"pin_code_end" + rsa_key.public_key().export_key("PEM")
        packets = protocols.Packet_Maker(JOIN_CHAT,shared_secrete=key, content=content)
        for packet in packets:
            # print(packet)
            server.send(packet)
            
        request, server_response = get_server_response(server)
        if request == SEND_GROUP_KEYS:
            # messagebox.showinfo("joining chat", "please wait while we encrypt your comunication line")
            user_values.pincode = pincode
            # print("full msg: " + str(server_response))
            group_private_key, group_dh_key = server_response.strip(b'\x00').split(b"end_private_key")
            user_values.rsa_group_key = AES_crypto.rsa_decrypt(group_private_key,rsa_key)
            group_private_key = RSA.import_key(user_values.rsa_group_key)
            group_dh_key = pow(pac_comp.bytes_to_int(group_dh_key),group_private_key.d,group_private_key.n)
            user_values.group_key = pac_comp.int_to_bytes(group_dh_key)
            print(user_values.group_key)
            # key_index, group_key = pac_comp.extract_group_key(server)
            # shared_key = pac_comp.int_to_bytes(parameters.gen_shared_key(group_key))
            # content = key_index + shared_key
            # packets = protocols.Packet_Maker(GET_GROUP_KEY,content=content)
            # for packet in packets:
            #     server.send(packet)
            # user_values.group_key =  pac_comp.get_shared_secret()
            
            chat_frame.tkraise()
            user_values.on_chat_raise()
        else:
            print("error")

    def open_new_chat():
        packets = protocols.Packet_Maker(CREATE_CHAT)
        for packet in packets:
            server.send(packet)
        server_response = server.recv(PACKET_SIZE)
        user_values.pincode = pac_comp.decrypt(server_response[HEADER_SIZE:].strip(b'\x00'),key).decode("utf-8")
        user_values.group_key = get_random_bytes(32)
        user_values.rsa_group_key = RSA.generate(2048)
        print(user_values.pincode)
        chat_frame.tkraise()
        user_values.on_chat_raise()

    # tkinter.Label(chat_picker_frame,text=f"hello {user_values.username}!",font="arial 23").grid(row=0,column=0,columnspan=3,sticky="NWE")

    chat_picker_frame.grid_columnconfigure(0,weight=1)
    chat_picker_frame.grid_columnconfigure(2,weight=1)
    chat_picker_frame.grid_rowconfigure(1,weight=1)
    chat_picker_frame.grid_rowconfigure(3,weight=3)

    tkinter.Label(chat_picker_frame,text="want to join a group chat?\nenter pin code",font=15).grid(row=1,column=0,sticky="S")

    pin_entry = tkinter.Entry(chat_picker_frame,font=15)
    pin_entry.grid(row=2,column=0,pady=20)

    tkinter.Button(chat_picker_frame,text="join chat",font=15,command= join_chat).grid(row=3,column=0,sticky="N")

    ttk.Separator(chat_picker_frame,orient='vertical').grid(row=1,column=1,rowspan=4,sticky="NEWS",pady=10)

    tkinter.Label(chat_picker_frame,text="start a new chat!",font=15).grid(row=1,column=2,sticky="S")
    tkinter.Button(chat_picker_frame,text="start new chat",font=15,command=open_new_chat).grid(row=2,column=2,sticky="N",pady=20)
    
if __name__ == "__main__":
    root = tkinter.Tk()
    create_frame(root,None,None,None,None,None)
    root.mainloop()