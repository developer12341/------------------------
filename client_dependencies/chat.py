import tkinter,threading
import socket,time, pyDH, hashlib
from ganeral_dependencies import pac_comp,protocols,AES_crypto
from ganeral_dependencies.global_values import *
from ganeral_dependencies.AES_crypto import decrypt
from Crypto.PublicKey import RSA
from tkinter.filedialog import askopenfilename
import os
class process_packets(threading.Thread):
    def __init__(self,server,user_values,parameters = None):
        self.request_queue = []
        self.server = server
        self.user_values = user_values
        self.parameters = parameters
        threading.Thread.__init__(self)

    def hash_key(self, key):
        return hashlib.sha256(key).hexdigest().encode("utf-8")

    def run(self):
        while self.user_values.pincode:
            if self.request_queue:
                if self.request_queue[0][0] == GET_GROUP_KEY:
                    client_public_key = RSA.import_key(self.request_queue[0][1].strip(b"\x00"))
                    content = AES_crypto.rsa_encrypt(self.user_values.rsa_group_key.export_key(),client_public_key)
                    content += b"end_private_key"
                    encrypted_group_key = pac_comp.int_to_bytes(pow(pac_comp.bytes_to_int(self.user_values.group_key),self.user_values.rsa_group_key.e,self.user_values.rsa_group_key.n))
                    content += encrypted_group_key
                    packets = protocols.Packet_Maker(SEND_GROUP_KEYS,content=content)
                    for packet in packets:
                        self.server.send(packet)
                    print("group_key: " + str(self.user_values.group_key))
                    print("sending user data")
                    del self.request_queue[0]

                elif self.request_queue[0][0] in [SEND_FILE, SEND_IMG]:
                    file_content = pac_comp.decrypt(self.request_queue[0][1][1],self.user_values.group_key)
                    file_name = pac_comp.decrypt(self.request_queue[0][1][0],self.user_values.group_key)
                    with open(".\\files\\" + file_name,"wb") as file_:
                        file_.write(file_content)
                    del self.request_queue[0]
            time.sleep(0.05)
    def add_request(self, request):
        self.request_queue.append(request)


def create_frame(root,chat_frame,chat_picker_frame,user_values,server,key):
    clickable_links = {}
    def group_info():
        pass

    def on_raise(parameters = None):
        root.title(f"sendme - {user_values.pincode}")
        
        msg = (f"{user_values.username} has entered the chat").encode("utf-8")
        list_box.insert(tkinter.END,msg)
        user_values.process_thread = process_packets(server,user_values)
        user_values.process_thread.start()
        chat_frame.after(100,msg_listener)
        if user_values.group_key:
            packets = protocols.Packet_Maker(SEND_MSG,shared_secrete=user_values.group_key,content=msg)
            for packet in packets:
                server.send(packet)

    def leave_group():
        user_values.pincode = None

    def on_send(*args):
        msg = f"<{user_values.username}>:" + chat_entry.get()
        
        list_box.insert(tkinter.END,msg)
        packets = protocols.Packet_Maker(SEND_MSG,shared_secrete=user_values.group_key,content=msg.encode("utf-8"))
        for packet in packets:
            server.send(packet)
        chat_entry.delete(0,"end")
        
        
    def on_send_file():
        # if not loop.img_send_stop:
        filepath = askopenfilename()
        if filepath:
            # chat_entry.grid_forget()
            # progress.grid(row=1,column=0,sticky="NWES")
            # loop.img_send_stop = True
            packets = protocols.Packet_Maker(SEND_IMG,content=user_values.username.encode("utf-8"),shared_secrete=user_values.group_key,file_path=filepath)
            for packet in packets:
                server.send(packet)
            
    
    def select_from_list_box(event):
        pass
        # curser = list_box.curselection()
        # # Updating label text to selected option
        # value = list_box.get(curser)
        # print(value)
        # if value.find(" sent a file") != -1:
        #     username = value[:value.find(" sent a file")]
        #     clickable_links[user_values]

    def msg_listener(*args):
        if user_values.pincode:
            server.settimeout(0.001)
            try:
                packet = server.recv(PACKET_SIZE)
                server.settimeout(None)
                msg_queue = []
                request, request_id, packet_amount, packet_number, flag = pac_comp.buffer_extractor(packet[:HEADER_SIZE])
                msg_queue.append(packet)
                server.settimeout(0.001)
                if packet_amount - packet_number > 1:
                    for _ in range(packet_amount-1):
                        packet = server.recv(PACKET_SIZE)
                        msg_queue.append(packet)
                server.settimeout(None)

                if request == SEND_MSG:
                    msg = b''
                    for packet in msg_queue:
                        msg += packet[HEADER_SIZE:]
                    msg = decrypt(msg, user_values.group_key)
                    list_box.insert(tkinter.END,msg)
                elif request in [SEND_FILE, SEND_IMG]:
                    username = b''
                    file_name = b''
                    file_content = b''
                    for packet in msg_queue:
                        request, request_id, packet_amount, packet_number, flag = pac_comp.buffer_extractor(packet[:HEADER_SIZE])
                        if flag == FILE_NAME_PACKET:
                            file_name += packet[HEADER_SIZE:]
                        elif flag == CONTENT_PACKET:
                            file_content += packet[HEADER_SIZE:]
                        elif flag == USERNAME_PACKET:
                            username += packet[HEADER_SIZE:]
                    print("username: " + str(username))
                    print("file_contnet: " + str(file_content))
                    print("file_name: " + str(file_name))
                    user_values.process_thread.add_request([request,[file_name,file_content]])
                    username = decrypt(username,user_values.group_key)
                    list_box.insert(tkinter.END,username.decode("utf-8") + " sent a file")
                    file_path = os.getcwd() + "\\files"
                    clickable_links[username.decode("utf-8")] = file_path

                else:
                    msg = b''
                    for packet in msg_queue:
                        msg += packet[HEADER_SIZE:]
                    user_values.process_thread.add_request([request,msg])
            except socket.timeout:
                server.settimeout(None)
            finally:
                chat_frame.after(300,msg_listener)
        

    # menubar = tkinter.Menu(chat_frame)
    # filemenu = tkinter.Menu(menubar, tearoff=0)
    # filemenu.add_command(label="grope info", command=group_info)
    # filemenu.add_separator()
    # filemenu.add_command(label="leave grope", command=leave_group)
    # menubar.add_cascade(label="options", menu=filemenu)


    # chat_frame.config(menu=menubar)
    user_values.on_chat_raise = on_raise
    chat_frame.grid_rowconfigure(0,weight=1)
    chat_frame.grid_columnconfigure(0,weight=9999)
    chat_frame.grid_columnconfigure(1,weight=1)
    chat_frame.grid_columnconfigure(2,weight=1)

    scrollbar = tkinter.Scrollbar(chat_frame)
    scrollbar.grid(row=0,column=3,sticky="NSWE",padx=(0,0))
    
    list_box = tkinter.Listbox(chat_frame,yscrollcommand = scrollbar.set)
    list_box.grid(row=0,column=0,columnspan=3,sticky="NWES")

    list_box.bind('<Double-1>', select_from_list_box)
    scrollbar.config(command = list_box.yview)


    chat_entry = tkinter.Entry(chat_frame,font="arial 14")
    chat_entry.grid(row=1,column=0,sticky="NWES")
    chat_entry.bind("<Return>",on_send)

    tkinter.Button(chat_frame,text="+",font="arial 14",command=on_send_file).grid(row=1,column=1,sticky="NWES")

    tkinter.Button(chat_frame,text="send",font="arial 14",command=on_send).grid(row=1,column=2,columnspan=2,sticky="NWES")
    
if __name__ == "__main__":
    root = tkinter.Tk()
    create_frame(root,None,None,None,None,None)
    root.mainloop()

