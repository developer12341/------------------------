import socket, tkinter, threading
from tkinter import ttk
from global_values import *
from ganeral_dependencies import packets_maker
from ganeral_dependencies import pac_comp
from ganeral_dependencies.global_values import *

class notifications_socket(threading.Thread):

    def __init__(self):
        self.notifications_pending = []
        self.incoming_notifications = []
        threading.Thread.__init__(self)
        self.keep_runing = threading.Event()
        self.keep_runing.set()
        
    def run(self):
        server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

        server.connect((IP,NOTIFICATION_PORT))

        while self.keep_runing.is_set():
            server.settimeout(10)
            try:
                notification = server.recv(PACKET_SIZE)
            except socket.timeout: # fail after 1 second of no activity
                pass
            server.settimeout(None)
            self.incoming_notifications.append(notification)




def create_frame(chat_picker_frame,user_values,server,public_key,private_key):

    def decrypt(msg):
        pass

    def fatch_data():
        pass

    def send_friend_req(*args):
        friend_name = friend_name_entry.get()
        content = friend_name.encode("ascii") + bytes(USERNAME_MAX_LEN-len(friend_name))
        content += user_values.username.encode("ascii") + bytes(USERNAME_MAX_LEN - len(user_values.username.encode("ascii")))
        packets = packets_maker.Packet_Maker(SEND_FRIEND_REQ,public_key, content=content)
        server.send(next(packets))
        server_response = server.recv(PACKET_SIZE)
        if pac_comp.does_user_exist(server_response):
            keys = server_response[HEADER_SIZE:].strip(b'\x00')
            keys = decrypt(keys)
            with open(f".\\client_dependencies\\chats\\{friend} keys.bin",wb) as f:
                f.write(keys)
            

        
    def notification_listener(*args):
        if notification_obj.incoming_notifications:
            print(notification_obj.incoming_notifications[0])
            del notification_obj.incoming_notifications[0]

        chat_picker_frame.after(100,notification_listener)

        
    def create_grope(*args):
        pass
    
    
    def update_list(*args):
        search_term = search_var.get()

        lbox.delete(0, END)
        lbox_list = []

        for item in lbox_list:
            if search_term.lower() in item.lower():
                lbox.insert(END, item)


    def OnSelect(event):
        widget = event.widget
        value = widget.get(widget.curselection()[0])
        print(value)


    menubar = tkinter.Menu(chat_picker_frame,bg= "grey")
    window.config(menu=menubar)
    filemenu = tkinter.Menu(menubar, tearoff=0)
    filemenu.add_command(label="a")
    filemenu.add_separator()
    filemenu.add_command(label="b")
    menubar.add_cascade(label="options", menu=filemenu)

    chat_picker_frame.grid_rowconfigure(1,weight=1)
    chat_picker_frame.grid_columnconfigure(0,weight=1)

    main_frame = tkinter.Frame(chat_picker_frame, bg="white")
    main_frame.grid(row=0,column=0,rowspan=2,sticky= "NWES")
    main_frame.grid_columnconfigure(0,weight=1)
    main_frame.grid_rowconfigure(1,weight=1)
    main_frame.grid_rowconfigure(3,weight=1)
    tkinter.Label(main_frame,text=f"hello there!",font="arial 23").grid(row=0,column=0,sticky="NWE",pady=20)

    tkinter.Label(main_frame,text="want to start a chat with someone?",font=15).grid(row=1,column=0,sticky="S")

    friend_name_entry = tkinter.Entry(main_frame, font=15)
    friend_name_entry.insert(tkinter.END, "enter their username")
    friend_name_entry.grid(row=2,column=0,pady=20)

    tkinter.Button(main_frame,text="send friend request",font=15,command= send_friend_req).grid(row=3,column=0,sticky="N")


    search_var = tkinter.StringVar()
    search_var.trace("w", update_list)
    search_entry = tkinter.Entry(chat_picker_frame,textvariable=search_var)
    search_entry.grid(row=0,column=1,sticky="WNES")
    list_box = tkinter.Listbox(chat_picker_frame,selectbackground="black",selectmode= tkinter.SINGLE,font=15)
    list_box.insert(1, "chats")
    list_box.grid(row=1,column=1,rowspan=20,sticky="WNES")
    list_box.configure(justify=tkinter.CENTER)

    chat_picker_frame.after(100,notification_listener)
    notification_obj = notifications_socket()
    notification_obj.start()
    list_box.bind("<Double-Button-1>", OnSelect)


if __name__ == "__main__":
    window = tkinter.Tk()
    window.configure(background='SystemButtonFace')
    create_frame(window,None,None,None,None)
    window.mainloop()