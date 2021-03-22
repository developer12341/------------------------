import tkinter,threading
from ganeral_dependencies import packets_maker
from ganeral_dependencies.global_values import *
from ganeral_dependencies import pac_comp
from cryptography.fernet import Fernet
def create_frame(chat_picker_frame,chat_frame,server,public_key,private_key):

    def join_chat():
        pass
    def open_new_chat():
        packets = packets_maker.Packet_Maker(CREATE_CHAT,public_key)
        server.send(next(packets))
        response = server.recv(PACKET_SIZE)
        chat_id = pac_comp.extract_chat_id(response,private_key)
        chat_frame.tkraise()

    tkinter.Label(chat_picker_frame,text=f"hello there!",font="arial 23").grid(row=0,column=0,columnspan=2,sticky="NWE",pady=20)

    chat_picker_frame.grid_columnconfigure(0,weight=1)
    chat_picker_frame.grid_columnconfigure(1,weight=1)
    chat_picker_frame.grid_rowconfigure(1,weight=1)
    chat_picker_frame.grid_rowconfigure(3,weight=3)
    chat_picker_frame.grid_rowconfigure(5,weight=1)

    tkinter.Label(chat_picker_frame,text="want to join a group chat?\nenter pin code",font=15).grid(row=1,column=0,sticky="S")

    pin_entry = tkinter.Entry(chat_picker_frame,font=15)
    pin_entry.grid(row=2,column=0,pady=20)

    tkinter.Button(chat_picker_frame,text="join chat",font=15,command= join_chat).grid(row=3,column=0,sticky="N")


    tkinter.Label(chat_picker_frame,text="start a new chat!",font=15).grid(row=1,column=1,sticky="S")
    tkinter.Button(chat_picker_frame,text="start new chat",font=15,command=open_new_chat).grid(row=2,column=1,sticky="N",pady=20)


# def main(self):
#     def close():
#         self.close_protocol = True
#         threading._start_new_thread(chat_picker_frame.destroy,tuple())

#     def join_chat():
#         self.send_obj.insert("join chat")
#         self.send_obj.insert(pin_entry.get())
#         msg = self.recv_obj.get_item()
#         if(msg == "good to go"):
#             self.chat_pin = pin_entry.get()
#             self.cur_window = "chat"
#             chat_picker_frame.destroy()
#         else:
#             tkinter.Label(chat_picker_frame,text=msg,fg="red").grid(row=4,column=0,columnspan=2,sticky="WENS")


#     def open_new_chat():
#         self.send_obj.insert("create new chat")
#         self.chat_pin = self.recv_obj.get_item()
#         self.cur_window = "chat"
#         chat_picker_frame.destroy()
        

#     chat_picker_frame = tkinter.Tk()
#     chat_picker_frame.geometry("400x400")
#     chat_picker_frame.title("sendme")
#     chat_picker_frame.protocol('WM_DELETE_WINDOW',close)
#     tkinter.Label(chat_picker_frame,text=f"hello {self.username}!",font="arial 23").grid(row=0,column=0,columnspan=2,sticky="NWE",pady=20)

#     chat_picker_frame.grid_columnconfigure(0,weight=1)
#     chat_picker_frame.grid_columnconfigure(1,weight=1)
#     chat_picker_frame.grid_rowconfigure(1,weight=1)
#     chat_picker_frame.grid_rowconfigure(3,weight=3)
#     chat_picker_frame.grid_rowconfigure(5,weight=1)

#     tkinter.Label(chat_picker_frame,text="want to join a group chat?\nenter pin code",font=15).grid(row=1,column=0,sticky="S")

#     pin_entry = tkinter.Entry(chat_picker_frame,font=15)
#     pin_entry.grid(row=2,column=0,pady=20)

#     tkinter.Button(chat_picker_frame,text="join chat",font=15,command= join_chat).grid(row=3,column=0,sticky="N")


#     tkinter.Label(chat_picker_frame,text="start a new chat!",font=15).grid(row=1,column=1,sticky="S")
#     tkinter.Button(chat_picker_frame,text="start new chat",font=15,command=open_new_chat).grid(row=2,column=1,sticky="N",pady=20)

#     chat_picker_frame.mainloop()