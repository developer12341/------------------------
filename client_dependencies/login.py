import tkinter,threading
from ganeral_dependencies import packets_maker,pac_comp
from ganeral_dependencies.global_values import LOGIN,PASSWORD_MAX_LEN,USERNAME_MAX_LEN, PACKET_SIZE
def Create_Frame(login_frame, register_frame, chat_picker_frame,server,public_key,private_key):

    def regiater():
        register_frame.tkraise()
    
    def on_submit():
        username = username_entry.get()
        password = password_entry.get()
        if username and password:
            if len(username) > USERNAME_MAX_LEN or len(password) > PASSWORD_MAX_LEN:
                print("error msg")

            content = username.encode("ascii") + bytes(USERNAME_MAX_LEN-len(username))
            content += password.encode("ascii") + bytes(PASSWORD_MAX_LEN-len(password))
            packets = packets_maker.Packet_Maker(LOGIN,public_key,content=content)
            for packet in packets:
                print(packet)
                server.send(packet)
            
            server_response = server.recv(PACKET_SIZE)
            if pac_comp.is_logged_in(server_response):
                chat_picker_frame.tkraise()
            else:
                print("error msg")
    
    def on_clear():
        username_entry.delete(0, 'end')
        password_entry.delete(0, 'end')

    tkinter.Label(login_frame,text="log in",font="arial 15").grid(row=0,column=0,columnspan=2,sticky="NEW")

    login_frame.grid_columnconfigure(0,weight=2)
    login_frame.grid_columnconfigure(1,weight=1)

    tkinter.Label(login_frame,text="username:",font=15).grid(row=1,column=0,sticky="E",pady=(20,0))
    username_entry = tkinter.Entry(login_frame,font=15)
    username_entry.grid(row=1,column=1,pady=(20,0))

    tkinter.Label(login_frame,text="password:",font=15).grid(row=2,column=0,sticky="E",pady=(20,0))
    password_entry = tkinter.Entry(login_frame,font=15,show="*")
    password_entry.grid(row=2,column=1,pady=(20,0))

    tkinter.Button(login_frame,text="send",font=15,command=on_submit).grid(row=4,column=0,pady=(20,0),sticky="E")

    tkinter.Button(login_frame,text="clear",font=15, command=on_clear).grid(row=4,column=1,pady=(20,0))

    tkinter.Label(login_frame,text="don't have a user?",font="arial 15").grid(row=6,column=0,columnspan=2,pady=(20,0))
    tkinter.Button(login_frame,text="register",font=15,command=regiater).grid(row=7,column=0,columnspan=2,pady=(20,0))

# def main(self):
#     def close():
#         self.close_protocol = True
#         threading._start_new_thread(window.destroy,tuple())

#     def on_clear():
#         username_entry.delete(0, 'end')
#         password_entry.delete(0, 'end')

#     def on_submit():
#         username = username_entry.get()
#         password = password_entry.get()
#         if username != "" or password != "":
#             self.send_obj.insert("login")
#             self.send_obj.insert(username)
#             self.send_obj.insert(password)
#             self.username = username

#             msg = self.recv_obj.get_item()
#             if msg == "good to go":
#                 self.cur_window = "chat_picker"
#                 window.destroy()
#             else:
#                 tkinter.Label(window,text = msg, fg="red").grid(row = 3, column=0,columnspan=2)
#         else:
#             tkinter.Label(window,text = "you must enter your details to log in", fg="red").grid(row = 3, column=0,columnspan=2)

#     def on_enter(event):
#         username = username_entry.get()
#         password = password_entry.get()
#         if username != "" or password != "":
#             self.send_obj.insert("login")
#             self.send_obj.insert(username)
#             self.send_obj.insert(password)
#             self.username = username

#             msg = self.recv_obj.get_item()
#             if msg == "good to go":
#                 self.cur_window = "chat_picker"
#                 window.destroy()
#             else:
#                 tkinter.Label(window,text = msg, fg="red").grid(row = 3, column=0,columnspan=2)
#         else:
#             tkinter.Label(window,text = "you must enter your details to log in", fg="red").grid(row = 3, column=0,columnspan=2)



#     def register_function():
#         self.cur_window = "register"
#         window.destroy()
    
#     window = tkinter.Tk()
#     window.title("sendme")
#     window.geometry("600x400")
#     window.protocol("WM_DELETE_WINDOW",close)
#     window.bind("<Return>",on_enter)
#     tkinter.Label(window,text="log in",font="arial 15").grid(row=0,column=0,columnspan=2,sticky="NEW")

#     window.grid_columnconfigure(0,weight=2)
#     window.grid_columnconfigure(1,weight=1)

#     tkinter.Label(window,text="username:",font=15).grid(row=1,column=0,sticky="E",pady=(20,0))
#     username_entry = tkinter.Entry(window,font=15)
#     username_entry.grid(row=1,column=1,pady=(20,0))

#     tkinter.Label(window,text="password:",font=15).grid(row=2,column=0,sticky="E",pady=(20,0))
#     password_entry = tkinter.Entry(window,font=15,show="*")
#     password_entry.grid(row=2,column=1,pady=(20,0))

#     tkinter.Button(window,text="send",command= on_submit,font=15).grid(row=4,column=0,pady=(20,0),sticky="E")

#     tkinter.Button(window,text="clear",font=15,command=on_clear).grid(row=4,column=1,pady=(20,0))

#     tkinter.Label(window,text="don't have a user?",font="arial 15").grid(row=6,column=0,columnspan=2,pady=(20,0))
#     tkinter.Button(window,text="register",font=15, command= register_function).grid(row=7,column=0,columnspan=2,pady=(20,0))

#     window.mainloop()

