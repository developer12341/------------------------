import tkinter,threading
from ganeral_dependencies import protocols,pac_comp
from ganeral_dependencies.global_values import *
def Create_Frame(login_frame, register_frame, chat_picker_frame,server,key,user_values):

    def regiater():
        register_frame.tkraise()
    
    def on_submit(*args):
        username = username_entry.get()
        password = password_entry.get()
        if username and password:
            content = username.encode("utf-8") + bytes(USERNAME_MAX_LEN-len(username))
            content += password.encode("utf-8") + bytes(PASSWORD_MAX_LEN-len(password))
            packets = protocols.Packet_Maker(LOGIN,shared_secrete=key,content=content)
            for packet in packets:
                server.send(packet)
            
            request,can_join_chat = pac_comp.is_logged_in(server.recv(PACKET_SIZE))
            if can_join_chat:
                server_error.grid_forget()
                user_values.username = username
                tkinter.Label(chat_picker_frame,text=f"hello {user_values.username}!",font="arial 23").grid(row=0,column=0,columnspan=3,sticky="NWE")
                chat_picker_frame.tkraise()
            else:
                if request == REG_LOGIN_FAIL:
                    logged_in_error.grid_forget()
                    server_error.grid(row=4,column=0,columnspan=2)
                elif request == USER_LOGGED_IN:
                    server_error.grid_forget()
                    logged_in_error.grid(row=4,column=0,columnspan=2)
        else:
            length_error["fg"] =  "red"

    def on_clear():
        username_entry.delete(0, 'end')
        password_entry.delete(0, 'end')
        server_error.grid_forget()
        logged_in_error.grid_forget()
        length_error["fg"] =  "black"


    tkinter.Label(login_frame,text="log in",font="arial 15").grid(row=0,column=0,columnspan=2,sticky="NEW")

    login_frame.grid_columnconfigure(0,weight=1)
    login_frame.grid_columnconfigure(1,weight=1)

    login_frame.grid_rowconfigure(0,weight=1)
    login_frame.grid_rowconfigure(1,weight=1)
    login_frame.grid_rowconfigure(2,weight=1)
    login_frame.grid_rowconfigure(5,weight=1)
    login_frame.grid_rowconfigure(7,weight=1)
    tkinter.Label(login_frame,text="username:",font=15).grid(row=1,column=0,sticky="E")
    username_entry = tkinter.Entry(login_frame,font=15)
    username_entry.grid(row=1,column=1)

    tkinter.Label(login_frame,text="password:",font=15).grid(row=2,column=0,sticky="E")
    password_entry = tkinter.Entry(login_frame,font=15,show="*")
    password_entry.grid(row=2,column=1)

    length_error = tkinter.Label(login_frame,text= "your username and password must have between 5 and 30 characters")
    length_error.grid(row=3,column=0,columnspan=2)
    
    server_error = tkinter.Label(login_frame, text = "your username or password was incorect",fg = "red")
    logged_in_error = tkinter.Label(login_frame, text = "you are allready logged in on another computer",fg = "red")
    
    tkinter.Button(login_frame,text="send",font=15,command=on_submit).grid(row=5,column=0,sticky="E")

    tkinter.Button(login_frame,text="clear",font=15, command=on_clear).grid(row=5,column=1)

    tkinter.Label(login_frame,text="don't have a user?",font="arial 15").grid(row=6,column=0,columnspan=2)
    tkinter.Button(login_frame,text="register",font=15,command=regiater).grid(row=7,column=0,columnspan=2)
    login_frame.bind("<Return>",on_submit)
    
if __name__ == "__main__":
    root = tkinter.Tk()
    login_frame = tkinter.Frame(root)
    login_frame.grid(row=0, column=0, sticky='news')
    root.minsize(500,500)
    root.maxsize(1500,1500)
    Create_Frame(login_frame,None,None,None,None,None)
    root.mainloop()


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

#     tkinter.Label(window,text="username:",font=15).grid(row=1,column=0,sticky="E")
#     username_entry = tkinter.Entry(window,font=15)
#     username_entry.grid(row=1,column=1)

#     tkinter.Label(window,text="password:",font=15).grid(row=2,column=0,sticky="E")
#     password_entry = tkinter.Entry(window,font=15,show="*")
#     password_entry.grid(row=2,column=1)

#     tkinter.Button(window,text="send",command= on_submit,font=15).grid(row=4,column=0,sticky="E")

#     tkinter.Button(window,text="clear",font=15,command=on_clear).grid(row=4,column=1)

#     tkinter.Label(window,text="don't have a user?",font="arial 15").grid(row=6,column=0,columnspan=2)
#     tkinter.Button(window,text="register",font=15, command= register_function).grid(row=7,column=0,columnspan=2)

#     window.mainloop()

