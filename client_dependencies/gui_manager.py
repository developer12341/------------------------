import tkinter as tk
from client_dependencies import start_window,register,login,email_validetor,chat_picker,chat

class user_values:
    username = ""
    pincode = 0
    group_key = None
    my_key = None


def main(server,key):
    user_values.my_key = key
    def close():
        root.destroy()

    root = tk.Tk()
    root.minsize(500,500)
    root.maxsize(1500,1500)
    root.title("sendme")
    root.columnconfigure(0,weight=1)
    root.rowconfigure(0,weight=1)
    root.protocol("WM_DELETE_WINDOW",close)

    start_frame = tk.Frame(root)
    login_frame = tk.Frame(root)
    register_frame = tk.Frame(root)
    email_validetor_frame = tk.Frame(root)
    chat_picker_frame = tk.Frame(root)
    chat_frame= tk.Frame(root)

    for frame in (start_frame, login_frame, register_frame, chat_picker_frame, chat_frame,email_validetor_frame):
        frame.grid(row=0, column=0, sticky='news')

    start_window.Create_Frame(start_frame,register_frame,login_frame)
    register.Create_Frame(register_frame,login_frame,email_validetor_frame,server,key,user_values)
    login.Create_Frame(login_frame,register_frame,chat_picker_frame,server,key,user_values)
    email_validetor.Create_Frame(email_validetor_frame,register_frame,chat_picker_frame,server,key)
    chat_picker.create_frame(chat_picker_frame,chat_frame,user_values,server,key)
    chat.create_frame(root,chat_frame,chat_picker_frame,user_values,server,key)

    login_frame.tkraise()
    root.mainloop()