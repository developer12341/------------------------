import tkinter
import tkinter as tk
from client_dependencies import start_window, register, login, email_validator, chat_picker, chat
import time


class UserValues:
    username = ""
    pin_code = 0
    group_key = None
    is_safe_chat = False
    rsa_group_key = None
    my_key = None


def about():
    top = tkinter.Toplevel()
    top.title("about us")
    about_label = tkinter.Label(top, text="""
Hello there!
Sendme is a chat app designed with security in mind 
to let you share your thoughts in private. 
With the ability to start your own chat you can easily share messages,
show feelings with kaomojis (^人^) and share files.
I hope you will have the best time with us!
""")
    about_label.pack()


def main(server, key):
    UserValues.my_key = key

    def close():
        UserValues.pin_code = 0
        time.sleep(0.3)
        root.destroy()

    root = tk.Tk()
    root.minsize(500, 500)
    root.maxsize(1500, 1500)
    root.title("sendme")
    root.columnconfigure(0, weight=1)
    root.rowconfigure(0, weight=1)
    root.protocol("WM_DELETE_WINDOW", close)

    menu_bar = tkinter.Menu(root)
    menu_bar.add_command(label="about us", command=about)

    root.config(menu=menu_bar)

    start_frame = tk.Frame(root)
    login_frame = tk.Frame(root)
    register_frame = tk.Frame(root)
    email_validator_frame = tk.Frame(root)
    chat_picker_frame = tk.Frame(root)
    chat_frame = tk.Frame(root)

    for frame in (start_frame, login_frame, register_frame, chat_picker_frame, chat_frame, email_validator_frame):
        frame.grid(row=0, column=0, sticky='news')

    start_window.create_frame(start_frame, register_frame, login_frame)
    register.create_frame(register_frame, login_frame, email_validator_frame, server, key, UserValues)
    login.create_frame(login_frame, register_frame, chat_picker_frame, server, key, UserValues)
    email_validator.create_frame(email_validator_frame, register_frame, UserValues, chat_picker_frame, server, key)
    chat_picker.create_frame(chat_picker_frame, chat_frame, UserValues, server, key)
    chat.create_frame(root, menu_bar, chat_frame, chat_picker_frame, UserValues, server, key)

    login_frame.tkraise()
    root.mainloop()
