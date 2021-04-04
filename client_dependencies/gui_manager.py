import tkinter as tk
from client_dependencies import start_window, register, login, email_validator, chat_picker, chat
import time


class UserValues:
    username = ""
    pin_code = 0
    group_key = None
    rsa_group_key = None
    my_key = None


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
    chat.create_frame(root, chat_frame, chat_picker_frame, UserValues, server, key)

    register_frame.tkraise()
    root.mainloop()
