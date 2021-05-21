import re
import tkinter

from ganeral_dependencies import protocol, protocol_digest
from ganeral_dependencies.global_functions import hash_password, reset_password_to_json
from ganeral_dependencies.global_values import *

# Make a regular expression for validating an Email
from ganeral_dependencies.protocol_digest import can_auth_reset

regex = '^(\w|\.|\_|\-)+[@](\w|\_|\-|\.)+[.]\w{2,3}$'


# Define a function for validating an Email
def is_valid_email(email):
    # pass the regular expression and the string in search() method
    if re.search(regex, email):
        return True
    else:
        return False


def create_frame(reset_frame, login_frame, email_validator_frame, user_values, server, key):

    def on_submit():
        email = email_entry.get()
        username = username_entry.get()
        password = password_entry.get()
        send = True

        if not is_valid_email(email):
            send = False
            email_error.grid(row=5, column=0, columnspan=2)

        if len(username) < USERNAME_MIN_LEN or len(username) > USERNAME_MAX_LEN:
            send = False
            length_error.grid(row=4, column=0, columnspan=2)

        if len(password) < PASSWORD_MIN_LEN or len(password) > PASSWORD_MAX_LEN:
            send = False
            length_error.grid(row=4, column=0, columnspan=2)

        if send:

            content = reset_password_to_json(username.encode("utf-8"), email.encode("utf-8"),
                                             hash_password(password).encode("utf-8"))
            packets = protocol.PacketMaker(RESET_PASSWORD, content=content, shared_secrete=key)
            for packet in packets:
                server.send(packet)

            server_response = server.recv(PACKET_SIZE)
            can_auth, reason = can_auth_reset(server_response)
            if can_auth:
                user_values.username = username
                email_validator_frame.tkraise()
            else:
                if reason == REG_LOGIN_FAIL:
                    server_error.grid(row=5, column=0, columnspan=2)
                elif reason == USER_LOGGED_IN:
                    logged_in_error.grid(row=5, column=0, columnspan=2)

    def on_clear():
        username_entry.delete(0, 'end')
        email_entry.delete(0, 'end')
        server_error.grid_forget()
        logged_in_error.grid_forget()

    tkinter.Label(reset_frame, text="reset password", font="arial 15").grid(row=0, column=0, columnspan=2, sticky="NEW")

    reset_frame.grid_columnconfigure(0, weight=1)
    reset_frame.grid_columnconfigure(1, weight=1)

    reset_frame.grid_rowconfigure(0, weight=1)
    reset_frame.grid_rowconfigure(1, weight=1)
    reset_frame.grid_rowconfigure(2, weight=1)
    reset_frame.grid_rowconfigure(3, weight=1)
    reset_frame.grid_rowconfigure(8, weight=3)

    tkinter.Label(reset_frame, text="username:", font=15).grid(row=1, column=0, sticky="E")
    username_entry = tkinter.Entry(reset_frame, font=15)
    username_entry.grid(row=1, column=1)

    tkinter.Label(reset_frame, text="email:", font=15).grid(row=2, column=0, sticky="E")
    email_entry = tkinter.Entry(reset_frame, font=15)
    email_entry.grid(row=2, column=1)

    tkinter.Label(reset_frame, text="new password:", font=15).grid(row=3, column=0, sticky="E")
    password_entry = tkinter.Entry(reset_frame, font=15, show="*")
    password_entry.grid(row=3, column=1)

    length_error = tkinter.Label(reset_frame, text="your username and password must have between 5 and 30 characters")
    length_error.grid(row=4, column=0, columnspan=2)
    email_error = tkinter.Label(reset_frame, text="this email is not a valid email", fg="red")
    server_error = tkinter.Label(reset_frame, text="your username or email does not match", fg="red")
    logged_in_error = tkinter.Label(reset_frame, text="you are already logged in on another computer", fg="red")

    button_frame = tkinter.Frame(reset_frame)
    button_frame.grid(row=8, column=0, columnspan=2, sticky="NEWS")
    for i in range(3):
        button_frame.grid_columnconfigure(i, weight=1)
    button_frame.grid_rowconfigure(0,weight=1)
    tkinter.Button(button_frame, text="send", font=15, command=on_submit).grid(row=0, column=0)

    tkinter.Button(button_frame, text="back to \nlogin", font=15, command=login_frame.tkraise).grid(row=0, column=1)

    tkinter.Button(button_frame, text="clear", font=15, command=on_clear).grid(row=0, column=2)


if __name__ == "__main__":
    root = tkinter.Tk()
    reset_frame = tkinter.Frame(root)
    reset_frame.grid(row=0, column=0, sticky='news')
    root.grid_rowconfigure(0, weight=1)
    root.columnconfigure(0, weight=1)
    root.minsize(500, 500)
    root.maxsize(1500, 1500)
    create_frame(reset_frame, None, None, None, None)
    root.mainloop()
