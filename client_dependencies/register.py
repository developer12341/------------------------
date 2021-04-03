import datetime
import re
import tkcalendar
import tkinter

from ganeral_dependencies import protocol_digest, protocols
from ganeral_dependencies.global_values import *

# Make a regular expression for validating an Email
regex = '^(\w|\.|\_|\-)+[@](\w|\_|\-|\.)+[.]\w{2,3}$'


# Define a function for validating an Email
def is_valid_email(email):
    # pass the regular expression and the string in search() method
    if re.search(regex, email):
        return True
    else:
        return False


error_msgs = {USERNAME_TAKEN: "this username is taken, please pick a different one",
              EMAIL_DOESNT_EXIST: "this email doesn't exist",
              EMAIL_TAKEN: "there is already a user with this email address"}


def create_frame(register_frame, login_frame, email_validate_frame, server, key, user_values):
    def login():
        login_frame.tkraise()

    def on_clear():
        username_error.grid_forget()
        password_error.grid_forget()
        re_password_error.grid_forget()
        date_error.grid_forget()
        server_error.grid_forget()

        username_entry.delete(0, 'end')
        password_entry.delete(0, 'end')
        re_password_entry.delete(0, 'end')
        today = datetime.date.today()
        birthday_picker.set_date(today)

    def on_submit(*args):
        date_error.grid_forget()
        email_error.grid_forget()
        re_password_error.grid_forget()
        username_error.grid_forget()
        password_error.grid_forget()
        server_error.grid_forget()

        username = username_entry.get()
        password = password_entry.get()
        re_password = re_password_entry.get()
        birthday = birthday_picker.get_date()
        today = datetime.date.today()
        email = email_entry.get()
        send = True
        if birthday > today:
            send = False
            date_error.grid(row=6, column=0, columnspan=2)
        if not is_valid_email(email):
            send = False
            email_error.grid(row=8, column=0, columnspan=2)
        if password != re_password:
            send = False
            re_password_error.grid(row=4, column=0, columnspan=2)
        if len(username) < USERNAME_MIN_LEN or len(username) > USERNAME_MAX_LEN:
            send = False
            username_error.grid(row=10, column=0, columnspan=2)
        if len(password) < PASSWORD_MIN_LEN or len(password) > PASSWORD_MAX_LEN:
            send = False
            password_error.grid(row=9, column=0, columnspan=2)
        if send:
            content = username.encode("utf-8") + bytes(USERNAME_MAX_LEN - len(username))
            content += password.encode("utf-8") + bytes(PASSWORD_MAX_LEN - len(password))
            content += birthday.year.to_bytes(2, "big") + bytes([birthday.month]) + bytes([birthday.day])
            content += email.encode("utf-8")
            packets = protocols.PacketMaker(REGISTER, key, content=content)
            for packet in packets:
                server.send(packet)

            server_response = server.recv(PACKET_SIZE)
            # print(server_response)
            can_auth, reason = protocol_digest.can_auth_email(server_response)
            if can_auth:
                user_values.username = username
                email_validate_frame.tkraise()
            else:
                print(error_msgs[reason])
                server_error_var.set(error_msgs[reason])
                server_error.grid(row=11, column=0, columnspan=2)

    tkinter.Label(register_frame, text="Register", font="arial 15").grid(row=0, column=0, columnspan=2, sticky="NEW",
                                                                         pady=15)

    register_frame.grid_columnconfigure(0, weight=1)
    register_frame.grid_columnconfigure(1, weight=1)

    tkinter.Label(register_frame, text="username:", font=15).grid(row=1, column=0, pady=(20, 0), sticky="E")
    username_entry = tkinter.Entry(register_frame, font=15)
    username_entry.grid(row=1, column=1, pady=(20, 0))

    tkinter.Label(register_frame, text="password:", font=15).grid(row=2, column=0, sticky="E", pady=(20, 0))
    password_entry = tkinter.Entry(register_frame, font=15, show="*")
    password_entry.grid(row=2, column=1, pady=(20, 0))

    tkinter.Label(register_frame, text="enter password again:", font=15).grid(row=3, column=0, sticky="E", pady=(20, 0))
    re_password_entry = tkinter.Entry(register_frame, font=15, show="*")
    re_password_entry.grid(row=3, column=1, pady=(20, 0))

    re_password_error = tkinter.Label(register_frame, text="the passwords do not match", fg="red")
    re_password_error.grid(row=4, column=0, columnspan=2)
    re_password_error.grid_forget()

    tkinter.Label(register_frame, text="birthday:", font=15).grid(row=5, column=0, sticky="E", pady=(20, 0))
    birthday_picker = tkcalendar.DateEntry(register_frame)
    birthday_picker.grid(row=5, column=1)

    date_error = tkinter.Label(register_frame, text="this date is not valid", fg="red")
    date_error.grid(row=6, column=0, columnspan=2)
    date_error.grid_forget()

    tkinter.Label(register_frame, text="email:", font=15).grid(row=7, column=0, sticky="E", pady=(20, 0))
    email_entry = tkinter.Entry(register_frame, font=15)
    email_entry.grid(row=7, column=1, pady=(20, 0))

    email_error = tkinter.Label(register_frame, text="this email is not valid", fg="red")
    email_error.grid(row=8, column=0, columnspan=2)
    email_error.grid_forget()

    password_error = tkinter.Label(register_frame,
                                   text=f"the password must be between {PASSWORD_MIN_LEN} and {PASSWORD_MAX_LEN} characters",
                                   fg="red")
    password_error.grid(row=9, column=0, columnspan=2)
    password_error.grid_forget()

    username_error = tkinter.Label(register_frame,
                                   text=f"the username must be between {USERNAME_MIN_LEN} and {USERNAME_MAX_LEN} characters",
                                   fg="red")
    username_error.grid(row=10, column=0, columnspan=2)
    username_error.grid_forget()

    server_error_var = tkinter.StringVar()
    server_error = tkinter.Label(register_frame, textvariable=server_error_var, fg="red")
    server_error.grid(row=11, column=0, columnspan=2)
    server_error.grid_forget()

    tkinter.Button(register_frame, text="send", font=15, command=on_submit).grid(row=12, column=0, pady=(20, 0))

    tkinter.Button(register_frame, text="clear", font=15, command=on_clear).grid(row=12, column=1, pady=(20, 0))

    tkinter.Label(register_frame, text="already have a user?", font=20).grid(row=13, column=0, columnspan=2,
                                                                             pady=(20, 0))
    tkinter.Button(register_frame, text="log in", font=15, command=login).grid(row=14, column=0, columnspan=2,
                                                                               pady=(20, 0))


if __name__ == "__main__":
    root = tkinter.Tk()
    root.minsize(500, 500)
    root.maxsize(1500, 1500)
    create_frame(root, None, None, None, None, None)
    root.mainloop()
