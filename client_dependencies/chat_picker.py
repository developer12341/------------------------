import tkinter
from tkinter import ttk

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

from ganeral_dependencies import protocol_digest
from ganeral_dependencies import protocols, AES_crypto
from ganeral_dependencies.global_functions import bytes_to_int, int_to_bytes
from ganeral_dependencies.global_values import *
from ganeral_dependencies.protocol_digest import get_server_response


def create_frame(chat_picker_frame, chat_frame, user_values, server, key):
    def join_chat(*args):
        pin_error.grid_forget()
        pin_code = pin_entry.get()
        if not pin_code:
            pin_error.grid(row=3, column=0, sticky="N")

        rsa_key = RSA.generate(2048)
        content = pin_code.encode("utf-8") + b"pin_code_end" + rsa_key.public_key().export_key("PEM")
        packets = protocols.PacketMaker(JOIN_CHAT, shared_secrete=key, content=content)
        for packet in packets:
            server.send(packet)

        request, server_response = get_server_response(server)
        if request == SEND_GROUP_KEYS:
            user_values.pin_code = pin_code
            group_private_key, group_dh_key = server_response.strip(b'\x00').split(b"end_private_key")
            user_values.rsa_group_key = AES_crypto.rsa_decrypt(group_private_key, rsa_key)
            group_private_key = RSA.import_key(user_values.rsa_group_key)
            group_dh_key = pow(bytes_to_int(group_dh_key), group_private_key.d, group_private_key.n)
            user_values.group_key = int_to_bytes(group_dh_key)

            chat_frame.tkraise()
            user_values.on_chat_raise()
        elif request == CANT_JOIN_CHAT:
            pin_error.grid(row=3, column=0, sticky="N")

    def open_new_chat():
        packets = protocols.PacketMaker(CREATE_CHAT)
        for packet in packets:
            server.send(packet)
        server_response = server.recv(PACKET_SIZE)
        user_values.pin_code = protocol_digest.decrypt(server_response[HEADER_SIZE:].strip(b'\x00'), key).decode(
            "utf-8")
        user_values.group_key = get_random_bytes(32)
        user_values.rsa_group_key = RSA.generate(2048)
        chat_frame.tkraise()
        user_values.on_chat_raise()

    chat_picker_frame.grid_columnconfigure(0, weight=1)
    chat_picker_frame.grid_columnconfigure(2, weight=1)
    chat_picker_frame.grid_rowconfigure(1, weight=1)
    chat_picker_frame.grid_rowconfigure(4, weight=3)

    tkinter.Label(chat_picker_frame, text="want to join a group chat?\nenter pin code", font=15).grid(row=1, column=0,
                                                                                                      sticky="S")

    pin_entry = tkinter.Entry(chat_picker_frame, font=15)
    pin_entry.grid(row=2, column=0, pady=20)

    pin_error = tkinter.Label(chat_picker_frame, text="the pin-code you entered is incorrect", fg="red")

    tkinter.Button(chat_picker_frame, text="join chat", font=15, command=join_chat).grid(row=4, column=0, sticky="N")

    ttk.Separator(chat_picker_frame, orient='vertical').grid(row=1, column=1, rowspan=4, sticky="NEWS", pady=10)

    tkinter.Label(chat_picker_frame, text="start a new chat!", font=15).grid(row=1, column=2, sticky="S")
    tkinter.Button(chat_picker_frame, text="start new chat", font=15, command=open_new_chat).grid(row=2, column=2,
                                                                                                  sticky="N", pady=20)


if __name__ == "__main__":
    root = tkinter.Tk()
    create_frame(root, None, None, None, None)
    root.mainloop()
