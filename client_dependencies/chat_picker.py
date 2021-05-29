import json
import random
import threading
import time
import tkinter
from tkinter import ttk

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

from ganeral_dependencies import protocol, AES_crypto
from ganeral_dependencies.AES_crypto import decrypt
from ganeral_dependencies.global_functions import bytes_to_int, int_to_bytes, buffer_extractor
from ganeral_dependencies.global_values import *
from ganeral_dependencies.protocol_digest import get_server_response


def is_in_list(item, chat_list):
    item1 = (item, "private")
    item2 = (item, "public")
    return item1 in chat_list or item2 in chat_list


def is_sublist(main_list: list, sublist: list):
    for item in sublist:
        if item not in main_list:
            return False
    return True


def create_frame(chat_picker_frame, chat_frame, user_values, server, key):
    continue_listening = threading.Event()
    stop_listening = threading.Event()
    chat_types = {}

    def open_new_private_chat():
        continue_listening.clear()
        time.sleep(0.05)
        swear_protected = is_swear_protected.get()
        packets = protocol.PacketMaker(CREATE_CHAT, content=int_to_bytes(swear_protected))
        for packet in packets:
            server.send(packet)

        packet = server.recv(PACKET_SIZE)
        msg = b""
        request, request_id, packet_amount, packet_number, flag = buffer_extractor(packet[:HEADER_SIZE])
        msg += packet[HEADER_SIZE:]
        if packet_amount - packet_number > 1:
            for _ in range(packet_amount - 1):
                packet = server.recv(PACKET_SIZE)
                msg += packet[HEADER_SIZE:]
        server_response = decrypt(msg, key).decode("utf-8")
        chat_name, chat_id = server_response.split("~~~")
        user_values.group_key = get_random_bytes(32)
        user_values.rsa_group_key = RSA.generate(2048)
        user_values.pin_code = chat_id
        user_values.chat_name = chat_name
        user_values.is_safe_chat = bool(swear_protected)
        user_values.on_chat_raise()
        stop_listening.set()
        chat_frame.tkraise()

    def open_new_public_chat():
        continue_listening.clear()
        swear_protected = is_swear_protected.get()
        time.sleep(0.5)
        rsa_key = RSA.generate(2048)
        if swear_protected == 0:
            content = rsa_key.public_key().export_key() + b'\x00'
        elif swear_protected == 1:
            content = rsa_key.public_key().export_key() + b'\x01'
        packets = protocol.PacketMaker(CREATE_PUBLIC_CHAT, content=content, shared_secret=key)
        for packet in packets:
            server.send(packet)

        packet = server.recv(PACKET_SIZE)
        msg = b""
        request, request_id, packet_amount, packet_number, flag = buffer_extractor(packet[:HEADER_SIZE])
        msg += packet[HEADER_SIZE:]
        if packet_amount - packet_number > 1:
            for _ in range(packet_amount - 1):
                packet = server.recv(PACKET_SIZE)
                msg += packet[HEADER_SIZE:]
        user_values.group_key = AES_crypto.rsa_decrypt(msg, rsa_key)
        user_values.chat_name = user_values.username + "'s public chat"

        if swear_protected:
            user_values.chat_name += " (swear protected)"
            user_values.is_safe_chat = True
        else:
            user_values.is_safe_chat = False

        user_values.on_chat_raise()
        stop_listening.set()
        chat_frame.tkraise()

    def on_select(event):
        if not continue_listening.isSet():
            return
        continue_listening.clear()

        courser = chat_listbox.curselection()
        if not courser:
            return
        value = chat_listbox.get(courser)
        if value[-11:] == "(safe chat)":
            user_values.is_safe_chat = True
        else:
            user_values.is_safe_chat = False

        if chat_types[value] == "private":
            top = tkinter.Toplevel()

            def join_chat(*args):
                continue_listening.clear()
                pin_error.grid_forget()
                pin_code = pin_code_entry.get()

                if not pin_code:
                    pin_error.grid(row=3, column=0, sticky="N")
                else:
                    rsa_key = RSA.generate(2048)
                    content = {"chat_name": value, "pin_code": pin_code, "rsa_key": rsa_key.export_key("PEM").decode(
                        "utf-8")}
                    content = json.dumps(content).encode("utf-8")
                    packets = protocol.PacketMaker(JOIN_CHAT, shared_secret=key, content=content)
                    for packet in packets:
                        server.send(packet)

                    request, server_response = get_server_response(server)
                    if request == SEND_GROUP_KEYS:
                        group_private_key, group_dh_key = server_response.strip(b'\x00').split(b"end_private_key")
                        user_values.rsa_group_key = AES_crypto.rsa_decrypt(group_private_key, rsa_key)
                        group_private_key = RSA.import_key(user_values.rsa_group_key)
                        group_dh_key = pow(bytes_to_int(group_dh_key), group_private_key.d, group_private_key.n)
                        user_values.group_key = int_to_bytes(group_dh_key)

                        top.withdraw()
                        pin_code_entry.delete(0, "end")
                        user_values.pin_code = pin_code
                        user_values.chat_name = value
                        stop_listening.set()
                        chat_frame.tkraise()
                        user_values.on_chat_raise()
                    elif request == CANT_JOIN_CHAT:
                        pin_error.grid(row=3, column=0, sticky="N")

            top.title("password inserter")

            tkinter.Label(top, text=f"want to join {value}?\nenter password", font=15).grid(row=1, column=0, sticky="S")

            pin_code_entry = tkinter.Entry(top, text="enter password", font=15)
            pin_code_entry.grid(row=2, column=0, pady=20, sticky="NEWS")

            pin_error = tkinter.Label(top, text="the pin-code you entered is incorrect", fg="red")

            tkinter.Button(top, text="join chat", font=15, command=join_chat).grid(row=4, column=0, sticky="N")
        else:
            stop_listening.set()
            rsa_key = RSA.generate(2048)
            content = dict(chat_name=value, rsa_key=rsa_key.export_key("PEM").decode("utf-8"))
            content = json.dumps(content).encode("utf-8")
            packets = protocol.PacketMaker(JOIN_PASSWORD_LESS_CHAT, content=content, shared_secret=key)
            for packet in packets:
                server.send(packet)

            packet = server.recv(PACKET_SIZE)
            request, request_id, packet_amount, packet_number, flag = buffer_extractor(packet[:HEADER_SIZE])
            full_msg = packet[HEADER_SIZE:]
            if packet_amount > 1:
                for _ in range(packet_amount - 1):
                    packet = server.recv(PACKET_SIZE)
                    full_msg += packet[HEADER_SIZE:]
            user_values.group_key = AES_crypto.rsa_decrypt(full_msg, rsa_key)
            user_values.chat_name = value
            chat_frame.tkraise()
            user_values.on_chat_raise()
            stop_listening.set()

    def on_raise():
        continue_listening.set()
        stop_listening.clear()
        chat_picker_frame.after(0, listener)

    def listener():
        if continue_listening.isSet():
            packets = protocol.PacketMaker(GET_CHATS)
            server.send(next(packets))
            packet = server.recv(PACKET_SIZE)
            msg = b""
            request, request_id, packet_amount, packet_number, flag = buffer_extractor(packet[:HEADER_SIZE])
            msg += packet[HEADER_SIZE:]
            if packet_amount - packet_number > 1:
                for _ in range(packet_amount - 1):
                    packet = server.recv(PACKET_SIZE)
                    msg += packet[HEADER_SIZE:]
            msg = decrypt(msg, key).decode("utf-8")
            chat_list = json.loads(msg)
            cur_list = chat_listbox.get(0, "end")
            for chat in chat_list:
                if chat not in cur_list:
                    chat_types[chat] = chat_list[chat]

                    chat_listbox.insert(tkinter.END, chat)

            i = 0
            for chat in cur_list:
                if chat not in chat_list:
                    chat_listbox.delete(i)
                i += 1

            chat_picker_frame.after(1000, listener)
        else:
            if not stop_listening.isSet():
                chat_picker_frame.after(2000, listener)

    chat_picker_frame.grid_columnconfigure(0, weight=1)
    chat_picker_frame.grid_columnconfigure(2, weight=1)
    chat_picker_frame.grid_rowconfigure(1, weight=1)
    chat_picker_frame.grid_rowconfigure(2, weight=1)
    chat_picker_frame.grid_rowconfigure(4, weight=2)

    tkinter.Label(chat_picker_frame, text="Want to join a group chat?\nClick on one of the groups",
                  font=15).grid(row=1,
                                column=0,
                                sticky="S")

    chat_listbox = tkinter.Listbox(chat_picker_frame, font=15)
    chat_listbox.grid(row=2, column=0, pady=20, sticky="NEWS", rowspan=5)
    chat_listbox.bind("<Double-1>", on_select)

    ttk.Separator(chat_picker_frame, orient='vertical').grid(row=1, column=1, rowspan=4, pady=10)

    tkinter.Label(chat_picker_frame, text="start a new chat!", font=15).grid(row=1, column=2)
    new_chat_button = tkinter.Button(chat_picker_frame, text="start new private chat", font=15,
                                     command=open_new_private_chat)
    new_chat_button.grid(row=2, column=2, pady=20)
    new_chat_button.config(justify="center")

    new_public_chat_button = tkinter.Button(chat_picker_frame, text="start new public chat", font=15,
                                            command=open_new_public_chat)
    new_public_chat_button.grid(row=3, column=2, pady=20)
    new_public_chat_button.config(justify="center")

    is_swear_protected = tkinter.IntVar()
    is_swear_protected_checkbox = tkinter.Checkbutton(chat_picker_frame, text="protect from curse words", font=15,
                                                      variable=is_swear_protected)
    is_swear_protected_checkbox.grid(row=4, column=2, pady=20, sticky="N")
    user_values.on_raise_chat_picker = on_raise


if __name__ == "__main__":
    root = tkinter.Tk()
    root.minsize(500, 500)
    create_frame(root, None, None, None, None)
    root.mainloop()
