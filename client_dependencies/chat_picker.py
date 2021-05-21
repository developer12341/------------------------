import socket
import time
import tkinter
from tkinter import ttk
import threading
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

from ganeral_dependencies import protocol_digest
from ganeral_dependencies import protocol, AES_crypto
from ganeral_dependencies.AES_crypto import decrypt
from ganeral_dependencies.global_functions import bytes_to_int, int_to_bytes
from ganeral_dependencies.global_values import *
from ganeral_dependencies.protocol_digest import get_server_response


def create_frame(chat_picker_frame, chat_frame, user_values, server, key):
    continue_listening = threading.Event()
    continue_listening.set()
    stop_listening = threading.Event()

    chat_types = {}
    def open_new_chat():
        continue_listening.clear()
        time.sleep(0.05)
        packets = protocol.PacketMaker(CREATE_CHAT)
        for packet in packets:
            server.send(packet)
        server_response = server.recv(PACKET_SIZE)
        user_values.pin_code = protocol_digest.decrypt(server_response[HEADER_SIZE:].strip(b'\x00'), key).decode(
            "utf-8")
        user_values.group_key = get_random_bytes(32)
        user_values.rsa_group_key = RSA.generate(2048)
        stop_listening.set()
        chat_frame.tkraise()
        user_values.on_chat_raise()

    def on_select(event):
        continue_listening.clear()
        value = chat_listbox.get(chat_listbox.curselection())

        def join_chat(*args):
            continue_listening.clear()
            pin_error.grid_forget()
            pin_code = pin_code_entry.get()
            if not pin_code:
                pin_error.grid(row=3, column=0, sticky="N")
            else:
                rsa_key = RSA.generate(2048)
                content = {"chat_name": value, "pin_code": pin_code, "rsa_key": rsa_key.export_key("PEM")}
                packets = protocol.PacketMaker(JOIN_CHAT, shared_secrete=key, content=content)
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
        if chat_types[value]:
            top = tkinter.Toplevel()
            top.title("password inserter")

            tkinter.Label(top, text=f"want to join {value}?\nenter password", font=15).grid(row=1, column=0, sticky="S")

            pin_code_entry = tkinter.Entry(top, text="enter password", font=15)
            pin_code_entry.grid(row=2, column=0, pady=20, sticky="NEWS")

            pin_error = tkinter.Label(top, text="the pin-code you entered is incorrect", fg="red")

            tkinter.Button(top, text="join chat", font=15, command=join_chat).grid(row=4, column=0,
                                                                               sticky="N")



    def listener():
        if continue_listening.isSet():
            server.settimeout(0.001)
            try:
                packet = server.recv(PACKET_SIZE)
                server.settimeout(None)
                msg_queue = []
                request, request_id, packet_amount, packet_number, flag = protocol_digest.buffer_extractor(
                    packet[:HEADER_SIZE])
                msg_queue.append(packet)
                server.settimeout(0.001)
                if packet_amount - packet_number > 1:
                    for _ in range(packet_amount - 1):
                        packet = server.recv(PACKET_SIZE)
                        msg_queue.append(packet)
                server.settimeout(None)

                if request == ADD_CHAT:
                    chat_name = b''
                    for packet in msg_queue:
                        chat_name += packet[HEADER_SIZE:]
                    chat_name = decrypt(chat_name.decode("utf-8"), key).decode("utf-8")
                    is_password_free =
                    chat_types[chat_name] = is_password_free
                    chat_listbox.insert(tkinter.END, chat_name)

            except socket.timeout:
                server.settimeout(None)
            finally:
                chat_frame.after(300, listener)
        else:
            pass

    chat_picker_frame.grid_columnconfigure(0, weight=1)
    chat_picker_frame.grid_columnconfigure(2, weight=1)
    chat_picker_frame.grid_rowconfigure(1, weight=1)
    chat_picker_frame.grid_rowconfigure(4, weight=1)

    tkinter.Label(chat_picker_frame, text="want to join a group chat?\nenter pin code", font=15).grid(row=1, column=0,
                                                                                                      sticky="S")

    chat_listbox = tkinter.Listbox(chat_picker_frame, font=15)
    chat_listbox.grid(row=2, column=0, pady=20, sticky="NEWS")
    chat_listbox.bind("<Double-1>", on_select)
    chat_listbox.insert(0, "ido's chat")
    ttk.Separator(chat_picker_frame, orient='vertical').grid(row=1, column=1, rowspan=4, pady=10)

    tkinter.Label(chat_picker_frame, text="start a new chat!", font=15).grid(row=1, column=2, sticky="S")
    new_chat_button = tkinter.Button(chat_picker_frame, text="start new chat", font=15, command=open_new_chat)
    new_chat_button.grid(row=2, column=2, pady=20)
    new_chat_button.config(justify="center")


if __name__ == "__main__":
    root = tkinter.Tk()
    root.minsize(500, 500)
    create_frame(root, None, None, None, None)
    root.mainloop()
