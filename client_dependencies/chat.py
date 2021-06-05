import os
import random
import socket
import subprocess
import threading
import time
import tkinter
from tkinter.filedialog import askopenfilename

import pyperclip
from Crypto.PublicKey import RSA
import win32api

from ganeral_dependencies import protocol_digest, protocol, AES_crypto
from ganeral_dependencies.AES_crypto import decrypt
from ganeral_dependencies.global_functions import bytes_to_int, int_to_bytes, extract_file_name
from ganeral_dependencies.global_values import *

with open(".\\client_dependencies\\swear words.txt", "r") as f:
    swear_words = f.read().split("\n")


def is_swear(sentence: str):
    words = sentence.split()
    for word in words:
        word = word.lower()
        if word in swear_words:
            return True
    return False


is_kaomoji_open = False


class Kaomojies:

    def __init__(self):
        self.top = tkinter.Toplevel()
        self.top.protocol("WM_DELETE_WINDOW", self.close)
        self.top.minsize(150, 150)
        self.top.grid_columnconfigure(0, weight=1)
        self.top.grid_rowconfigure(0, weight=1)
        self.list_box = tkinter.Listbox(self.top)
        self.list_box.grid(row=0, column=0, sticky="NEWS")
        self.list_box.configure(justify=tkinter.CENTER)
        self.list_box.bind('<Double-1>', self.select_from_list_box)
        for folder in kaomoji_folder_list:
            self.list_box.insert(tkinter.END, folder)

    def close(self):
        global is_kaomoji_open
        is_kaomoji_open = False
        self.top.destroy()

    def select_from_list_box(self, event):
        global chat_entry

        if self.list_box.get(0) != "go back":
            courser = self.list_box.curselection()
            # Updating label text to selected option
            value = self.list_box.get(courser)
            self.list_box.delete(0, tkinter.END)
            self.list_box.insert(0, "go back")
            k_file = open(".\\kaomoji\\" + value + "\\Kaomoji.k", "rb")
            kaomojis = k_file.readlines()
            for kaomoji in kaomojis:
                self.list_box.insert(tkinter.END, kaomoji.decode("utf-8"))
        else:
            courser = self.list_box.curselection()
            # Updating label text to selected option
            value = self.list_box.get(courser)
            if value == "go back":
                self.list_box.delete(0, tkinter.END)
                for folder in kaomoji_folder_list:
                    self.list_box.insert(tkinter.END, folder)
            else:
                chat_entry.insert(tkinter.END, value.strip('\n') + " ")
                self.close()


FILE_BROWSER_PATH = os.path.join(os.getenv('WINDIR'), 'explorer.exe')
clickable_links = {}


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


def explore(path):
    # explorer would choke on forward slashes
    path = os.path.normpath(path)

    if os.path.isdir(path):
        subprocess.run([FILE_BROWSER_PATH, path])
    elif os.path.isfile(path):
        subprocess.run([FILE_BROWSER_PATH, '/select,', os.path.normpath(path)])


class ProcessPackets(threading.Thread):
    def __init__(self, server, user_values, key, parameters=None):
        self.request_queue = []
        self.server = server
        self.key = key
        self.user_values = user_values
        self.parameters = parameters
        self.top = None
        threading.Thread.__init__(self)

    def run(self):
        while self.user_values.pin_code or self.user_values.chat_name:
            if self.request_queue:
                if self.request_queue[0][0] == GET_GROUP_KEY:
                    client_public_key = RSA.import_key(self.request_queue[0][1].strip(b"\x00"))
                    content = AES_crypto.rsa_encrypt(self.user_values.rsa_group_key.export_key(), client_public_key)
                    content += b"end_private_key"
                    encrypted_group_key = int_to_bytes(
                        pow(bytes_to_int(self.user_values.group_key), self.user_values.rsa_group_key.e,
                            self.user_values.rsa_group_key.n))
                    content += encrypted_group_key
                    packets = protocol.PacketMaker(SEND_GROUP_KEYS, content=content)
                    for packet in packets:
                        self.server.send(packet)
                    del self.request_queue[0]

                elif self.request_queue[0][0] in [SEND_FILE, SEND_IMG]:
                    file_content = protocol_digest.decrypt(self.request_queue[0][1][1], self.user_values.group_key)
                    file_name = protocol_digest.decrypt(self.request_queue[0][1][0], self.user_values.group_key)
                    with open(".\\files\\" + file_name.decode("utf-8"), "wb") as file_:
                        file_.write(file_content)
                    del self.request_queue[0]

                elif self.request_queue[0][0] == GET_GROUP_INFO:
                    top = tkinter.Toplevel()
                    self.top = top
                    top.title("group info")
                    top.minsize(250, 250)
                    group_users = decrypt(self.request_queue[0][1], self.key).decode("utf-8")
                    content = f"{self.user_values.chat_name}\n"
                    if self.user_values.pin_code:
                        pyperclip.copy(self.user_values.pin_code)
                        content += f"\nGroup code - {self.user_values.pin_code}\n"
                    content += "\nusers\n"
                    content += group_users
                    about_label = tkinter.Label(top, text=content)
                    about_label.pack()
                    del self.request_queue[0]

            time.sleep(0.05)

    def add_request(self, request):
        self.request_queue.append(request)


def create_frame(main_root, menu_bar, chat_frame, chat_picker_frame, user_values, server, key):
    global chat_entry
    root_menu_bar = menu_bar

    def group_info():
        packets = protocol.PacketMaker(GET_GROUP_INFO)
        server.send(next(packets))

    def on_raise():
        main_root.title(f"sendme - {user_values.chat_name}")
        file_menu = tkinter.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="grope info", command=group_info)
        file_menu.add_separator()
        file_menu.add_command(label="leave grope", command=leave_group)
        menu_bar.add_cascade(label="options", menu=file_menu)
        msg = f"{user_values.username} has entered the chat".encode("utf-8")
        list_box.insert(tkinter.END, msg)
        user_values.process_thread = ProcessPackets(server, user_values, key)
        user_values.process_thread.start()
        chat_frame.after(100, msg_listener)
        if user_values.group_key:
            packets = protocol.PacketMaker(SEND_MSG, shared_secret=user_values.group_key, content=msg)
            for packet in packets:
                server.send(packet)

    def leave_group():
        main_root.title("sendme")
        user_values.pin_code = 0
        user_values.chat_name = ""
        root_menu_bar.delete(tkinter.END)
        msg = f"{user_values.username} is leaving this chat"
        packets = protocol.PacketMaker(SEND_MSG, shared_secret=user_values.group_key, content=msg.encode("utf-8"))
        for packet in packets:
            server.send(packet)
        packets = protocol.PacketMaker(LEAVE_CHAT)
        server.send(next(packets))

        chat_entry.delete(0, tkinter.END)
        list_box.delete(0, tkinter.END)
        user_values.on_raise_chat_picker()
        chat_picker_frame.tkraise()

    def on_send(*args):
        msg = chat_entry.get()
        if not msg:
            return
        if user_values.is_safe_chat:
            if is_swear(msg):
                win32api.MessageBox(0, "you can't swear in hear!", 'warning', 0x00001000)
                return

        msg = f"<{user_values.username}>:" + msg

        list_box.insert(tkinter.END, msg)
        packets = protocol.PacketMaker(SEND_MSG, shared_secret=user_values.group_key, content=msg.encode("utf-8"))
        for packet in packets:
            server.send(packet)
        chat_entry.delete(0, "end")

    def on_send_file():
        print("send a pic")
        filepath = askopenfilename()
        if filepath:
            request = SEND_FILE
            file_format = extract_file_name(filepath).split(".")[-1]
            if file_format.upper() in image_file_formats:
                request = SEND_IMG

            packets = protocol.PacketMaker(request, shared_secret=user_values.group_key,
                                           username=user_values.username.encode("utf-8"), file_path=filepath)
            for packet in packets:
                server.send(packet)

    def select_from_list_box(event):
        courser = list_box.curselection()
        value = list_box.get(courser)
        if value in clickable_links:
            explore(clickable_links[value])

    def kaomoji_popup():
        global is_kaomoji_open
        if not is_kaomoji_open:
            is_kaomoji_open = True
            Kaomojies()

    def msg_listener(*args):
        if user_values.pin_code or user_values.chat_name:
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
                if request == SEND_MSG:
                    msg = b''
                    for packet in msg_queue:
                        msg += packet[HEADER_SIZE:]
                    msg = decrypt(msg, user_values.group_key)
                    list_box.insert(tkinter.END, msg.decode("utf-8"))
                elif request in [SEND_FILE, SEND_IMG]:
                    print("got a pic")
                    username = b''
                    file_name = b''
                    file_content = b''
                    for packet in msg_queue:
                        request, request_id, packet_amount, packet_number, flag = protocol_digest.buffer_extractor(
                            packet[:HEADER_SIZE])
                        if flag == FILE_NAME_PACKET:
                            file_name += packet[HEADER_SIZE:]
                        elif flag == CONTENT_PACKET:
                            file_content += packet[HEADER_SIZE:]
                        elif flag == USERNAME_PACKET:
                            username += packet[HEADER_SIZE:]
                    user_values.process_thread.add_request([request, [file_name, file_content]])
                    username = decrypt(username, user_values.group_key)
                    list_box.insert(tkinter.END, username.decode("utf-8") + " sent a file")
                    file_path = os.getcwd() + "\\files"
                    clickable_links[username.decode("utf-8") + " sent a file"] = file_path
                elif request == GET_GROUP_INFO:
                    msg = b''
                    for packet in msg_queue:
                        msg += packet[HEADER_SIZE:]
                    user_values.process_thread.add_request([request, msg])
                else:
                    msg = b''
                    for packet in msg_queue:
                        msg += packet[HEADER_SIZE:]
                    user_values.process_thread.add_request([request, msg])

            except socket.timeout:
                server.settimeout(None)
            finally:
                chat_frame.after(300, msg_listener)

    user_values.on_chat_raise = on_raise
    chat_frame.grid_rowconfigure(0, weight=1)
    chat_frame.grid_columnconfigure(0, weight=9999)
    chat_frame.grid_columnconfigure(1, weight=1)
    chat_frame.grid_columnconfigure(2, weight=1)
    chat_frame.grid_columnconfigure(3, weight=1)

    scrollbar = tkinter.Scrollbar(chat_frame)
    scrollbar.grid(row=0, column=4, sticky="NSEW", padx=(0, 0))

    list_box = tkinter.Listbox(chat_frame, yscrollcommand=scrollbar.set)
    list_box.grid(row=0, column=0, columnspan=4, sticky="NEWS")

    list_box.bind('<Double-1>', select_from_list_box)
    scrollbar.config(command=list_box.yview)

    chat_entry = tkinter.Entry(chat_frame, font="arial 14")
    chat_entry.grid(row=1, column=0, sticky="NEWS")
    chat_entry.bind("<Return>", on_send)

    tkinter.Button(chat_frame, text="+", font="arial 14", command=on_send_file).grid(row=1, column=1, sticky="NEWS")

    tkinter.Button(chat_frame, text=";-)", font="arial 14", command=kaomoji_popup).grid(row=1, column=2,
                                                                                        sticky="NEWS")

    tkinter.Button(chat_frame, text="send", font="arial 14", command=on_send).grid(row=1, column=3, columnspan=2,
                                                                                   sticky="NEWS")


if __name__ == "__main__":
    root = tkinter.Tk()
    create_frame(root, None, None, None, None, None)
    root.mainloop()
