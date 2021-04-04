import os
import socket
import subprocess
import threading
import time
import tkinter
from tkinter.filedialog import askopenfilename

from Crypto.PublicKey import RSA

from ganeral_dependencies import protocol_digest, protocol, AES_crypto
from ganeral_dependencies.AES_crypto import decrypt
from ganeral_dependencies.global_functions import bytes_to_int, int_to_bytes
from ganeral_dependencies.global_values import *

FILE_BROWSER_PATH = os.path.join(os.getenv('WINDIR'), 'explorer.exe')
clickable_links = {}


def explore(path):
    # explorer would choke on forward slashes
    path = os.path.normpath(path)

    if os.path.isdir(path):
        subprocess.run([FILE_BROWSER_PATH, path])
    elif os.path.isfile(path):
        subprocess.run([FILE_BROWSER_PATH, '/select,', os.path.normpath(path)])


class ProcessPackets(threading.Thread):
    def __init__(self, server, user_values, parameters=None):
        self.request_queue = []
        self.server = server
        self.user_values = user_values
        self.parameters = parameters
        threading.Thread.__init__(self)

    def run(self):
        while self.user_values.pin_code:
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
                    print("group_key: " + str(self.user_values.group_key))
                    print("sending user data")
                    del self.request_queue[0]

                elif self.request_queue[0][0] in [SEND_FILE, SEND_IMG]:
                    file_content = protocol_digest.decrypt(self.request_queue[0][1][1], self.user_values.group_key)
                    file_name = protocol_digest.decrypt(self.request_queue[0][1][0], self.user_values.group_key)
                    with open(".\\files\\" + file_name.decode("utf-8"), "wb") as file_:
                        file_.write(file_content)
                    del self.request_queue[0]
            time.sleep(0.05)

    def add_request(self, request):
        self.request_queue.append(request)


def create_frame(root, chat_frame, chat_picker_frame, user_values, server, key):

    def group_info():
        pass

    def on_raise():
        root.title(f"sendme - {user_values.pin_code}")
        # root.config(menu=menu_bar)
        msg = f"{user_values.username} has entered the chat".encode("utf-8")
        list_box.insert(tkinter.END, msg)
        user_values.process_thread = ProcessPackets(server, user_values)
        user_values.process_thread.start()
        chat_frame.after(100, msg_listener)
        if user_values.group_key:
            packets = protocol.PacketMaker(SEND_MSG, shared_secrete=user_values.group_key, content=msg)
            for packet in packets:
                server.send(packet)

    def leave_group():
        user_values.pin_code = 0
        root.config(menu=None)
        chat_picker_frame.tkraise()

    def on_send(*args):
        msg = f"<{user_values.username}>:" + chat_entry.get()

        list_box.insert(tkinter.END, msg)
        packets = protocol.PacketMaker(SEND_MSG, shared_secrete=user_values.group_key, content=msg.encode("utf-8"))
        for packet in packets:
            server.send(packet)
        chat_entry.delete(0, "end")

    def on_send_file():
        filepath = askopenfilename()
        if filepath:
            packets = protocol.PacketMaker(SEND_IMG, shared_secrete=user_values.group_key,
                                           username=user_values.username.encode("utf-8"), file_path=filepath)
            for packet in packets:
                server.send(packet)

    def select_from_list_box(event):
        pass
        courser = list_box.curselection()
        # Updating label text to selected option
        value = list_box.get(courser)
        print(value)
        if value in clickable_links:
            explore(clickable_links[value])

    def msg_listener(*args):
        if user_values.pin_code:
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
                    list_box.insert(tkinter.END, msg)
                elif request in [SEND_FILE, SEND_IMG]:
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

                else:
                    msg = b''
                    for packet in msg_queue:
                        msg += packet[HEADER_SIZE:]
                    user_values.process_thread.add_request([request, msg])
            except socket.timeout:
                server.settimeout(None)
            finally:
                chat_frame.after(300, msg_listener)

    menu_bar = tkinter.Menu(chat_frame)
    file_menu = tkinter.Menu(menu_bar, tearoff=0)
    file_menu.add_command(label="grope info", command=group_info)
    file_menu.add_separator()
    file_menu.add_command(label="leave grope", command=leave_group)
    menu_bar.add_cascade(label="options", menu=file_menu)

    user_values.on_chat_raise = on_raise
    chat_frame.grid_rowconfigure(0, weight=1)
    chat_frame.grid_columnconfigure(0, weight=9999)
    chat_frame.grid_columnconfigure(1, weight=1)
    chat_frame.grid_columnconfigure(2, weight=1)

    scrollbar = tkinter.Scrollbar(chat_frame)
    scrollbar.grid(row=0, column=3, sticky="NSEW", padx=(0, 0))

    list_box = tkinter.Listbox(chat_frame, yscrollcommand=scrollbar.set)
    list_box.grid(row=0, column=0, columnspan=3, sticky="NEWS")

    list_box.bind('<Double-1>', select_from_list_box)
    scrollbar.config(command=list_box.yview)

    chat_entry = tkinter.Entry(chat_frame, font="arial 14")
    chat_entry.grid(row=1, column=0, sticky="NEWS")
    chat_entry.bind("<Return>", on_send)

    tkinter.Button(chat_frame, text="+", font="arial 14", command=on_send_file).grid(row=1, column=1, sticky="NEWS")

    tkinter.Button(chat_frame, text="send", font="arial 14", command=on_send).grid(row=1, column=2, columnspan=2,
                                                                                   sticky="NEWS")


if __name__ == "__main__":
    root = tkinter.Tk()
    create_frame(root, None, None, None, None, None)
    root.mainloop()
