import tkinter
from ganeral_dependencies.protocols import PacketMaker
from ganeral_dependencies.global_values import *
from ganeral_dependencies import protocol_digest


def create_frame(email_validate_frame, register_frame, user_values, chat_picker_frame, server, key):
    def register():
        register_frame.tkraise()

    def on_submit(*args):
        pin_code = pin_code_entry.get()
        if len(pin_code) == 6:
            content = pin_code.encode("utf-8")
            packets = PacketMaker(SEND_PIN_CODE, key, content=content)
            pac = next(packets)
            server.send(pac)
            server_response = server.recv(PACKET_SIZE)
            if protocol_digest.is_logged_in(server_response):
                tkinter.Label(chat_picker_frame, text=f"hello {user_values.username}!", font="arial 23").grid(row=0,
                                                                                                              column=0,
                                                                                                              columnspan=3,
                                                                                                              sticky="NWE") 
                chat_picker_frame.tkraise()
            else:
                print("error msg")

    def on_clear():
        pin_code_entry.delete(0, "END")

    tkinter.Label(email_validate_frame, text="Validate_email", font="arial 15").grid(row=0, column=0, columnspan=2,
                                                                                     sticky="NEW")

    email_validate_frame.grid_columnconfigure(0, weight=2)
    email_validate_frame.grid_columnconfigure(1, weight=1)

    tkinter.Label(email_validate_frame, text="pin-code:", font=15).grid(row=1, column=0, sticky="E", pady=(20, 0))
    pin_code_entry = tkinter.Entry(email_validate_frame, font=15)
    pin_code_entry.grid(row=1, column=1, pady=(20, 0))

    pin_code_error_str = tkinter.StringVar()
    pin_code_error_label = tkinter.Label(email_validate_frame, textvariable=pin_code_error_str, font=15)

    tkinter.Button(email_validate_frame, text="send", font=15, command=on_submit).grid(row=4, column=0, pady=(20, 0),
                                                                                       sticky="E")

    tkinter.Button(email_validate_frame, text="clear", font=15, command=on_clear).grid(row=4, column=1, pady=(20, 0))

    tkinter.Label(email_validate_frame, text="your email is not", font="arial 15").grid(row=6, column=0, columnspan=2,
                                                                                        pady=(20, 0))
    tkinter.Button(email_validate_frame, text="register", font=15, command=register).grid(row=7, column=0,
                                                                                          columnspan=2, pady=(20, 0))
