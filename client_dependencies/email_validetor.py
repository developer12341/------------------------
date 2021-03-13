import tkinter
from ganeral_dependencies.packets_maker import Packet_Maker
from ganeral_dependencies.global_values import *

def Create_Frame(email_validetor_frame, register_frame, chat_picker_frame,server,public_key,private_key):

    def regiater():
        register_frame.tkraise()
    
    def on_submit(*args):
        pincode = pincode_entry.get()
        if len(pincode) == 6:
            packets = Packet_Maker(AUTHENTICAT_EMAIL,public_key)
            server.send(next(packets))


    def on_clear():
        pincode_entry.delete(0, "END")

    tkinter.Label(email_validetor_frame,text="Validate_email",font="arial 15").grid(row=0,column=0,columnspan=2,sticky="NEW")

    email_validetor_frame.grid_columnconfigure(0,weight=2)
    email_validetor_frame.grid_columnconfigure(1,weight=1)

    tkinter.Label(email_validetor_frame,text="pin-code:",font=15).grid(row=1,column=0,sticky="E",pady=(20,0))
    pincode_entry = tkinter.Entry(email_validetor_frame,font=15)
    pincode_entry.grid(row=1,column=1,pady=(20,0))

    pincode_error_str = tkinter.StringVar()
    pibcode_error_lable = tkinter.Label(email_validetor_frame,textvariable = pincode_error_str,font=15)

    tkinter.Button(email_validetor_frame,text="send",font=15,command=on_submit).grid(row=4,column=0,pady=(20,0),sticky="E")

    tkinter.Button(email_validetor_frame,text="clear",font=15, command=on_clear).grid(row=4,column=1,pady=(20,0))

    tkinter.Label(email_validetor_frame,text="your email is not",font="arial 15").grid(row=6,column=0,columnspan=2,pady=(20,0))
    tkinter.Button(email_validetor_frame,text="register",font=15,command=regiater).grid(row=7,column=0,columnspan=2,pady=(20,0))
