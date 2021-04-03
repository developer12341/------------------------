import tkinter,threading,datetime, tkcalendar
from ganeral_dependencies.global_values import *
from ganeral_dependencies import pac_comp,protocols
import re
 
# Make a regular expression for validating an Email
regex = '^(\w|\.|\_|\-)+[@](\w|\_|\-|\.)+[.]\w{2,3}$'
 
# Define a function for validating an Email
def is_valid_email(email):
    # pass the regular expression and the string in search() method
    if( re.search(regex, email)):
        return True
    else:
        return False
 
error_msgs = {USERNAME_TAKEN: "this username is taken, please pick a diffrent one",
EMAIL_DOSENT_EXIST:"this email doesn't exist",
EMAIL_TAKEN:"there is allready a user with this email address"}
def Create_Frame(register_frame,login_frame,email_validetor_frame,server,key,user_values):
    
    def login():
        login_frame.tkraise()

    def on_submit(*args):
        date_error.grid_forget()
        email_error.grid_forget()
        Re_password_error.grid_forget()
        username_error.grid_forget()
        password_error.grid_forget()
        server_error.grid_forget()
        
        username = username_entry.get()
        password = password_entry.get()
        re_password = Re_password_entry.get()
        birthday = birthday_picker.get_date()
        today = datetime.date.today()
        email = email_entry.get()
        send = True
        if birthday > today:
            send = False
            date_error.grid(row=6,column=0,columnspan=2)
        if not is_valid_email(email):
            send = False
            email_error.grid(row=8,column=0,columnspan=2)
        if password != re_password:
            send = False
            Re_password_error.grid(row=4,column=0,columnspan=2)
        if (len(username) < USERNAME_MIN_LEN or len(username) > USERNAME_MAX_LEN):
            send = False
            username_error.grid(row=10,column=0,columnspan=2)
        if (len(password) < PASSWORD_MIN_LEN or len(password) > PASSWORD_MAX_LEN):
            send = False
            password_error.grid(row=9,column=0,columnspan=2)
        if send:
            content = username.encode("utf-8") + bytes(USERNAME_MAX_LEN-len(username))
            content += password.encode("utf-8") + bytes(PASSWORD_MAX_LEN-len(password))
            content += birthday.year.to_bytes(2,"big") + bytes([birthday.month]) + bytes([birthday.day])
            content += email.encode("utf-8")
            packets = protocols.Packet_Maker(REGISTER,key,content=content)
            for packet in packets:
                server.send(packet)

            server_response = server.recv(PACKET_SIZE)
            #print(server_response)
            can_auth, reasone =  pac_comp.can_auth_email(server_response)
            if can_auth:
                user_values.username = username
                email_validetor_frame.tkraise()
            else:
                print(error_msgs[reasone])
                server_error_var.set(error_msgs[reasone])
                server_error.grid(row=11,column=0,columnspan=2)





    tkinter.Label(register_frame,text="Register",font="arial 15").grid(row=0,column=0,columnspan=2,sticky="NEW",pady=15)

    register_frame.grid_columnconfigure(0,weight=1)
    register_frame.grid_columnconfigure(1,weight=1)

    tkinter.Label(register_frame,text="username:",font=15).grid(row=1,column=0,pady=(20,0),sticky="E")
    username_entry = tkinter.Entry(register_frame,font=15)
    username_entry.grid(row=1,column=1,pady=(20,0))


    tkinter.Label(register_frame,text="password:",font=15).grid(row=2,column=0,sticky="E",pady=(20,0))
    password_entry = tkinter.Entry(register_frame,font=15,show="*")
    password_entry.grid(row=2,column=1,pady=(20,0))


    tkinter.Label(register_frame,text="enter password again:",font=15).grid(row=3,column=0,sticky="E",pady=(20,0))
    Re_password_entry = tkinter.Entry(register_frame,font=15,show="*")
    Re_password_entry.grid(row=3,column=1,pady=(20,0))

    Re_password_error = tkinter.Label(register_frame,text = "the passwords do not match", fg="red")
    Re_password_error.grid(row=4,column=0,columnspan=2)
    Re_password_error.grid_forget()

    tkinter.Label(register_frame,text="birthday:",font=15).grid(row=5,column=0,sticky="E",pady=(20,0))
    birthday_picker = tkcalendar.DateEntry(register_frame)
    birthday_picker.grid(row=5,column=1)

    date_error = tkinter.Label(register_frame,text = "this date is not valid", fg="red")
    date_error.grid(row=6,column=0,columnspan=2)
    date_error.grid_forget()

    tkinter.Label(register_frame,text="email:",font=15).grid(row=7,column=0,sticky="E",pady=(20,0))
    email_entry = tkinter.Entry(register_frame,font=15)
    email_entry.grid(row=7,column=1,pady=(20,0))

    email_error = tkinter.Label(register_frame,text = "this email is not valid", fg="red")
    email_error.grid(row=8,column=0,columnspan=2)
    email_error.grid_forget()

    password_error = tkinter.Label(register_frame,text = f"the password must be between {PASSWORD_MIN_LEN} and {PASSWORD_MAX_LEN} charactors", fg="red")
    password_error.grid(row=9,column=0,columnspan=2)
    password_error.grid_forget()

    username_error = tkinter.Label(register_frame,text = f"the username must be between {USERNAME_MIN_LEN} and {USERNAME_MAX_LEN} charactors", fg="red")
    username_error.grid(row=10,column=0,columnspan=2)
    username_error.grid_forget()


    server_error_var = tkinter.StringVar()
    server_error = tkinter.Label(register_frame,textvariable= server_error_var, fg="red")
    server_error.grid(row=11,column=0,columnspan=2)
    server_error.grid_forget()

    tkinter.Button(register_frame,text="send",font=15,command = on_submit).grid(row=12,column=0,pady=(20,0))

    tkinter.Button(register_frame,text="clear",font=15).grid(row=12,column=1,pady=(20,0))

    tkinter.Label(register_frame,text="already have a user?", font=20).grid(row=13,column=0,columnspan=2,pady=(20,0))
    tkinter.Button(register_frame,text="log in",font=15,command=login).grid(row=14,column=0,columnspan=2,pady=(20,0))

if __name__ == "__main__":
    root = tkinter.Tk()
    root.minsize(500,500)
    root.maxsize(1500,1500)
    Create_Frame(root,None,None,None,None,None)
    root.mainloop()

# def main(self):
#     def close():
#         self.close_protocol = True
#         threading._start_new_thread(window.destroy,tuple())
    
#     def birthday_valadate(date):
#         today = datetime.datetime.now()
#         if(today.year <date.year or today.year -date.year > 130):
#             return False
#         else:
#             if(today.year != date.year):
#                 return True
#             else:
#                 if(today.month < date.month ):
#                     return False
#                 else:
#                     if(today.month != date.month):
#                         return True
#                     else:
#                         if(today.day < date.day ):
#                             return False
#                         else:
#                             if(today.day != date.day):
#                                 return True
#                             else:
#                                 return False
    
#     def on_submit():
#         username_error.grid_forget()
#         password_error.grid_forget()
#         Re_password_error.grid_forget()
#         date_error.grid_forget()
#         server_error.grid_forget()
        
#         send = True
#         username = username_entry.get()
#         password = password_entry.get()
#         Re_password = Re_password_entry.get()
        
#         try:
#             birthday = datetime.date(
#                 int(year.get()),
#                 int(month.get()),
#                 int(day.get()))
#             if not birthday_valadate(birthday):
#                 date_error.grid(row=8,column=0,columnspan=2)
#                 send = False
#         except:
#             date_error.grid(row=8,column=0,columnspan=2)
#             send = False
        
#         if len(username) < 5 or len(username) > 30:
#             username_error.grid(row=2,column=0,columnspan=2)
#             send = False
#         if len(password) < 5 or len(password) > 100:
#             password_error.grid(row=4,column=0,columnspan=2)
#             send = False
#         if Re_password != password:
#             Re_password_error.grid(row=6,column=0,columnspan=2)
#             send = False
        
#         if send:
#             self.send_obj.insert("register")
#             self.send_obj.insert(username)
#             self.send_obj.insert(password)
#             self.send_obj.insert(str(birthday.year))
#             self.send_obj.insert(str(birthday.month))
#             self.send_obj.insert(str(birthday.day))
#             msg = self.recv_obj.get_item()
#             if msg == "good to go":
#                 self.username = username
#                 self.cur_window = "chat_picker"
#                 window.destroy()
#             else:
#                 server_error_var.set(msg)
#                 server_error.grid(row=9,column=0,columnspan=2)

#     def on_enter(event):
#         username_error.grid_forget()
#         password_error.grid_forget()
#         Re_password_error.grid_forget()
#         date_error.grid_forget()
#         server_error.grid_forget()
        
#         send = True
#         username = username_entry.get()
#         password = password_entry.get()
#         Re_password = Re_password_entry.get()
        
#         try:
#             birthday = datetime.date(
#                 int(year.get()),
#                 int(month.get()),
#                 int(day.get()))
#             if not birthday_valadate(birthday):
#                 date_error.grid(row=8,column=0,columnspan=2)
#                 send = False
#         except:
#             date_error.grid(row=8,column=0,columnspan=2)
#             send = False
        
#         if len(username) < 5 or len(username) > 20:
#             username_error.grid(row=2,column=0,columnspan=2)
#             send = False
#         if len(password) < 5 or len(password) > 20:
#             password_error.grid(row=4,column=0,columnspan=2)
#             send = False
#         if Re_password != password:
#             Re_password_error.grid(row=6,column=0,columnspan=2)
#             send = False
        
#         if send:
#             self.send_obj.insert("register")
#             self.send_obj.insert(username)
#             self.send_obj.insert(password)
#             self.send_obj.insert(str(birthday.year))
#             self.send_obj.insert(str(birthday.month))
#             self.send_obj.insert(str(birthday.day))
#             msg = self.recv_obj.get_item()
#             if msg == "good to go":
#                 self.username = username
#                 self.cur_window = "chat_picker"
#                 window.destroy()
#             else:
#                 server_error_var.set(msg)
#                 server_error.grid(row=9,column=0,columnspan=2)

#     def on_clear():
#         username_error.grid_forget()
#         password_error.grid_forget()
#         Re_password_error.grid_forget()
#         date_error.grid_forget()
#         server_error.grid_forget()

#         username_entry.delete(0, 'end')
#         password_entry.delete(0, 'end')
#         Re_password_entry.delete(0, 'end')
#         year.delete(0, 'end')
#         year.insert(0,"YYYY")
#         month.delete(0, 'end')
#         month.insert(0,"MMM")
#         day.delete(0, 'end')
#         day.insert(0,"DDD")

#     def go_log_in():
#         self.cur_window = "login"
#         window.destroy()

#     window = tkinter.Tk()
#     window.geometry("400x600")
#     window.title("sendme")
#     window.protocol("WM_DELETE_WINDOW",close)
#     window.bind("<Return>",on_enter)
#     tkinter.Label(window,text="Register",font="arial 15").grid(row=0,column=0,columnspan=2,sticky="NEW",pady=15)

#     window.grid_columnconfigure(0,weight=1)
#     window.grid_columnconfigure(1,weight=1)
    


#     tkinter.Label(window,text="username:",font=15).grid(row=1,column=0,pady=(20,0),sticky="E")
#     username_entry = tkinter.Entry(font=15)
#     username_entry.grid(row=1,column=1,pady=(20,0))

#     username_error = tkinter.Label(window,text = "the username must be between 5 and 20 charactors", fg="red")
#     username_error.grid(row=2,column=0,columnspan=2)
#     username_error.grid_forget()

#     tkinter.Label(window,text="password:",font=15).grid(row=3,column=0,sticky="E",pady=(20,0))
#     password_entry = tkinter.Entry(font=15,show="*")
#     password_entry.grid(row=3,column=1,pady=(20,0))

#     password_error = tkinter.Label(window,text = "the password must be between 5 and 20 charactors", fg="red")
#     password_error.grid(row=4,column=0,columnspan=2)
#     password_error.grid_forget()

#     tkinter.Label(window,text="enter password again:",font=15).grid(row=5,column=0,sticky="E",pady=(20,0))
#     Re_password_entry = tkinter.Entry(font=15,show="*")
#     Re_password_entry.grid(row=5,column=1,pady=(20,0))

#     Re_password_error = tkinter.Label(window,text = "the passwords do not match", fg="red")
#     Re_password_error.grid(row=6,column=0,columnspan=2)
#     Re_password_error.grid_forget()

#     tkinter.Label(window,text="birthday:",font=15).grid(row=7,column=0,sticky="E",pady=(20,0))
#     birthday_frame = tkinter.Frame(window)
#     birthday_frame.grid(row=7,column=1,pady=(20,0))

#     year = tkinter.Entry(birthday_frame,width=6,font=15)
#     year.grid(row=0,column=0)
#     year.insert(0,"YYYY")

#     tkinter.Label(birthday_frame,text="/",font=15).grid(row=0,column=1)

#     month = tkinter.Entry(birthday_frame,width=5,font=15)
#     month.grid(row=0,column=2)
#     month.insert(0,"MMM")
    
#     tkinter.Label(birthday_frame,text="/",font=15).grid(row=0,column=3)
    
#     day = tkinter.Entry(birthday_frame,width=5,font=15)
#     day.grid(row=0,column=4)
#     day.insert(0,"DDD")

#     date_error = tkinter.Label(window,text = "this date is not valid", fg="red")
#     date_error.grid(row=8,column=0,columnspan=2)
#     date_error.grid_forget()

#     server_error_var = tkinter.StringVar()
#     server_error = tkinter.Label(window,textvariable= server_error_var, fg="red")
#     server_error.grid(row=9,column=0,columnspan=2)
#     server_error.grid_forget()

#     tkinter.Button(window,text="send",font=15,command=on_submit).grid(row=10,column=0,pady=(20,0))

#     tkinter.Button(window,text="clear",font=15,command=on_clear).grid(row=10,column=1,pady=(20,0))

#     tkinter.Label(window,text="already have a user?", font=20).grid(row=11,column=0,columnspan=2,pady=(20,0))
#     tkinter.Button(window,text="log in",font=15,command=go_log_in).grid(row=12,column=0,columnspan=2,pady=(20,0))

#     window.mainloop()